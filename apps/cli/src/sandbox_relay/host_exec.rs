//! Connection-scoped host processes. Never log command text or output.
use super::agent_policy::AgentPolicy;
use super::host_mask::Masker;
use sandbox_protocol::*;
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const RING_LIMIT: usize = 1_048_576;
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(HOST_SAFE_INTEGER as u128) as u64
}
#[derive(Default)]
struct Ring {
    bytes: VecDeque<u8>,
    total: u64,
}
impl Ring {
    fn push(&mut self, bytes: &[u8]) {
        self.total += bytes.len() as u64;
        let tail = &bytes[bytes.len().saturating_sub(RING_LIMIT)..];
        let overflow = (self.bytes.len() + tail.len()).saturating_sub(RING_LIMIT);
        self.bytes.drain(..overflow);
        self.bytes.extend(tail);
    }
    fn poll(&self, offset: u64, max: usize) -> HostExecOutputV11 {
        let first = self.total - self.bytes.len() as u64;
        let at = offset.max(first).min(self.total);
        let bytes: Vec<u8> = self
            .bytes
            .iter()
            .skip((at - first) as usize)
            .take(max.min(HOST_OUTPUT_MAX_BYTES))
            .copied()
            .collect();
        HostExecOutputV11 {
            offset: at,
            data: encode_host_data(&bytes),
            dropped: offset < first,
        }
    }
}
struct Entry {
    owner: String,
    revision: u64,
    state: HostExecState,
    started: u64,
    ends: u64,
    finished: Option<u64>,
    exit: Option<i32>,
    signal: Option<i32>,
    stdout: Ring,
    stderr: Ring,
}
struct Work {
    entry: Arc<Mutex<Entry>>,
    stop: Arc<Mutex<Option<HostExecState>>>,
    stdin: mpsc::SyncSender<(Vec<u8>, bool)>,
    stdin_open: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
pub(super) struct HostExecRegistry {
    commands: HashMap<String, Work>,
    recent: VecDeque<String>,
    secret: zeroize::Zeroizing<Vec<u8>>,
    ends_tx: mpsc::Sender<String>,
    ends_rx: mpsc::Receiver<String>,
}
impl HostExecRegistry {
    pub fn new(secret: &[u8]) -> Self {
        let (ends_tx, ends_rx) = mpsc::channel();
        Self {
            commands: HashMap::new(),
            recent: VecDeque::new(),
            secret: zeroize::Zeroizing::new(secret.to_vec()),
            ends_tx,
            ends_rx,
        }
    }
    pub fn start(
        &mut self,
        req: HostExecStartV11,
        policy: &AgentPolicy,
        host_owner: &str,
    ) -> DaemonControlMessage {
        let reject = |reason| {
            DaemonControlMessage::HostExecRejected(HostExecRejectedV11 {
                request_id: req.request_id.clone(),
                command_id: req.command_id.clone(),
                reason,
            })
        };
        if let Err(reason) = policy.authorize(req.agent_policy_revision, &req.owner_id, host_owner)
        {
            return reject(reason);
        }
        if !req.is_valid() {
            return reject(HostExecRejectReason::BadCommand);
        }
        if self.commands.contains_key(&req.command_id) {
            return reject(HostExecRejectReason::Duplicate);
        }
        if self
            .commands
            .values()
            .filter(|w| lock(&w.entry).state == HostExecState::Running)
            .count()
            >= 8
        {
            return reject(HostExecRejectReason::Limit);
        }
        let Some(cwd) = command_cwd(req.cwd.as_deref()) else {
            return reject(HostExecRejectReason::BadCwd);
        };
        #[cfg(not(target_os = "linux"))]
        {
            let _ = cwd;
            reject(HostExecRejectReason::SpawnFailed)
        }
        #[cfg(target_os = "linux")]
        {
            let failure = HostExecRejectReason::SpawnFailed;
            let Ok(Launched {
                mut process,
                out,
                err,
                mut stdin,
            }) = launch(&req, cwd)
            else {
                return reject(failure);
            };
            let started = now_ms();
            let timeout = Duration::from_millis(req.timeout_ms.min(policy.max_ms));
            let ends = started
                .saturating_add(timeout.as_millis() as u64)
                .min(HOST_SAFE_INTEGER);
            let entry = Arc::new(Mutex::new(Entry {
                owner: req.owner_id.clone(),
                revision: req.agent_policy_revision,
                state: HostExecState::Running,
                started,
                ends,
                finished: None,
                exit: None,
                signal: None,
                stdout: Ring::default(),
                stderr: Ring::default(),
            }));
            let stop = Arc::new(Mutex::new(None));
            let stdin_open = Arc::new(AtomicBool::new(req.stdin));
            let (stdin_tx, stdin_rx) = mpsc::sync_channel(8);
            let producer_done = Arc::new(AtomicBool::new(false));
            let out_worker = out.and_then(|r| {
                reader(
                    r,
                    entry.clone(),
                    true,
                    Masker::new(&self.secret),
                    producer_done.clone(),
                )
                .ok()
            });
            let err_worker = err.and_then(|r| {
                reader(
                    r,
                    entry.clone(),
                    false,
                    Masker::new(&self.secret),
                    producer_done.clone(),
                )
                .ok()
            });
            if out_worker.is_none() || err_worker.is_none() {
                producer_done.store(true, Ordering::Release);
                process.abort();
                return reject(failure);
            }
            if let Some(pipe) = &stdin
                && rustix::fs::fcntl_setfl(pipe, rustix::fs::OFlags::NONBLOCK).is_err()
            {
                producer_done.store(true, Ordering::Release);
                process.abort();
                return reject(failure);
            }
            let e = entry.clone();
            let s = stop.clone();
            let open = stdin_open.clone();
            let id = req.command_id.clone();
            let tx = self.ends_tx.clone();
            // Child ownership stays with this scope if thread creation fails.
            let child = Arc::new(Mutex::new(Some(process)));
            let owned = child.clone();
            let output_done = producer_done.clone();
            let worker = std::thread::Builder::new()
                .name("wssp-host-exec".into())
                .spawn(move || {
                    let Some(mut child) = lock(&owned).take() else {
                        return;
                    };
                    let (state, exit, signal) = child.run(&mut stdin, stdin_rx, &open, &s, timeout);
                    output_done.store(true, Ordering::Release);
                    let out_ok = out_worker.is_some_and(|t| t.join().is_ok());
                    let err_ok = err_worker.is_some_and(|t| t.join().is_ok());
                    open.store(false, Ordering::Release);
                    {
                        let mut entry = lock(&e);
                        entry.state = if out_ok && err_ok {
                            state
                        } else {
                            HostExecState::Interrupted
                        };
                        entry.exit = exit;
                        entry.signal = signal;
                        entry.finished = Some(now_ms());
                    }
                    let _ = tx.send(id);
                });
            let Ok(worker) = worker else {
                producer_done.store(true, Ordering::Release);
                if let Some(mut c) = lock(&child).take() {
                    c.abort();
                }
                return reject(failure);
            };
            self.commands.insert(
                req.command_id.clone(),
                Work {
                    entry,
                    stop,
                    stdin: stdin_tx,
                    stdin_open,
                    worker: Some(worker),
                },
            );
            DaemonControlMessage::HostExecStarted(HostExecStartedV11 {
                request_id: req.request_id,
                command_id: req.command_id,
                started_at: started,
                ends_by: ends,
            })
        }
    }
    pub fn poll(
        &self,
        id: &str,
        request_id: Option<String>,
        out: u64,
        err: u64,
        max: usize,
    ) -> DaemonControlMessage {
        let mut status = HostExecStatusV11 {
            request_id,
            command_id: id.into(),
            state: HostExecState::Unknown,
            exit_code: None,
            signal: None,
            started_at: None,
            ends_by: None,
            finished_at: None,
            stdout: HostExecOutputV11 {
                offset: 0,
                data: String::new(),
                dropped: false,
            },
            stderr: HostExecOutputV11 {
                offset: 0,
                data: String::new(),
                dropped: false,
            },
            stdout_bytes: 0,
            stderr_bytes: 0,
        };
        if let Some(work) = self.commands.get(id) {
            let e = lock(&work.entry);
            status.state = e.state;
            status.started_at = Some(e.started);
            status.ends_by = Some(e.ends);
            status.finished_at = e.finished;
            status.exit_code = e.exit;
            status.signal = e.signal;
            status.stdout = e.stdout.poll(out, max);
            status.stderr = e.stderr.poll(err, max);
            status.stdout_bytes = e.stdout.total;
            status.stderr_bytes = e.stderr.total;
        }
        DaemonControlMessage::HostExecStatus(status)
    }
    pub fn stdin(
        &self,
        req: HostExecStdinV11,
        policy: &AgentPolicy,
        owner: &str,
    ) -> DaemonControlMessage {
        let result = || -> Result<(), &'static str> {
            let w = self.commands.get(&req.command_id).ok_or("unknown")?;
            let e = lock(&w.entry);
            policy
                .authorize(e.revision, &e.owner, owner)
                .map_err(|r| match r {
                    HostExecRejectReason::HostCommandsOff => "host_commands_off",
                    HostExecRejectReason::PolicyChanged => "policy_changed",
                    _ => "owner_mismatch",
                })?;
            if e.state != HostExecState::Running || !w.stdin_open.load(Ordering::Acquire) {
                return Err("stdin_closed");
            }
            let data = decode_host_data(&req.data).ok_or("invalid_input")?;
            w.stdin.try_send((data, req.eof)).map_err(|_| "limit")?;
            if req.eof {
                w.stdin_open.store(false, Ordering::Release);
            }
            Ok(())
        }();
        DaemonControlMessage::HostExecStdinResult(HostExecStdinResultV11 {
            request_id: req.request_id,
            command_id: req.command_id,
            accepted: result.is_ok(),
            reason: result.err().map(str::to_owned),
        })
    }
    pub fn cancel(&self, id: &str, state: HostExecState) {
        if let Some(w) = self.commands.get(id) {
            *lock(&w.stop) = Some(state);
        }
    }
    pub fn interrupt_all(&self) {
        for w in self.commands.values() {
            *lock(&w.stop) = Some(HostExecState::Interrupted);
        }
    }
    pub fn finished(&mut self) -> Vec<DaemonControlMessage> {
        let mut frames = Vec::new();
        while let Ok(id) = self.ends_rx.try_recv() {
            if let Some(w) = self.commands.get_mut(&id)
                && let Some(t) = w.worker.take()
            {
                let _ = t.join();
            }
            frames.push(self.poll(&id, None, u64::MAX, u64::MAX, 0));
            self.recent.push_back(id);
        }
        while self.recent.len() > 64 {
            if let Some(id) = self.recent.pop_front() {
                self.commands.remove(&id);
            }
        }
        frames
    }
}
impl Drop for HostExecRegistry {
    fn drop(&mut self) {
        self.interrupt_all();
        for w in self.commands.values_mut() {
            if let Some(t) = w.worker.take() {
                let _ = t.join();
            }
        }
    }
}
fn command_cwd(raw: Option<&str>) -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    let path = match raw {
        None | Some("~") => home.clone(),
        Some(v) if v.starts_with("~/") => home.join(&v[2..]),
        Some(v) => Path::new(v).to_path_buf(),
    };
    (path.is_absolute() && path.is_dir()).then_some(path)
}
#[cfg(target_os = "linux")]
fn reader<R: Read + Send + std::os::fd::AsFd + 'static>(
    mut pipe: R,
    entry: Arc<Mutex<Entry>>,
    stdout: bool,
    mut mask: Masker,
    producer_done: Arc<AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    rustix::fs::fcntl_setfl(&pipe, rustix::fs::OFlags::NONBLOCK).map_err(std::io::Error::from)?;
    std::thread::Builder::new()
        .name("wssp-host-output".into())
        .spawn(move || {
            let mut buffer = zeroize::Zeroizing::new(vec![0; 8192]);
            let mut final_bytes = 0usize;
            loop {
                let ended = producer_done.load(Ordering::Acquire);
                if ended && final_bytes >= RING_LIMIT {
                    break;
                }
                match pipe.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        if ended {
                            final_bytes += n;
                        }
                        let bytes = mask.push(&buffer[..n], false);
                        let mut e = lock(&entry);
                        if stdout {
                            e.stdout.push(&bytes);
                        } else {
                            e.stderr.push(&bytes);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if ended {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
            let bytes = mask.push(&[], true);
            let mut e = lock(&entry);
            if stdout {
                e.stdout.push(&bytes);
            } else {
                e.stderr.push(&bytes);
            }
        })
}
#[cfg(target_os = "linux")]
fn terminate(pid: u32, signal: nix::sys::signal::Signal) {
    if let Ok(pid) = i32::try_from(pid) {
        let _ = nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pid), signal);
    }
}
#[cfg(target_os = "linux")]
fn abort_child(child: &mut Child) {
    let mut tree = crate::host_process::Tree::new(child.id(), false);
    let _ = tree.refresh();
    if child.try_wait().ok().flatten().is_some() {
        tree.root_reaped();
        let _ = tree.finish();
        return;
    }
    terminate(child.id(), nix::sys::signal::Signal::SIGTERM);
    let until = Instant::now() + Duration::from_secs(1);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            _ if Instant::now() >= until => {
                tree.kill();
                let _ = child.wait();
                break;
            }
            _ => {
                let _ = tree.refresh();
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    tree.root_reaped();
    let _ = tree.finish();
}
#[cfg(target_os = "linux")]
fn run_child(
    child: &mut Child,
    stdin: &mut Option<std::process::ChildStdin>,
    rx: mpsc::Receiver<(Vec<u8>, bool)>,
    open: &AtomicBool,
    stop: &Mutex<Option<HostExecState>>,
    timeout: Duration,
    report: &Path,
) -> (HostExecState, Option<i32>, Option<i32>) {
    use nix::sys::signal::Signal::SIGTERM;
    use std::os::unix::process::ExitStatusExt;
    let mut tree = crate::host_process::Tree::new(child.id(), false);
    let began = Instant::now();
    let mut stopping = None;
    let mut reason = None;
    let mut pending: Option<(Vec<u8>, usize, bool)> = None;
    loop {
        if tree.refresh().is_err() {
            reason = Some(HostExecState::Interrupted);
            tree.kill();
        }
        if reason.is_none() {
            reason = *lock(stop);
            if reason.is_none() && began.elapsed() >= timeout {
                reason = Some(HostExecState::TimedOut);
            }
            if reason.is_some() {
                terminate(child.id(), SIGTERM);
                stopping = Some(Instant::now());
                *stdin = None;
                open.store(false, Ordering::Release);
            }
        }
        if stopping.is_some_and(|at: Instant| at.elapsed() >= Duration::from_secs(2)) {
            tree.kill();
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                // A clean supervisor result proves all descendants, including
                // adopted setsid/double-fork orphans, are dead and reaped.
                tree.root_reaped();
                let cleanup = tree.finish();
                let actual = crate::host_process::exit_status(report);
                let clean = status.success() && cleanup && actual.is_some();
                let status = actual.unwrap_or(status);
                return (
                    if clean {
                        reason.unwrap_or(if status.success() {
                            HostExecState::Succeeded
                        } else {
                            HostExecState::Failed
                        })
                    } else {
                        HostExecState::Interrupted
                    },
                    status.code(),
                    status.signal(),
                );
            }
            Err(_) => {
                tree.kill();
                let _ = child.wait();
                tree.root_reaped();
                let _ = tree.finish();
                return (HostExecState::Interrupted, None, None);
            }
            Ok(None) => {}
        }
        if reason.is_none() {
            pump_stdin(stdin, &rx, open, &mut pending);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(target_os = "linux")]
fn pump_stdin(
    stdin: &mut Option<std::process::ChildStdin>,
    rx: &mpsc::Receiver<(Vec<u8>, bool)>,
    open: &AtomicBool,
    pending: &mut Option<(Vec<u8>, usize, bool)>,
) {
    if pending.is_none() {
        *pending = rx.try_recv().ok().map(|(v, eof)| (v, 0, eof));
    }
    if let Some((data, at, eof)) = pending {
        let mut failed = false;
        if let Some(pipe) = stdin.as_mut() {
            match pipe.write(&data[*at..]) {
                Ok(n) => *at += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => failed = true,
            }
        } else {
            failed = true;
        }
        if failed || *at == data.len() {
            if failed || *eof {
                *stdin = None;
                open.store(false, Ordering::Release);
            }
            *pending = None;
        }
    }
}

#[cfg(target_os = "linux")]
struct Launched {
    process: Process,
    out: Option<std::process::ChildStdout>,
    err: Option<std::process::ChildStderr>,
    stdin: Option<std::process::ChildStdin>,
}
#[cfg(target_os = "linux")]
struct Process {
    child: Child,
    report: tempfile::NamedTempFile,
}
#[cfg(target_os = "linux")]
fn launch(req: &HostExecStartV11, cwd: PathBuf) -> anyhow::Result<Launched> {
    use std::os::unix::process::CommandExt;
    let argv = req.argv.clone().unwrap_or_else(|| {
        vec![
            "/bin/sh".into(),
            "-c".into(),
            req.script.clone().unwrap_or_default(),
        ]
    });
    let report = tempfile::NamedTempFile::new()?;
    let mut command = crate::host_process::command(report.path(), &argv)?;
    command
        .current_dir(cwd)
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if req.stdin {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    let mut child = command.spawn()?;
    let ready_until = Instant::now() + Duration::from_secs(2);
    loop {
        if crate::host_process::Report::read(report.path()).is_some() {
            break;
        }
        if child.try_wait().ok().flatten().is_some() || Instant::now() >= ready_until {
            abort_child(&mut child);
            anyhow::bail!("host command supervisor unavailable");
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    Ok(Launched {
        out: child.stdout.take(),
        err: child.stderr.take(),
        stdin: child.stdin.take(),
        process: Process { child, report },
    })
}
#[cfg(target_os = "linux")]
impl Process {
    fn abort(&mut self) {
        abort_child(&mut self.child)
    }
    fn run(
        &mut self,
        stdin: &mut Option<std::process::ChildStdin>,
        rx: mpsc::Receiver<(Vec<u8>, bool)>,
        open: &AtomicBool,
        stop: &Mutex<Option<HostExecState>>,
        timeout: Duration,
    ) -> (HostExecState, Option<i32>, Option<i32>) {
        run_child(
            &mut self.child,
            stdin,
            rx,
            open,
            stop,
            timeout,
            self.report.path(),
        )
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    fn policy() -> AgentPolicy {
        AgentPolicy {
            enabled: true,
            max_ms: 1000,
            roots: Vec::new(),
            revision: 1,
        }
    }
    fn req(n: u8, script: &str) -> HostExecStartV11 {
        HostExecStartV11 {
            connection_epoch: 1,
            request_id: format!("request-{n}"),
            command_id: format!("{:022}", n),
            owner_id: "owner".into(),
            agent_policy_revision: 1,
            argv: None,
            script: Some(script.into()),
            cwd: None,
            timeout_ms: 5000,
            stdin: false,
        }
    }
    fn status(r: &HostExecRegistry, id: &str) -> HostExecStatusV11 {
        let DaemonControlMessage::HostExecStatus(s) = r.poll(id, Some("poll".into()), 0, 0, 65536)
        else {
            panic!()
        };
        s
    }
    fn wait(r: &mut HostExecRegistry, id: &str) -> HostExecStatusV11 {
        let until = Instant::now() + Duration::from_secs(6);
        loop {
            r.finished();
            let s = status(r, id);
            if s.state != HostExecState::Running {
                return s;
            }
            assert!(Instant::now() < until, "host process did not finish");
            std::thread::sleep(Duration::from_millis(15));
        }
    }
    fn rejected(frame: DaemonControlMessage, reason: HostExecRejectReason) {
        let DaemonControlMessage::HostExecRejected(r) = frame else {
            panic!("not rejected")
        };
        assert_eq!(r.reason, reason);
    }
    #[test]
    fn validates_every_start_refusal_and_concurrency() {
        let mut r = HostExecRegistry::new(b"daemon-secret");
        let mut p = policy();
        p.enabled = false;
        rejected(
            r.start(req(1, "true"), &p, "owner"),
            HostExecRejectReason::HostCommandsOff,
        );
        p.enabled = true;
        let mut request = req(1, "true");
        request.agent_policy_revision = 0;
        rejected(
            r.start(request, &p, "owner"),
            HostExecRejectReason::PolicyChanged,
        );
        rejected(
            r.start(req(1, "true"), &p, "different"),
            HostExecRejectReason::OwnerMismatch,
        );
        let mut bad = req(1, "true");
        bad.script = None;
        rejected(r.start(bad, &p, "owner"), HostExecRejectReason::BadCommand);
        let mut bad = req(1, "true");
        bad.cwd = Some("relative".into());
        rejected(r.start(bad, &p, "owner"), HostExecRejectReason::BadCwd);
        let mut bad = req(1, "");
        bad.script = None;
        bad.argv = Some(vec!["/does/not/exist/wssp-test".into()]);
        rejected(r.start(bad, &p, "owner"), HostExecRejectReason::SpawnFailed);
        for n in 1..=8 {
            assert!(matches!(
                r.start(req(n, "sleep 30"), &p, "owner"),
                DaemonControlMessage::HostExecStarted(_)
            ));
        }
        rejected(
            r.start(req(1, "true"), &p, "owner"),
            HostExecRejectReason::Duplicate,
        );
        rejected(
            r.start(req(9, "true"), &p, "owner"),
            HostExecRejectReason::Limit,
        );
        r.interrupt_all();
        for n in 1..=8 {
            assert_eq!(
                wait(&mut r, &req(n, "").command_id).state,
                HostExecState::Interrupted
            );
        }
    }
    #[test]
    fn output_is_masked_and_timeout_is_capped() {
        let mut r = HostExecRegistry::new(b"fixture-own-secret");
        let p = policy();
        let request = req(
            1,
            "printf 'fixture-own-secret wssp_agent_fixture-token'; printf 'stderr' >&2",
        );
        let id = request.command_id.clone();
        r.start(request, &p, "owner");
        let result = wait(&mut r, &id);
        assert_eq!(result.state, HostExecState::Succeeded);
        let out = decode_host_data(&result.stdout.data).unwrap();
        assert!(!String::from_utf8_lossy(&out).contains("fixture-own-secret"));
        assert!(!String::from_utf8_lossy(&out).contains("wssp_agent_"));
        let request = req(2, "sleep 30");
        let id = request.command_id.clone();
        let DaemonControlMessage::HostExecStarted(start) = r.start(request, &p, "owner") else {
            panic!()
        };
        assert_eq!(start.ends_by - start.started_at, 1000);
        assert_eq!(wait(&mut r, &id).state, HostExecState::TimedOut);
    }
    #[test]
    fn stdin_rechecks_policy_owner_and_revision_and_supports_eof() {
        let mut r = HostExecRegistry::new(b"daemon-secret");
        let p = policy();
        let mut request = req(1, "cat");
        request.stdin = true;
        let id = request.command_id.clone();
        r.start(request, &p, "owner");
        let input = HostExecStdinV11 {
            connection_epoch: 1,
            request_id: "stdin".into(),
            command_id: id.clone(),
            data: encode_host_data(b"input"),
            eof: true,
        };
        for (p, owner, reason) in [
            (
                AgentPolicy {
                    enabled: false,
                    ..p.clone()
                },
                "owner",
                "host_commands_off",
            ),
            (
                AgentPolicy {
                    revision: 2,
                    ..p.clone()
                },
                "owner",
                "policy_changed",
            ),
            (p.clone(), "other", "owner_mismatch"),
        ] {
            let DaemonControlMessage::HostExecStdinResult(result) =
                r.stdin(input.clone(), &p, owner)
            else {
                panic!()
            };
            assert!(!result.accepted);
            assert_eq!(result.reason.as_deref(), Some(reason));
        }
        let DaemonControlMessage::HostExecStdinResult(result) = r.stdin(input, &p, "owner") else {
            panic!()
        };
        assert!(result.accepted);
        assert_eq!(wait(&mut r, &id).state, HostExecState::Succeeded);
    }
    #[test]
    fn output_reader_does_not_wait_for_a_pipe_held_beyond_command_exit() {
        use std::os::unix::process::CommandExt;
        let mut child = crate::managed_child::ManagedChild::spawn(
            sandbox_runtime::host_agent_command("/bin/sleep")
                .arg("30")
                .process_group(0)
                .stdout(Stdio::piped()),
        )
        .unwrap();
        let entry = Arc::new(Mutex::new(Entry {
            owner: "owner".into(),
            revision: 1,
            state: HostExecState::Running,
            started: 0,
            ends: 1,
            finished: Some(1),
            exit: Some(0),
            signal: None,
            stdout: Ring::default(),
            stderr: Ring::default(),
        }));
        let began = Instant::now();
        let task = reader(
            child.stdout.take().unwrap(),
            entry.clone(),
            true,
            Masker::new(b"fixture-daemon"),
            Arc::new(AtomicBool::new(true)),
        )
        .unwrap();
        let joined = task.join();
        terminate(child.id(), nix::sys::signal::Signal::SIGKILL);
        let _ = child.wait();
        assert!(joined.is_ok());
        assert_eq!(
            lock(&entry).state,
            HostExecState::Running,
            "drain must finish before the worker publishes completion"
        );
        assert!(began.elapsed() < Duration::from_secs(5));
    }
    fn detached_script(double_fork: bool, keep_shell: bool) -> String {
        let start = if double_fork {
            r#"/usr/bin/python3 -c 'import os,time; p=os.fork();
if p: os._exit(0)
os.setsid(); p=os.fork()
if p: os._exit(0)
open("escaped.pid","w").write(str(os.getpid()))
time.sleep(300)'"#
                .to_owned()
        } else {
            "setsid /bin/sleep 300 </dev/null >/dev/null 2>&1 & echo $! > escaped.pid".into()
        };
        format!(
            "{start}\n{}",
            if keep_shell { "sleep 300" } else { "exit 0" }
        )
    }
    fn escaped_pid(path: &Path) -> u32 {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(pid) = std::fs::read_to_string(path)
                .ok()
                .and_then(|v| v.trim().parse::<u32>().ok())
            {
                return pid;
            }
            assert!(Instant::now() < until, "detached process did not start");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn assert_reaped(pid: u32) {
        let until = Instant::now() + Duration::from_secs(3);
        while Path::new(&format!("/proc/{pid}")).exists() {
            assert!(
                Instant::now() < until,
                "escaped child {pid} survived or became a zombie"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    #[test]
    fn host_detached_descendants_die_and_are_reaped_on_shell_exit() {
        for double_fork in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let mut r = HostExecRegistry::new(b"fixture");
            let mut request = req(1, &detached_script(double_fork, false));
            request.cwd = Some(dir.path().display().to_string());
            let id = request.command_id.clone();
            assert!(matches!(
                r.start(request, &policy(), "owner"),
                DaemonControlMessage::HostExecStarted(_)
            ));
            let pid = escaped_pid(&dir.path().join("escaped.pid"));
            assert_eq!(wait(&mut r, &id).state, HostExecState::Succeeded);
            r.cancel(&id, HostExecState::Cancelled);
            assert_reaped(pid);
        }
    }
    #[test]
    fn host_detached_descendants_die_on_cancel_lower_timeout_and_disconnect() {
        for double_fork in [false, true] {
            for ending in [
                HostExecState::Cancelled,
                HostExecState::Interrupted,
                HostExecState::TimedOut,
            ] {
                let dir = tempfile::tempdir().unwrap();
                let mut r = HostExecRegistry::new(b"fixture");
                let mut request = req(1, &detached_script(double_fork, true));
                request.cwd = Some(dir.path().display().to_string());
                request.timeout_ms = if ending == HostExecState::TimedOut {
                    1000
                } else {
                    5000
                };
                let id = request.command_id.clone();
                assert!(matches!(
                    r.start(request, &policy(), "owner"),
                    DaemonControlMessage::HostExecStarted(_)
                ));
                let pid = escaped_pid(&dir.path().join("escaped.pid"));
                assert!(Path::new(&format!("/proc/{pid}")).exists());
                if ending == HostExecState::Interrupted {
                    r.interrupt_all();
                }
                if ending == HostExecState::Cancelled {
                    r.cancel(&id, ending);
                }
                assert_eq!(wait(&mut r, &id).state, ending);
                assert_reaped(pid);
            }
            let dir = tempfile::tempdir().unwrap();
            let mut r = HostExecRegistry::new(b"fixture");
            let mut request = req(1, &detached_script(double_fork, true));
            request.cwd = Some(dir.path().display().to_string());
            assert!(matches!(
                r.start(request, &policy(), "owner"),
                DaemonControlMessage::HostExecStarted(_)
            ));
            let pid = escaped_pid(&dir.path().join("escaped.pid"));
            drop(r);
            assert_reaped(pid);
        }
    }
    #[test]
    fn host_orphan_reaping_does_not_steal_an_unrelated_child_status() {
        let mut unrelated = crate::managed_child::ManagedChild::spawn(
            sandbox_runtime::host_agent_command("/bin/sh").args(["-c", "sleep 0.1; exit 37"]),
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut r = HostExecRegistry::new(b"fixture");
        let mut request = req(1, &detached_script(true, false));
        request.cwd = Some(dir.path().display().to_string());
        let id = request.command_id.clone();
        assert!(matches!(
            r.start(request, &policy(), "owner"),
            DaemonControlMessage::HostExecStarted(_)
        ));
        let pid = escaped_pid(&dir.path().join("escaped.pid"));
        assert_eq!(wait(&mut r, &id).state, HostExecState::Succeeded);
        assert_reaped(pid);
        assert_eq!(unrelated.wait().unwrap().code(), Some(37));
    }
    #[test]
    fn rings_are_bounded_and_offsets_report_eviction() {
        let mut ring = Ring::default();
        ring.push(&vec![b'x'; RING_LIMIT + 12]);
        assert_eq!(ring.bytes.len(), RING_LIMIT);
        assert!(
            ring.bytes.capacity() <= RING_LIMIT,
            "a large masked chunk must not grow the ring allocation"
        );
        assert_eq!(ring.total, (RING_LIMIT + 12) as u64);
        let out = ring.poll(0, 65536);
        assert!(out.dropped);
        assert_eq!(out.offset, 12);
        assert_eq!(decode_host_data(&out.data).unwrap().len(), 65536);
        assert!(!ring.poll(12, 1).dropped);
        assert_eq!(ring.poll(u64::MAX, 0).offset, ring.total);
    }
}
