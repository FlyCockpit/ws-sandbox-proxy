//! Executable-shim tests for CLI channels: a fake `incus` binary in a
//! private temp dir, never a live VM. The shim stands in for the guest-root
//! phases only (scope creation and the cancel fence need guest root and guest
//! systemd); everything after them is the REAL helper chain run locally: the
//! channel wrapper (prompt, preamble, READY/EXIT) and the signal helper. A
//! small driver here plays the IO owner (the daemon's socket thread).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::client::IncusClient;
use super::kvm::IncusKvmRuntime;
use crate::{
    ChannelBirth, ChannelClose, ChannelExitStatus, ChannelMode, ChannelOutput, ChannelRead,
    ChannelScope, ChannelScopeRef, ChannelSignalOutcome, FrameFilter, GuestFrame, GuestIdentity,
    KillScopesRequest, ProcessSignal, PtySize, RelayDecoder, RelayEnd, RelayFailure,
    SandboxRuntime, ScopeKill, SpawnChannelRequest, SpawnedChannel, channel_nonce,
    channel_preamble, guest_frame_bytes, relay_data_frame, relay_end_frame,
};

const FP: &str = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

/// Channel tests spawn real local processes; keep them from overlapping.
static CHANNEL_TESTS: Mutex<()> = Mutex::new(());
static DIRS: AtomicU64 = AtomicU64::new(0);

const SHIM: &str = r#"#!/usr/bin/python3 -I
import os, sys
d = os.path.dirname(os.path.abspath(__file__))
args = sys.argv[1:]
with open(os.path.join(d, "argv.log"), "a") as log:
    log.write("\x1f".join([sys.argv[0]] + args) + "\x1f\x1e")
if args[:1] == ["--project"]:
    args = args[2:]
cmd, rest = args[0], args[1:]
if cmd == "query":
    name = "wssp-sbx-sbx-1"
    if rest[-1] != "/1.0/instances/%s?project=default" % name or os.path.exists(os.path.join(d, "deleted")):
        print('{"type":"error","error":"Instance not found","error_code":404}')
        sys.exit(1)
    status, code = ("Stopped", 102) if os.path.exists(os.path.join(d, "stopped")) else ("Running", 103)
    print('{"type":"sync","metadata":{"name":"%s","type":"virtual-machine","status":"%s","status_code":%d,"config":{"user.flycockpit.sandbox_id":"sbx-1","user.flycockpit.template_digest":"sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","volatile.base_image":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}}}' % (name, status, code))
    sys.exit(0)
if cmd != "exec":
    sys.stderr.write("Error: unexpected %s\n" % cmd)
    sys.exit(1)
tail = rest[rest.index("--") + 1:]
helper = tail[:4] == ["python3", "-I", "-S", "-c"] and len(tail) > 5
if helper and tail[5] == "launch":
    # Guest-root launcher stand-in: the scope and the cancel fence need guest
    # root; the wrapper chain after them runs for real.
    if os.path.exists(os.path.join(d, "refuse")):
        nonce = tail[7]
        os.write(1 if os.isatty(1) else 2, ("\x1eWSSP_CHAN %s REFUSED scope\x1f" % nonce).encode())
        sys.exit(120)
    inner = tail[tail.index("--", 6) + 1:]
    if "-t" in rest[: rest.index("--")]:
        os.execvp(inner[0], inner)
    # Like `incus exec -T`: this client relays the guest process's pipes, so
    # only it holds the host pipe ends; its death ends them (EOF) even while
    # guest survivors still hold their side.
    import subprocess, threading
    child = subprocess.Popen(inner, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, bufsize=0)
    def pump(src, dst):
        while True:
            data = src.read(65536)
            if not data:
                break
            try:
                os.write(dst, data)
            except OSError:
                # Like the real client: a closed output pipe ends it.
                os._exit(141)
    def feed():
        try:
            while True:
                data = os.read(0, 65536)
                if not data:
                    break
                child.stdin.write(data)
        except OSError:
            pass
        try:
            child.stdin.close()
        except OSError:
            pass
    threading.Thread(target=feed, daemon=True).start()
    out = threading.Thread(target=pump, args=(child.stdout, 1))
    err = threading.Thread(target=pump, args=(child.stderr, 2))
    out.start(); err.start()
    code = child.wait()
    out.join(); err.join()
    sys.exit(code if code >= 0 else 128 - code)
if helper and tail[5] == "kill":
    nonce = tail[6]
    verdict = "present" if os.path.exists(os.path.join(d, "present")) else "gone"
    with open(os.path.join(d, "kills"), "a") as kills:
        for item in tail[7:]:
            kills.write(item + "\n")
            print("WSSP_CHAN_KILL %s %s %s" % (nonce, item.rsplit(":", 1)[0], verdict))
    sys.exit(0)
os.execvp(tail[0], tail)
"#;

struct Shim {
    dir: PathBuf,
    runtime: IncusKvmRuntime,
    _serial: std::sync::MutexGuard<'static, ()>,
}

impl Drop for Shim {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

impl Shim {
    fn new() -> Self {
        let serial = CHANNEL_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "wssp-channel-shim-{}-{}",
            std::process::id(),
            DIRS.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("incus");
        super::shim_tests::install_executable(&binary, SHIM, 0o755);
        let client = IncusClient::new(binary.to_string_lossy().into_owned(), "default");
        // Static pin: the only binary these tests can run is the temp shim.
        assert!(Path::new(&client.binary).starts_with(std::env::temp_dir()));
        Self {
            dir,
            runtime: IncusKvmRuntime::from_test_client(client),
            _serial: serial,
        }
    }

    fn execs(&self) -> Vec<Vec<String>> {
        fs::read_to_string(self.dir.join("argv.log"))
            .unwrap_or_default()
            .split('\u{1e}')
            .filter(|record| !record.is_empty())
            .map(|record| {
                let mut argv: Vec<String> = record.split('\u{1f}').map(str::to_string).collect();
                argv.pop();
                argv
            })
            .filter(|argv| argv.get(3).map(String::as_str) == Some("exec"))
            .collect()
    }

    fn kills(&self) -> Vec<String> {
        fs::read_to_string(self.dir.join("kills"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }
}

fn guest() -> GuestIdentity {
    GuestIdentity {
        // The wrapper reports the uid it actually runs as (this test user).
        guest_uid: 1000,
        guest_gid: 1000,
        guest_home: "/home/user".into(),
        guest_shell: "/bin/sh".into(),
    }
}

/// The signal helper's own probe, run locally: does this kernel accept
/// process-group pidfd signals?
fn group_signals_supported() -> bool {
    let output = std::process::Command::new("python3")
        .args([
            "-I",
            "-c",
            super::exec::SIGNAL_HELPER,
            "wssp-signal-probe",
            "probe0123",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    match stderr.trim() {
        "WSSP_SIGNAL probe0123 group" => true,
        "WSSP_SIGNAL probe0123 unsupported" => false,
        other => panic!("unexpected probe output {other:?}"),
    }
}

fn request(mode: ChannelMode, argv: &[&str]) -> SpawnChannelRequest {
    SpawnChannelRequest {
        template_fingerprint: FP.into(),
        sandbox_id: "sbx-1".into(),
        connection_id: "conn1".into(),
        channel_id: format!("ch{}", DIRS.fetch_add(1, Ordering::Relaxed)),
        guest: guest(),
        mode,
        argv: (!argv.is_empty()).then(|| argv.iter().map(|a| a.to_string()).collect()),
        login: false,
        cwd: None,
        nonce: channel_nonce().unwrap(),
    }
}

fn pty() -> ChannelMode {
    ChannelMode::Pty {
        size: PtySize::new(24, 80).unwrap(),
        term: "xterm-256color".into(),
    }
}

/// The IO owner's view of one channel, as the daemon keeps it.
struct Driver {
    spawned: SpawnedChannel,
    pty: bool,
    filter: FrameFilter,
    preamble: Option<Vec<u8>>,
    input: Vec<Vec<u8>>,
    close_stdin: bool,
    prompted: bool,
    birth: Option<ChannelBirth>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    eof: [bool; 2],
    status: Option<ChannelExitStatus>,
    refused: bool,
    failed: Option<RelayFailure>,
    /// A relay channel: stdout is framed.
    relay: Option<RelayDecoder>,
    relay_end: Option<RelayEnd>,
}

impl Driver {
    fn new(spawned: SpawnedChannel, request: &SpawnChannelRequest, env: &[(&str, &str)]) -> Self {
        let secret = channel_nonce().unwrap();
        let env: Vec<(String, String)> = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Self {
            spawned,
            pty: matches!(request.mode, ChannelMode::Pty { .. }),
            filter: FrameFilter::new(&request.nonce, &secret),
            preamble: Some(channel_preamble(&env, &secret).unwrap()),
            input: Vec::new(),
            close_stdin: false,
            prompted: false,
            birth: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            eof: [false, false],
            status: None,
            refused: false,
            failed: None,
            relay: request.mode.is_relay().then(RelayDecoder::new),
            relay_end: None,
        }
    }

    fn spawn(shim: &Shim, request: &SpawnChannelRequest, env: &[(&str, &str)]) -> Self {
        Self::new(shim.runtime.spawn_channel(request).unwrap(), request, env)
    }

    fn input(mut self, chunks: &[&[u8]], close: bool) -> Self {
        // A relay's stdin is framed as the daemon frames it: data frames,
        // then the client's eof (`E`) before the close.
        self.input = if self.relay.is_some() {
            let mut framed: Vec<Vec<u8>> = chunks
                .iter()
                .flat_map(|c| c.chunks(32 * 1024))
                .map(relay_data_frame)
                .collect();
            if close {
                framed.push(relay_end_frame(RelayEnd::Eof));
            }
            framed
        } else {
            chunks.iter().map(|c| c.to_vec()).collect()
        };
        self.input.reverse();
        self.close_stdin = close;
        self
    }

    fn frame_stream(&self) -> ChannelOutput {
        if self.pty {
            ChannelOutput::Stdout
        } else {
            ChannelOutput::Stderr
        }
    }

    fn streams(&self) -> &'static [ChannelOutput] {
        if self.pty {
            &[ChannelOutput::Stdout]
        } else {
            &[ChannelOutput::Stdout, ChannelOutput::Stderr]
        }
    }

    fn done(&self) -> bool {
        self.streams().iter().all(|s| self.eof[*s as usize])
    }

    /// One owner tick.
    fn tick(&mut self) {
        let frame_stream = self.frame_stream();
        let streams = self.streams();
        let io = &mut self.spawned.io;
        if self.prompted
            && io.input_ready()
            && let Some(preamble) = self.preamble.take()
            && let Err(refused) = io.try_write(preamble)
        {
            assert!(!refused.closed, "stdin closed before the preamble");
            self.preamble = Some(refused.bytes);
        }
        if self.birth.is_some() {
            while let Some(chunk) = self.input.pop() {
                if let Err(refused) = io.try_write(chunk) {
                    self.input.push(refused.bytes);
                    break;
                }
            }
            if self.input.is_empty() && self.close_stdin && io.close_stdin() {
                self.close_stdin = false;
            }
        }
        for stream in streams.iter().copied() {
            // The workload's own stream is read only after READY.
            if self.eof[stream as usize] || (stream != frame_stream && self.birth.is_none()) {
                continue;
            }
            match io.try_read(stream) {
                ChannelRead::Data(bytes) => {
                    let data = if stream == frame_stream {
                        let (data, frames) = self.filter.feed(&bytes);
                        for frame in frames {
                            match frame {
                                GuestFrame::Prompt => self.prompted = true,
                                GuestFrame::Refused => self.refused = true,
                                GuestFrame::Ready(birth) => self.birth = Some(birth),
                                GuestFrame::Exit(status) => self.status = Some(status),
                                GuestFrame::Failed(failure) => self.failed = Some(failure),
                            }
                        }
                        data
                    } else if let Some(relay) = &mut self.relay {
                        let (data, end) = relay.feed(&bytes);
                        if end.is_some() {
                            self.relay_end = end;
                        }
                        data
                    } else {
                        bytes
                    };
                    match stream {
                        ChannelOutput::Stdout => self.stdout.extend(data),
                        ChannelOutput::Stderr => self.stderr.extend(data),
                    }
                }
                ChannelRead::WouldBlock => {}
                ChannelRead::Eof => {
                    if stream == frame_stream {
                        let rest = self.filter.finish();
                        match stream {
                            ChannelOutput::Stdout => self.stdout.extend(rest),
                            ChannelOutput::Stderr => self.stderr.extend(rest),
                        }
                    }
                    if stream == ChannelOutput::Stdout
                        && let Some(relay) = &mut self.relay
                    {
                        self.relay_end = Some(relay.finish());
                    }
                    self.eof[stream as usize] = true;
                }
            }
        }
    }

    fn run_until(&mut self, bound: Duration, done: impl Fn(&Self) -> bool) {
        let deadline = Instant::now() + bound;
        while !done(self) {
            assert!(
                Instant::now() < deadline,
                "channel stuck: ready {:?} status {:?} eof {:?} stdout {:?} stderr {:?}",
                self.birth,
                self.status,
                self.eof,
                String::from_utf8_lossy(&self.stdout),
                String::from_utf8_lossy(&self.stderr)
            );
            self.tick();
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// Until both streams ended, then the natural end.
    fn finish(mut self, bound: Duration) -> Self {
        self.run_until(bound, Self::done);
        let end = self.spawned.custody.close(ChannelClose::Finish);
        assert!(end.reaped);
        assert_eq!(end.scope, ChannelScope::Released);
        self
    }

    fn ready(&mut self) -> ChannelBirth {
        self.run_until(Duration::from_secs(10), |d| d.birth.is_some());
        self.birth.clone().unwrap()
    }
}

#[test]
fn exec_channel_runs_the_launcher_as_guest_root_and_round_trips_stdin() {
    let shim = Shim::new();
    let req = request(ChannelMode::Exec, &["cat"]);
    let out = Driver::spawn(&shim, &req, &[])
        .input(&[b"hello ", b"world"], true)
        .finish(Duration::from_secs(10));
    assert_eq!(out.stdout, b"hello world");
    assert!(out.stderr.is_empty(), "frames never leak: {:?}", out.stderr);
    assert_eq!(out.status, Some(ChannelExitStatus::Code(0)));
    let exec = &shim.execs()[0];
    let tail = exec.iter().position(|a| a == "--").unwrap();
    // Only the fixed helper runs as guest root (it drops before the workload).
    assert_eq!(&exec[4..8], ["--user", "0", "--group", "0"]);
    assert_eq!(exec[tail - 2], "-T");
    assert_eq!(exec[tail - 1], "wssp-sbx-sbx-1");
    assert_eq!(&exec[tail + 1..tail + 5], ["python3", "-I", "-S", "-c"]);
    assert_eq!(exec[tail + 6], "launch");
    assert_eq!(exec[tail + 7], req.scope_unit().unwrap());
    assert_eq!(exec[tail + 8], req.nonce);
    assert_eq!(&exec[tail + 9..tail + 11], ["1000", "1000"]);
    let wrap = exec.iter().position(|a| a == "wrap").unwrap();
    assert_eq!(
        &exec[wrap + 1..wrap + 5],
        ["WSSP_PID", &req.nonce, "exec", "0"]
    );
    assert_eq!(exec.last().unwrap(), "cat");
}

#[test]
fn exec_exit_code_143_is_not_a_sigterm_death() {
    let shim = Shim::new();
    let req = request(ChannelMode::Exec, &["sh", "-c", "echo e >&2; exit 143"]);
    let out = Driver::spawn(&shim, &req, &[]).finish(Duration::from_secs(10));
    assert_eq!(out.status, Some(ChannelExitStatus::Code(143)));
    assert_eq!(out.stderr, b"e\n");
    let req = request(ChannelMode::Exec, &["sh", "-c", "kill -TERM $$"]);
    let out = Driver::spawn(&shim, &req, &[]).finish(Duration::from_secs(10));
    assert_eq!(out.status, Some(ChannelExitStatus::Signal(15)));
}

#[test]
fn exec_argv_is_structural() {
    let shim = Shim::new();
    let req = request(
        ChannelMode::Exec,
        &["printf", "[%s]", "a b", "", "$x;|'\"", "*"],
    );
    let out = Driver::spawn(&shim, &req, &[]).finish(Duration::from_secs(10));
    assert_eq!(out.stdout, b"[a b][][$x;|'\"][*]");
}

#[test]
fn env_reaches_the_workload_only_through_the_preamble() {
    let shim = Shim::new();
    let req = request(
        ChannelMode::Exec,
        &["sh", "-c", "printf %s \"$WSSP_TEST_VALUE\"; cat"],
    );
    let out = Driver::spawn(&shim, &req, &[("WSSP_TEST_VALUE", "secret-ish")])
        .input(&[b"+in"], true)
        .finish(Duration::from_secs(10));
    assert_eq!(out.stdout, b"secret-ish+in");
    let req = request(pty(), &["sh", "-c", "printf '<%s>' \"$WSSP_TEST_VALUE\""]);
    let out = Driver::spawn(&shim, &req, &[("WSSP_TEST_VALUE", "tty-value")])
        .finish(Duration::from_secs(10));
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("<tty-value>"),
        "{:?}",
        out.stdout
    );
    for exec in shim.execs() {
        assert!(
            !exec
                .iter()
                .any(|a| a.contains("secret-ish") || a.contains("tty-value")),
            "env value in argv"
        );
    }
}

#[test]
fn nothing_runs_without_the_last_preamble_byte() {
    let shim = Shim::new();
    let marker = shim.dir.join("ran");
    let script = format!("touch {}", marker.display());
    for mode in [ChannelMode::Exec, pty()] {
        let req = request(mode, &["sh", "-c", &script]);
        let mut driver = Driver::spawn(&shim, &req, &[("A", "b")]);
        driver.run_until(Duration::from_secs(10), |d| d.prompted);
        // Everything but the go byte.
        let mut preamble = driver.preamble.take().unwrap();
        preamble.pop();
        let deadline = Instant::now() + Duration::from_secs(5);
        while let Err(refused) = driver.spawned.io.try_write(preamble) {
            preamble = refused.bytes;
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(2));
        }
        // The writer took the chunk; a later chunk is accepted only once it
        // is written into the pipe.
        let deadline = Instant::now() + Duration::from_secs(5);
        while let Err(refused) = driver.spawned.io.try_write(Vec::new()) {
            assert!(!refused.closed);
            assert!(
                Instant::now() < deadline,
                "the prefix never reached the pipe"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        // With the custody alive, the wrapper waits: no READY, no workload.
        let started = Instant::now();
        while started.elapsed() < Duration::from_millis(700) {
            driver.tick();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(driver.birth.is_none(), "READY before the go byte");
        assert!(!marker.exists(), "the workload ran before the go byte");
        let SpawnedChannel { io, mut custody } = driver.spawned;
        drop(io);
        let end = custody.close(ChannelClose::Kill { forget: false });
        assert!(end.reaped);
        assert!(!marker.exists(), "a truncated preamble starts no workload");
    }
}

#[test]
fn exec_stdin_stays_open_after_the_io_is_dropped_until_the_custody_closes() {
    let shim = Shim::new();
    let marker = shim.dir.join("eof");
    let script = format!("cat >/dev/null; touch {}", marker.display());
    let req = request(ChannelMode::Exec, &["sh", "-c", &script]);
    let mut driver = Driver::spawn(&shim, &req, &[]);
    driver.ready();
    let SpawnedChannel { io, mut custody } = driver.spawned;
    drop(io);
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !marker.exists(),
        "no stdin EOF reaches the workload ahead of the custody's close"
    );
    let end = custody.close(ChannelClose::Kill { forget: true });
    assert_eq!(end.scope, ChannelScope::Killed);
}

#[test]
fn exec_signal_reaches_the_wrapper_group_through_the_helper() {
    let shim = Shim::new();
    let req = request(ChannelMode::Exec, &["sleep", "30"]);
    let mut driver = Driver::spawn(&shim, &req, &[]);
    let birth = driver.ready();
    let outcome = driver
        .spawned
        .custody
        .signal(&birth, ProcessSignal::Sigterm);
    if !group_signals_supported() {
        // Kernel without pidfd group signals: refused, never widened.
        assert_eq!(outcome, ChannelSignalOutcome::Unsupported);
        driver
            .spawned
            .custody
            .close(ChannelClose::Kill { forget: true });
        return;
    }
    assert_eq!(outcome, ChannelSignalOutcome::Delivered);
    let mut out = driver.finish(Duration::from_secs(10));
    assert_eq!(out.status, Some(ChannelExitStatus::Signal(15)));
    assert_eq!(
        out.spawned.custody.signal(&birth, ProcessSignal::Sigint),
        ChannelSignalOutcome::Ended
    );
}

#[test]
fn kill_close_tombstones_and_proves_the_scope_gone() {
    let shim = Shim::new();
    let req = request(ChannelMode::Exec, &["sleep", "30"]);
    let mut driver = Driver::spawn(&shim, &req, &[]);
    driver.ready();
    let end = driver
        .spawned
        .custody
        .close(ChannelClose::Kill { forget: true });
    assert_eq!(end.scope, ChannelScope::Killed);
    assert!(end.reaped);
    // READY was seen, so the helper may drop the tombstone after the proof.
    assert_eq!(
        shim.kills(),
        vec![format!("{}:1", req.scope_unit().unwrap())]
    );
}

#[test]
fn an_unproven_kill_is_uncertain_and_a_stopped_vm_is_proof() {
    let shim = Shim::new();
    fs::write(shim.dir.join("present"), "").unwrap();
    let req = request(ChannelMode::Exec, &["sleep", "30"]);
    let mut driver = Driver::spawn(&shim, &req, &[]);
    driver.ready();
    let end = driver
        .spawned
        .custody
        .close(ChannelClose::Kill { forget: true });
    assert_eq!(end.scope, ChannelScope::Uncertain);
    assert!(!end.settled());
    let sweep = KillScopesRequest {
        sandbox_id: "sbx-1".into(),
        template_fingerprint: FP.into(),
        guest: guest(),
        scopes: vec![ChannelScopeRef {
            unit: req.scope_unit().unwrap(),
            forget: false,
        }],
    };
    let results = shim.runtime.kill_channel_scopes(&sweep).unwrap();
    assert_eq!(results[0].1, ScopeKill::Present);
    fs::write(shim.dir.join("stopped"), "").unwrap();
    let before = shim.kills().len();
    let results = shim.runtime.kill_channel_scopes(&sweep).unwrap();
    assert_eq!(results[0].1, ScopeKill::Gone);
    assert_eq!(
        shim.kills().len(),
        before,
        "a stopped VM needs no guest exec"
    );
    fs::write(shim.dir.join("deleted"), "").unwrap();
    let results = shim.runtime.kill_channel_scopes(&sweep).unwrap();
    assert_eq!(results[0].1, ScopeKill::Gone);
    // The proof is in: end and reap the local client.
    let SpawnedChannel { io, mut custody } = driver.spawned;
    drop(io);
    assert!(custody.terminate());
}

#[test]
fn a_refused_launcher_ends_the_frame_stream_with_a_refusal_and_no_ready() {
    let shim = Shim::new();
    fs::write(shim.dir.join("refuse"), "").unwrap();
    let req = request(ChannelMode::Exec, &["true"]);
    let mut driver = Driver::spawn(&shim, &req, &[]);
    driver.run_until(Duration::from_secs(10), |d| d.eof[1]);
    assert!(driver.refused);
    assert!(driver.birth.is_none() && !driver.prompted);
    let end = driver
        .spawned
        .custody
        .close(ChannelClose::Kill { forget: false });
    assert!(end.reaped);
}

#[test]
fn pty_channel_runs_argv_on_a_tty_and_strips_the_frames() {
    let shim = Shim::new();
    let req = request(
        pty(),
        &[
            "sh",
            "-c",
            "tty >/dev/null && stty size; printf '[%s]' \"$TERM\"; exit 7",
        ],
    );
    let out = Driver::spawn(&shim, &req, &[]).finish(Duration::from_secs(10));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("24 80"), "{text:?}");
    assert!(!text.contains("WSSP_CHAN"), "{text:?}");
    assert_eq!(out.status, Some(ChannelExitStatus::Code(7)));
    let exec = &shim.execs()[0];
    let tail = exec.iter().position(|a| a == "--").unwrap();
    assert_eq!(exec[tail - 2], "-t");
    assert!(exec.contains(&"TERM=xterm-256color".to_string()));
}

#[test]
fn pty_output_is_never_dropped_for_a_slow_consumer() {
    let shim = Shim::new();
    let req = request(
        pty(),
        &["sh", "-c", "head -c 3000000 /dev/zero | tr '\\0' x; exit 3"],
    );
    let mut driver = Driver::spawn(&shim, &req, &[]);
    driver.ready();
    // The reader holds one chunk and the kernel the rest; nothing is dropped.
    std::thread::sleep(Duration::from_millis(2500));
    let out = driver.finish(Duration::from_secs(30));
    let xs = out.stdout.iter().filter(|b| **b == b'x').count();
    assert_eq!(xs, 3_000_000);
    assert_eq!(out.status, Some(ChannelExitStatus::Code(3)));
}

#[test]
fn pty_hangup_releases_the_scope() {
    let shim = Shim::new();
    let req = request(pty(), &["sleep", "30"]);
    let mut driver = Driver::spawn(&shim, &req, &[]);
    let birth = driver.ready();
    let SpawnedChannel { io, mut custody } = driver.spawned;
    drop(io);
    let end = custody.close(ChannelClose::Hangup(Some(birth)));
    assert_eq!(end.scope, ChannelScope::Released);
    assert!(end.reaped);
    assert!(shim.kills().is_empty(), "a normal close kills no scope");
}

#[test]
fn a_workload_cannot_forge_its_exit_with_the_argv_nonce() {
    let shim = Shim::new();
    // The workload reads the public argv nonce of its wrapper (as any guest
    // process can) and writes an EXIT frame with it, then keeps running.
    let find = "n=$(tr '\\0' ' ' < /proc/$PPID/cmdline | sed -n 's/.*WSSP_PID \\([0-9a-f]*\\) .*/\\1/p'); ";
    let exec =
        format!("{find}printf '\\036WSSP_CHAN %s EXIT code 0\\037' \"$n\" >&2; sleep 1; exit 4");
    let req = request(ChannelMode::Exec, &["sh", "-c", &exec]);
    let out = Driver::spawn(&shim, &req, &[]).finish(Duration::from_secs(15));
    assert_eq!(out.status, Some(ChannelExitStatus::Code(4)));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("WSSP_CHAN"),
        "the forged frame is plain data: {:?}",
        out.stderr
    );
    let tty = format!("{find}printf '\\036WSSP_CHAN %s EXIT code 0\\037' \"$n\"; sleep 1; exit 4");
    let req = request(pty(), &["sh", "-c", &tty]);
    let out = Driver::spawn(&shim, &req, &[]).finish(Duration::from_secs(15));
    assert_eq!(
        out.status,
        Some(ChannelExitStatus::Code(4)),
        "pty frames are secret-bound too"
    );
}

#[test]
fn silent_fast_workloads_end_naturally_in_both_modes() {
    let shim = Shim::new();
    let req = request(ChannelMode::Exec, &["true"]);
    let out = Driver::spawn(&shim, &req, &[]).finish(Duration::from_secs(10));
    assert_eq!(out.status, Some(ChannelExitStatus::Code(0)));
    assert!(out.birth.is_some(), "stdout is read only after READY");
    let req = request(pty(), &["true"]);
    let out = Driver::spawn(&shim, &req, &[]).finish(Duration::from_secs(10));
    assert!(out.birth.is_some());
    assert_eq!(out.status, Some(ChannelExitStatus::Code(0)));
    assert!(shim.kills().is_empty(), "a natural end kills nothing");
}

#[test]
fn finishing_a_channel_with_a_survivor_ends_its_streams_at_once() {
    let shim = Shim::new();
    let req = request(
        ChannelMode::Exec,
        &[
            "sh",
            "-c",
            "(trap '' HUP; exec timeout 12 yes) & sleep 0.3; exit 0",
        ],
    );
    let mut driver = Driver::spawn(&shim, &req, &[]);
    driver.run_until(Duration::from_secs(10), |d| d.status.is_some());
    assert_eq!(driver.status, Some(ChannelExitStatus::Code(0)));
    let started = Instant::now();
    let end = driver.spawned.custody.close(ChannelClose::Finish);
    assert!(end.reaped);
    driver.run_until(Duration::from_secs(5), Driver::done);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "terminating the client ends both host pipes: {:?}",
        started.elapsed()
    );
    assert!(!driver.stdout.is_empty());
}

#[test]
fn an_unproven_kill_leaves_the_client_and_stdin_until_a_later_proof() {
    let shim = Shim::new();
    fs::write(shim.dir.join("present"), "").unwrap();
    let marker = shim.dir.join("eof");
    let script = format!("cat >/dev/null; touch {}", marker.display());
    let req = request(ChannelMode::Exec, &["sh", "-c", &script]);
    let mut driver = Driver::spawn(&shim, &req, &[]);
    driver.ready();
    let SpawnedChannel { io, mut custody } = driver.spawned;
    drop(io);
    let end = custody.close(ChannelClose::Kill { forget: true });
    assert_eq!(end.scope, ChannelScope::Uncertain);
    assert!(!end.reaped, "the client keeps running");
    std::thread::sleep(Duration::from_millis(300));
    assert!(!custody.reap_confirmed());
    assert!(
        !marker.exists(),
        "no stdin EOF reaches a workload the kill may have missed"
    );
    // A later kill proved the scope gone: the custodian ends the client.
    assert!(custody.terminate());
}

#[test]
fn an_unproven_kill_keeps_the_output_pipes_of_a_writing_workload() {
    let shim = Shim::new();
    fs::write(shim.dir.join("present"), "").unwrap();
    // Keeps writing: if the daemon closed its pipe ends, the client relaying
    // this output would hit EPIPE and end before the kill is proven.
    let req = request(
        ChannelMode::Exec,
        &["sh", "-c", "while :; do echo x; echo y >&2; done"],
    );
    let mut driver = Driver::spawn(&shim, &req, &[]);
    driver.ready();
    let SpawnedChannel { io, mut custody } = driver.spawned;
    drop(io);
    let end = custody.close(ChannelClose::Kill { forget: true });
    assert_eq!(end.scope, ChannelScope::Uncertain);
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !custody.reap_confirmed(),
        "the client ended before a kill proof"
    );
    assert!(custody.terminate());
}

/// The workload starts only after READY is written, and READY only once the
/// workload child runs with default signal dispositions: a group signal sent
/// while READY is being written (held up by a full frame pipe) reaches the
/// workload, which never runs.
#[test]
fn a_group_signal_at_ready_always_reaches_the_workload() {
    use std::io::{Read, Write};
    let shim = Shim::new();
    let marker = shim.dir.join("started");
    let nonce = channel_nonce().unwrap();
    let secret = channel_nonce().unwrap();
    let limits = sandbox_protocol::env_limits();
    let (mut frames, frames_w) = std::io::pipe().unwrap();
    let mut filler = frames_w.try_clone().unwrap();
    let mut relay = std::process::Command::new("python3")
        .args([
            "-I",
            "-S",
            "-c",
            super::channel::CHANNEL_HELPER,
            "wrap",
            "WSSP_PID",
        ])
        .arg(&nonce)
        .args(["exec", "0", "30000"])
        .args([
            limits.max_entries.to_string(),
            limits.key_bytes.to_string(),
            limits.value_bytes.to_string(),
            limits.json_bytes.to_string(),
        ])
        .args(["--", "sh", "-c"])
        .arg(format!("touch {}", marker.display()))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::from(frames_w))
        .spawn()
        .unwrap();
    // PROMPT first.
    let prompt = guest_frame_bytes(&nonce, "PROMPT");
    let mut got = vec![0u8; prompt.len()];
    frames.read_exact(&mut got).unwrap();
    assert_eq!(got, prompt);
    // Fill the frame pipe: READY cannot be written until it is drained. The
    // filler blocked in a pipe write proves the pipe is full.
    let (tid_tx, tid_rx) = std::sync::mpsc::channel();
    let fill = std::thread::spawn(move || {
        let me = fs::read_link("/proc/thread-self").unwrap();
        tid_tx.send(me).unwrap();
        let _ = filler.write_all(&vec![b'.'; 1 << 20]);
    });
    let filler_task = Path::new("/proc").join(tid_rx.recv().unwrap());
    wait_for("the frame pipe is full", || {
        blocked_in_pipe_write(&filler_task)
    });
    let mut stdin = relay.stdin.take().unwrap();
    stdin
        .write_all(&channel_preamble(&[], &secret).unwrap())
        .unwrap();
    // The wrapper (the relay's child, a session and group leader) is blocked
    // writing READY, and its workload child already runs with default signal
    // dispositions (the gate): signal its group as the signal helper would.
    let wrapper = wait_for_child(relay.id());
    let workload = wait_for_child(wrapper);
    wait_for("the workload child has default signals", || {
        default_dispositions(workload)
    });
    wait_for("the wrapper is blocked writing READY", || {
        blocked_in_pipe_write(&Path::new("/proc").join(wrapper.to_string()))
    });
    assert!(
        !marker.exists(),
        "the workload ran before READY was written"
    );
    let status = std::process::Command::new("kill")
        .args(["-TERM", "--", &format!("-{wrapper}")])
        .status()
        .unwrap();
    assert!(status.success());
    // Drain: READY, then the workload's signal death.
    let mut seen = Vec::new();
    let ready = format!("\x1eWSSP_CHAN {secret} READY ");
    let mut buf = vec![0u8; 1 << 16];
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(Instant::now() < deadline, "the frame pipe never ended");
        let n = frames.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        seen.extend_from_slice(&buf[..n]);
    }
    let text = String::from_utf8_lossy(&seen);
    assert!(text.contains(&ready), "READY was written");
    let exit = String::from_utf8_lossy(&guest_frame_bytes(&secret, "EXIT signal 15")).into_owned();
    assert!(text.contains(&exit), "the signal reached the workload");
    assert!(!marker.exists(), "the workload ran despite the signal");
    drop(stdin);
    let _ = relay.wait().unwrap();
    fill.join().unwrap();
}

/// Bounded wait (no fixed sleeps standing in for a condition).
fn wait_for(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "never reached: {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The first child of `pid` (bounded wait until it exists).
fn wait_for_child(pid: u32) -> u32 {
    let path = format!("/proc/{pid}/task/{pid}/children");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(child) = fs::read_to_string(&path)
            .ok()
            .and_then(|c| c.split_whitespace().next().map(str::to_string))
        {
            return child.parse().unwrap();
        }
        assert!(Instant::now() < deadline, "{pid} never forked");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The task at `/proc/...` sleeps in a pipe write (`anon_pipe_write`, or
/// `pipe_write` on older kernels): its pipe is full.
fn blocked_in_pipe_write(task: &Path) -> bool {
    fs::read_to_string(task.join("wchan")).is_ok_and(|w| w.trim_end().ends_with("pipe_write"))
}

/// No signal is caught, ignored or blocked by `pid`.
fn default_dispositions(pid: u32) -> bool {
    let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
        return false;
    };
    ["SigBlk:", "SigIgn:", "SigCgt:"].iter().all(|key| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .is_some_and(|mask| mask.trim().bytes().all(|b| b == b'0'))
    })
}

// ---------------------------------------------------------------- relay ----

/// A one-connection guest service on this host's loopback (the shim's
/// "guest"): `serve` runs on the accepted socket; the bytes it read come
/// back through the handle.
fn tcp_service(
    serve: impl FnOnce(&mut std::net::TcpStream) + Send + 'static,
) -> (u16, std::thread::JoinHandle<Vec<u8>>) {
    use std::io::Read;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        serve(&mut stream);
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest);
        rest
    });
    (port, handle)
}

fn relay_request(mode: ChannelMode) -> SpawnChannelRequest {
    request(mode, &[])
}

#[test]
fn a_tcp_relay_runs_the_real_helper_as_the_guest_user_and_round_trips() {
    use std::io::{Read, Write};
    let shim = Shim::new();
    // An echo service: everything back, then its own close.
    let (port, service) = tcp_service(|stream| {
        let mut all = Vec::new();
        stream.read_to_end(&mut all).unwrap();
        stream.write_all(&all).unwrap();
    });
    let req = relay_request(ChannelMode::Tcp { port });
    let big: Vec<u8> = (0..300_000_u32).map(|i| (i % 251) as u8).collect();
    let out = Driver::spawn(&shim, &req, &[])
        .input(&[b"hello ", &big], true)
        .finish(Duration::from_secs(20));
    let mut expected = b"hello ".to_vec();
    expected.extend(&big);
    assert!(out.stdout == expected, "the relayed bytes differ");
    assert!(out.stderr.is_empty(), "frames never leak: {:?}", out.stderr);
    assert_eq!(out.relay_end, Some(RelayEnd::Eof));
    assert_eq!(out.status, Some(ChannelExitStatus::Code(0)));
    assert!(service.join().unwrap().is_empty());
    let exec = &shim.execs()[0];
    let tail = exec.iter().position(|a| a == "--").unwrap();
    assert_eq!(&exec[4..8], ["--user", "0", "--group", "0"]);
    assert_eq!(exec[tail - 2], "-T");
    assert_eq!(exec[tail + 6], "launch");
    let wrap = exec.iter().position(|a| a == "wrap").unwrap();
    assert_eq!(
        &exec[wrap + 1..wrap + 5],
        ["WSSP_PID", &req.nonce, "tcp", "0"]
    );
    // The target is the only argument: a port, never a host.
    let dashes = exec[wrap..].iter().position(|a| a == "--").unwrap() + wrap;
    assert_eq!(&exec[dashes + 1..], [port.to_string()]);
}

#[test]
fn a_guest_service_that_shuts_its_write_side_still_gets_later_input() {
    use std::io::Write;
    let shim = Shim::new();
    // Greets, shuts its write side, then waits for (and records) more input.
    let (port, service) = tcp_service(|stream| {
        stream.write_all(b"220 ready\r\n").unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
    });
    let req = relay_request(ChannelMode::Tcp { port });
    let mut driver = Driver::spawn(&shim, &req, &[]);
    driver.run_until(Duration::from_secs(10), |d| d.relay_end.is_some());
    assert_eq!(driver.stdout, b"220 ready\r\n");
    assert_eq!(
        driver.relay_end,
        Some(RelayEnd::Eof),
        "the EOF travelled first"
    );
    assert!(driver.status.is_none(), "the relay still runs");
    // The client keeps talking after the guest's EOF.
    let driver = driver
        .input(&[b"late ", b"input"], true)
        .finish(Duration::from_secs(10));
    assert_eq!(service.join().unwrap(), b"late input");
    assert_eq!(driver.status, Some(ChannelExitStatus::Code(0)));
}

#[test]
fn a_client_half_close_reaches_the_service_before_its_reply() {
    use std::io::{Read, Write};
    let shim = Shim::new();
    let (port, service) = tcp_service(|stream| {
        let mut request = Vec::new();
        // Only the client's write shutdown ends this read.
        stream.read_to_end(&mut request).unwrap();
        let mut reply = b"got ".to_vec();
        reply.extend(&request);
        stream.write_all(&reply).unwrap();
    });
    let req = relay_request(ChannelMode::Tcp { port });
    let out = Driver::spawn(&shim, &req, &[])
        .input(&[b"query"], true)
        .finish(Duration::from_secs(10));
    assert_eq!(out.stdout, b"got query");
    assert_eq!(out.relay_end, Some(RelayEnd::Eof));
    assert!(service.join().unwrap().is_empty());
}

#[test]
fn a_reset_by_the_service_ends_the_relay_with_a_reset() {
    use std::io::Read;
    let shim = Shim::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let service = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut one = [0_u8; 1];
        stream.read_exact(&mut one).unwrap();
        // Closing with unread bytes in the receive queue is a reset (RST).
        std::thread::sleep(Duration::from_millis(300));
        drop(stream);
    });
    let req = relay_request(ChannelMode::Tcp { port });
    let mut driver = Driver::spawn(&shim, &req, &[]).input(&[b"x", b"more bytes"], false);
    driver.run_until(Duration::from_secs(10), |d| {
        d.eof == [true, true] && d.relay_end.is_some()
    });
    service.join().unwrap();
    assert_eq!(driver.relay_end, Some(RelayEnd::Reset));
    assert_eq!(driver.status, Some(ChannelExitStatus::Code(1)));
}

#[test]
fn a_reset_after_the_guest_write_shutdown_is_a_reset_not_a_clean_end() {
    // The review's case: the service greets, shuts its write side, then
    // resets while it receives more input. `E` travels first; the reset
    // after it is an `R` and exit 1, never the clean exit 0.
    use std::io::{Read, Write};
    let shim = Shim::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let service = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(b"220 ready\r\n").unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut one = [0_u8; 1];
        stream.read_exact(&mut one).unwrap();
        // Closing with unread input is a reset (RST).
        std::thread::sleep(Duration::from_millis(300));
        drop(stream);
    });
    let req = relay_request(ChannelMode::Tcp { port });
    let mut driver = Driver::spawn(&shim, &req, &[]);
    driver.run_until(Duration::from_secs(10), |d| d.relay_end.is_some());
    assert_eq!(driver.relay_end, Some(RelayEnd::Eof));
    let mut driver = driver.input(&[b"x", b"more bytes"], false);
    driver.run_until(Duration::from_secs(10), |d| {
        d.eof == [true, true] && d.status.is_some()
    });
    service.join().unwrap();
    assert_eq!(driver.stdout, b"220 ready\r\n");
    assert_eq!(driver.relay_end, Some(RelayEnd::Reset), "R after E");
    assert!(driver.relay.as_ref().unwrap().eof_seen());
    assert_eq!(driver.status, Some(ChannelExitStatus::Code(1)));
}

#[test]
fn a_reset_after_the_guest_write_shutdown_is_seen_while_the_client_is_idle() {
    // Nothing more to send either way: the helper still watches the socket
    // for an error, so the reset arrives without waiting for client bytes.
    use std::io::Write;
    let shim = Shim::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (go, wait) = std::sync::mpsc::channel::<()>();
    let service = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        // The client's first bytes stay unread, so the close below resets.
        let mut one = [0_u8; 1];
        stream.peek(&mut one).unwrap();
        stream.write_all(b"bye").unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        wait.recv().unwrap();
        drop(stream);
    });
    let req = relay_request(ChannelMode::Tcp { port });
    let mut driver = Driver::spawn(&shim, &req, &[]).input(&[b"hello"], false);
    driver.run_until(Duration::from_secs(10), |d| d.relay_end.is_some());
    assert_eq!(driver.relay_end, Some(RelayEnd::Eof));
    std::thread::sleep(Duration::from_millis(200));
    driver.tick();
    assert!(driver.status.is_none(), "the relay waits for the client");
    go.send(()).unwrap();
    driver.run_until(Duration::from_secs(10), |d| {
        d.eof == [true, true] && d.status.is_some()
    });
    service.join().unwrap();
    assert_eq!(driver.relay_end, Some(RelayEnd::Reset));
    assert_eq!(driver.status, Some(ChannelExitStatus::Code(1)));
}

#[test]
fn a_reset_after_the_client_half_close_is_a_reset_without_an_eof() {
    // The client already sent its eof (the helper shut the socket's write
    // side); the service then closes with that input unread: a Unix reset
    // (ECONNRESET after its data), so `R` with no `E` and exit 1.
    use std::io::{Read, Write};
    let shim = Shim::new();
    let path = shim.dir.join("reset.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let service = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        // Wait (blocking) for the request, then leave the rest of it
        // unread: the close below is a reset whenever the helper runs.
        let mut one = [0_u8; 1];
        stream.read_exact(&mut one).unwrap();
        stream.write_all(b"partial").unwrap();
    });
    let req = relay_request(ChannelMode::Unix {
        path: path.to_string_lossy().into_owned(),
    });
    let mut driver = Driver::spawn(&shim, &req, &[]).input(&[b"request"], true);
    driver.run_until(Duration::from_secs(10), |d| {
        d.eof == [true, true] && d.status.is_some()
    });
    service.join().unwrap();
    assert_eq!(driver.stdout, b"partial");
    assert_eq!(driver.relay_end, Some(RelayEnd::Reset));
    assert!(!driver.relay.as_ref().unwrap().eof_seen());
    assert_eq!(driver.status, Some(ChannelExitStatus::Code(1)));
}

#[test]
fn a_unix_service_that_closes_after_its_reply_still_ends_cleanly() {
    // A Unix peer's full close is a hang-up, not an error: the relay keeps
    // waiting for the client's end and exits 0.
    use std::io::Write;
    let shim = Shim::new();
    let path = shim.dir.join("close.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let service = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(b"reply").unwrap();
    });
    let req = relay_request(ChannelMode::Unix {
        path: path.to_string_lossy().into_owned(),
    });
    let mut driver = Driver::spawn(&shim, &req, &[]);
    driver.run_until(Duration::from_secs(10), |d| d.relay_end.is_some());
    service.join().unwrap();
    std::thread::sleep(Duration::from_millis(200));
    driver.tick();
    assert!(driver.status.is_none(), "the relay waits for the client");
    let out = driver.input(&[], true).finish(Duration::from_secs(10));
    assert_eq!(out.stdout, b"reply");
    assert_eq!(out.relay_end, Some(RelayEnd::Eof));
    assert_eq!(out.status, Some(ChannelExitStatus::Code(0)));
}

/// A loopback port nothing listens on, reserved while the guard lives: the
/// local end of a connected socket (bound, never listening), so a connect
/// to it is refused and no other test's listener can take it meanwhile.
fn refused_port() -> (u16, (std::net::TcpStream, std::net::TcpStream)) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client.local_addr().unwrap().port(), (client, server))
}

#[test]
fn a_refused_port_reports_failed_before_ready_and_starts_nothing() {
    let shim = Shim::new();
    let (port, _reserved) = refused_port();
    let req = relay_request(ChannelMode::Tcp { port });
    let mut driver = Driver::spawn(&shim, &req, &[]);
    driver.run_until(Duration::from_secs(10), |d| d.eof[1]);
    assert_eq!(driver.failed, Some(RelayFailure::Refused));
    assert!(driver.birth.is_none(), "no READY for a refused connect");
    assert!(driver.stderr.is_empty(), "{:?}", driver.stderr);
}

#[test]
fn a_unix_relay_reaches_the_socket_path() {
    use std::io::{Read, Write};
    let shim = Shim::new();
    let path = shim.dir.join("app.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let service = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut all = Vec::new();
        stream.read_to_end(&mut all).unwrap();
        stream.write_all(&all).unwrap();
    });
    let req = relay_request(ChannelMode::Unix {
        path: path.to_string_lossy().into_owned(),
    });
    let out = Driver::spawn(&shim, &req, &[])
        .input(&[b"over a socket"], true)
        .finish(Duration::from_secs(10));
    service.join().unwrap();
    assert_eq!(out.stdout, b"over a socket");
    assert_eq!(out.status, Some(ChannelExitStatus::Code(0)));
    // A missing path is a refusal.
    let req = relay_request(ChannelMode::Unix {
        path: shim.dir.join("missing.sock").to_string_lossy().into_owned(),
    });
    let mut driver = Driver::spawn(&shim, &req, &[]);
    driver.run_until(Duration::from_secs(10), |d| d.eof[1]);
    assert_eq!(driver.failed, Some(RelayFailure::Refused));
}

#[test]
fn a_refused_ipv4_loopback_falls_back_to_ipv6() {
    use std::io::{Read, Write};
    // The IPv4 port stays reserved and refused for the whole test.
    let (port, _reserved) = refused_port();
    let Ok(listener) = std::net::TcpListener::bind(("::1", port)) else {
        return; // No IPv6 loopback on this host.
    };
    let shim = Shim::new();
    let service = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut all = Vec::new();
        stream.read_to_end(&mut all).unwrap();
        stream.write_all(b"v6").unwrap();
    });
    let req = relay_request(ChannelMode::Tcp { port });
    let out = Driver::spawn(&shim, &req, &[])
        .input(&[b"hi"], true)
        .finish(Duration::from_secs(10));
    service.join().unwrap();
    assert_eq!(out.stdout, b"v6");
}

/// What a partial-request service saw: the request head, the outcome of
/// the read after it (EOF or the error), and its socket.
type PartialRequest<S> = (Vec<u8>, std::io::Result<Vec<u8>>, S);

/// A guest service that records the first `want` request bytes, reports
/// them, and then reads on.
fn partial_request_service<S: std::io::Read + Send + 'static>(
    accept: impl FnOnce() -> S + Send + 'static,
    want: usize,
) -> (
    std::sync::mpsc::Receiver<()>,
    std::thread::JoinHandle<PartialRequest<S>>,
) {
    let (got, seen) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let mut stream = accept();
        let mut head = vec![0_u8; want];
        stream.read_exact(&mut head).unwrap();
        got.send(()).unwrap();
        let mut rest = Vec::new();
        let outcome = stream.read_to_end(&mut rest).map(|_| rest);
        (head, outcome, stream)
    });
    (seen, handle)
}

#[test]
fn a_killed_tcp_relay_resets_the_guest_service_mid_request() {
    // A kill close (local reset, Ctrl-C, revocation, deadline, ...) SIGKILLs
    // the helper: the service must see a reset, never a clean EOF that would
    // make the partial request look complete.
    let shim = Shim::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (seen, service) = partial_request_service(
        move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(15)))
                .unwrap();
            stream
        },
        b"POST /half".len(),
    );
    let req = relay_request(ChannelMode::Tcp { port });
    let mut driver = Driver::spawn(&shim, &req, &[]).input(&[b"POST /half"], false);
    driver.run_until(Duration::from_secs(10), |_| seen.try_recv().is_ok());
    let end = driver
        .spawned
        .custody
        .close(ChannelClose::Kill { forget: true });
    assert!(end.reaped);
    let (head, outcome, _stream) = service.join().unwrap();
    assert_eq!(head, b"POST /half");
    assert_eq!(
        outcome.map_err(|e| e.kind()),
        Err(std::io::ErrorKind::ConnectionReset),
        "an aborted relay must reset the service, not end its request"
    );
}

#[test]
fn a_relay_stdin_that_ends_without_its_eof_frame_resets_the_guest_service() {
    // The host client or the daemon died: stdin just ends, with no `E`. That
    // is an abort (a reset, exit 1), never the client's clean half-close.
    let shim = Shim::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (seen, service) = partial_request_service(
        move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(15)))
                .unwrap();
            stream
        },
        b"PUT /half".len(),
    );
    let req = relay_request(ChannelMode::Tcp { port });
    let mut driver = Driver::spawn(&shim, &req, &[]).input(&[b"PUT /half"], false);
    driver.run_until(Duration::from_secs(10), |_| seen.try_recv().is_ok());
    // A raw stdin close: no `E` frame before it.
    driver.close_stdin = true;
    driver.run_until(Duration::from_secs(10), |d| {
        d.eof == [true, true] && d.status.is_some()
    });
    let (head, outcome, _stream) = service.join().unwrap();
    assert_eq!(head, b"PUT /half");
    assert_eq!(
        outcome.map_err(|e| e.kind()),
        Err(std::io::ErrorKind::ConnectionReset)
    );
    assert_eq!(driver.relay_end, Some(RelayEnd::Reset));
    assert_eq!(driver.status, Some(ChannelExitStatus::Code(1)));
}

#[test]
fn a_clean_tcp_relay_end_closes_the_service_orderly_with_every_byte() {
    // The service answers and shuts its write side first, and reads the
    // upload only after the relay ended cleanly: part of it then still waits
    // in the helper's socket send queue (more than the service's receive
    // window), so only an orderly close delivers every byte and the EOF; an
    // abortive close would drop that queue.
    use std::io::{Read, Write};
    let shim = Shim::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (go, wait) = std::sync::mpsc::channel::<()>();
    let service = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .unwrap();
        stream.write_all(b"send it").unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        wait.recv().unwrap();
        let mut all = Vec::new();
        stream
            .read_to_end(&mut all)
            .map(|_| all)
            .map_err(|e| e.kind())
    });
    let upload: Vec<u8> = (0..256 * 1024_u32).map(|i| (i % 253) as u8).collect();
    let req = relay_request(ChannelMode::Tcp { port });
    let out = Driver::spawn(&shim, &req, &[])
        .input(&[&upload], true)
        .finish(Duration::from_secs(20));
    assert_eq!(out.stdout, b"send it");
    assert_eq!(out.relay_end, Some(RelayEnd::Eof));
    assert_eq!(out.status, Some(ChannelExitStatus::Code(0)));
    go.send(()).unwrap();
    let received = service.join().unwrap();
    assert!(
        received.as_deref() == Ok(&upload[..]),
        "the clean end lost bytes or reset: {:?}",
        received.map(|r| r.len())
    );
}

#[test]
fn an_aborted_unix_relay_is_a_full_close_the_service_can_tell_from_a_half_close() {
    // No reset exists for a Unix socket: an abort is a full close, so after
    // the EOF the service's write fails (EPIPE), while a client half-close
    // (`a_unix_relay_reaches_the_socket_path`) still takes its reply.
    use std::io::Write;
    let shim = Shim::new();
    let path = shim.dir.join("abort.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let (seen, service) = partial_request_service(
        move || {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(15)))
                .unwrap();
            stream
        },
        b"half".len(),
    );
    let req = relay_request(ChannelMode::Unix {
        path: path.to_string_lossy().into_owned(),
    });
    let mut driver = Driver::spawn(&shim, &req, &[]).input(&[b"half"], false);
    driver.run_until(Duration::from_secs(10), |_| seen.try_recv().is_ok());
    let end = driver
        .spawned
        .custody
        .close(ChannelClose::Kill { forget: true });
    assert!(end.reaped);
    let (head, outcome, mut stream) = service.join().unwrap();
    assert_eq!(head, b"half");
    assert_eq!(outcome.map(|rest| rest.len()).ok(), Some(0));
    assert_eq!(
        stream.write_all(b"reply").map_err(|e| e.kind()),
        Err(std::io::ErrorKind::BrokenPipe)
    );
}
