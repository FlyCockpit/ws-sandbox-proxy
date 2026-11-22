//! C51 executable-shim tests for the Incus PTY child: a fake `incus` binary
//! in a private temp dir, never a live VM. `exec` becomes a Python stand-in
//! for the guest shell that reports its tty size, SIGWINCH, input and EOF.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sandbox_protocol::SandboxErrorCode;

use super::client::IncusClient;
use super::kvm::IncusKvmRuntime;
use crate::{
    GuestIdentity, OpenPtyRequest, PtyCloseIntent, PtyEvent, PtySession, PtySize, PtyTermination,
    SandboxRuntime,
};

const FP: &str = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const NAME: &str = "wssp-sbx-sbx-1";

/// PTY tests count this process's PTY descriptors; serialize them.
static PTY_TESTS: Mutex<()> = Mutex::new(());
static DIRS: AtomicU64 = AtomicU64::new(0);

const SHIM: &str = r#"#!/bin/sh
dir=$(dirname "$0")
{ printf '%s\037' "$0"; for a in "$@"; do printf '%s\037' "$a"; done; printf '\036'; } >> "$dir/argv.log"
project=""
while [ $# -gt 0 ]; do
  case "$1" in
    --project) project=$2; shift 2 ;;
    *) break ;;
  esac
done
cmd=$1
shift
case "$cmd" in
  query)
    name=wssp-sbx-sbx-1
    for a in "$@"; do path=$a; done
    case "$path" in
      "/1.0/instances/$name?project=default") ;;
      *) printf '{"type":"error","error":"Instance not found","error_code":404}\n'; exit 1 ;;
    esac
    if [ -f "$dir/deleted" ]; then
      printf '{"type":"error","error":"Instance not found","error_code":404}\n'; exit 1
    fi
    status=Running; code=103
    if [ -f "$dir/stopped" ]; then status=Stopped; code=102; fi
    printf '{"type":"sync","metadata":{"name":"%s","type":"virtual-machine","status":"%s","status_code":%s,"config":{"user.flycockpit.sandbox_id":"sbx-1","user.flycockpit.template_digest":"sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","volatile.base_image":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}}}\n' "$name" "$status" "$code"
    ;;
  exec)
    [ "$project" = default ] || { echo "Error: missing --project" >&2; exit 1; }
    env | LC_ALL=C sort > "$dir/exec.env"
    case "$(cat "$dir/mode")" in
      env-*) exec /usr/bin/python3 -I "$dir/nested.py" "$@" ;;
    esac
    # grandkid: a descendant in the child's process group that ignores
    # SIGHUP and holds the tty (C51-TB-1).
    case "$(cat "$dir/mode")" in
      grandkid*)
        ( trap '' HUP; exec sleep 60 ) &
        echo $! > "$dir/gk.pid"
        ;;
    esac
    exec python3 -I "$dir/child.py" "$(cat "$dir/mode")"
    ;;
  stop|delete)
    if [ -f "$dir/effectfail" ]; then echo "Error: refused" >&2; exit 1; fi
    if [ "$cmd" = stop ]; then : > "$dir/stopped"; else : > "$dir/deleted"; fi
    ;;
  *) echo "Error: unexpected $cmd" >&2; exit 1 ;;
esac
"#;

const CHILD: &str = r#"
import os, sys, signal, struct, fcntl, termios, time, tty
mode = sys.argv[1]
d = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(d, "child.pid.tmp"), "w") as f:
    f.write(str(os.getpid()))
os.rename(os.path.join(d, "child.pid.tmp"), os.path.join(d, "child.pid"))
def size():
    rows, cols, _, _ = struct.unpack("HHHH", fcntl.ioctl(0, termios.TIOCGWINSZ, b"\0" * 8))
    return rows, cols
def out(s):
    os.write(1, s.encode())
signal.signal(signal.SIGWINCH, lambda *_: out("WINCH %d %d\n" % size()))
def hup(*_):
    # Ignore the hangup, but record whether the VM effect had already run
    # when the terminal close reached us (C51-CC-1 ordering witness).
    done = any(os.path.exists(os.path.join(d, f)) for f in ("stopped", "deleted"))
    with open(os.path.join(d, "hup-%d" % os.getpid()), "w") as f:
        f.write("effect_done=%d" % done)
if mode == "hupignore":
    signal.signal(signal.SIGHUP, hup)
if mode in ("stall", "grandkid"):
    tty.setraw(0)
out("READY %d %d tty=%d sid=%d\n" % (size() + (int(os.isatty(0)), int(os.getsid(0) == os.getpid()))))
if mode in ("stall", "hupignore", "grandkid"):
    while True:
        time.sleep(1)
while True:
    data = os.read(0, 4096)
    if not data:
        out("EOF\n")
        sys.exit(7)
    for line in data.decode(errors="replace").splitlines():
        if line == "exit":
            out("BYE\n")
            sys.exit(3)
        out("IN:%s\n" % line)
"#;

struct Shim {
    dir: PathBuf,
    runtime: IncusKvmRuntime,
}

impl Drop for Shim {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

impl Shim {
    fn new(mode: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "wssp-pty-shim-{}-{}",
            std::process::id(),
            DIRS.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("incus");
        super::shim_tests::install_executable(&binary, SHIM, 0o755);
        fs::write(dir.join("child.py"), CHILD).unwrap();
        fs::write(dir.join("mode"), mode).unwrap();
        let client = IncusClient::new(binary.to_string_lossy().into_owned(), "default");
        // Static pin: the only binary these tests can run is the temp shim.
        assert!(Path::new(&client.binary).starts_with(std::env::temp_dir()));
        Self {
            dir,
            runtime: IncusKvmRuntime::from_test_client(client),
        }
    }

    /// Every recorded invocation as [program, args...].
    fn invocations(&self) -> Vec<Vec<String>> {
        fs::read_to_string(self.dir.join("argv.log"))
            .unwrap_or_default()
            .split('\u{1e}')
            .filter(|record| !record.is_empty())
            .map(|record| {
                record
                    .split('\u{1f}')
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .map(|mut argv| {
                argv.pop(); // trailing separator
                argv
            })
            .collect()
    }

    fn execs(&self) -> Vec<Vec<String>> {
        self.invocations()
            .into_iter()
            .filter(|argv| argv.get(3).map(String::as_str) == Some("exec"))
            .collect()
    }

    fn child_pid(&self) -> u32 {
        let path = self.dir.join("child.pid");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(text) = fs::read_to_string(&path) {
                return text.trim().parse().unwrap();
            }
            assert!(Instant::now() < deadline, "child never started");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn bound(&self) -> super::client::BoundInstance {
        self.runtime
            .client()
            .bind_instance(NAME, "sbx-1", FP, None)
            .unwrap()
    }
}

fn request(session_id: &str) -> OpenPtyRequest {
    OpenPtyRequest {
        template_fingerprint: FP.into(),
        sandbox_id: "sbx-1".into(),
        session_id: session_id.into(),
        guest: GuestIdentity::default(),
        size: PtySize::new(24, 80).unwrap(),
        max_duration: None,
        env: Vec::new(),
        cwd: None,
        setup_cancel: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    }
}

fn pty_fds() -> usize {
    fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| fs::read_link(entry.ok()?.path()).ok())
        .filter(|target| target == Path::new("/dev/ptmx") || target.starts_with("/dev/pts/"))
        .count()
}

/// Kernel truth for "reaped": a zombie still has a /proc entry.
fn process_gone(pid: u32) -> bool {
    !Path::new(&format!("/proc/{pid}")).exists()
}

fn assert_released(baseline: usize, pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while (pty_fds() != baseline || !process_gone(pid)) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        process_gone(pid),
        "child {pid} not reaped (zombie or alive)"
    );
    assert_eq!(pty_fds(), baseline, "leaked PTY descriptors");
}

/// Collect output until `needle` appears; returns the text and any `Ended`.
fn read_until(session: &mut PtySession, needle: &str) -> (String, Option<PtyTermination>) {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut text = String::new();
    while Instant::now() < deadline {
        match session.next_event(Duration::from_millis(50)).unwrap() {
            Some(PtyEvent::Output(bytes)) => {
                text.push_str(&String::from_utf8_lossy(&bytes));
                if text.contains(needle) {
                    return (text, None);
                }
            }
            Some(PtyEvent::Ended(done)) => return (text, Some(done)),
            None => {}
        }
    }
    panic!("timed out waiting for {needle:?}; got {text:?}");
}

fn wait_ended(session: &mut PtySession) -> PtyTermination {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Some(PtyEvent::Ended(done)) = session.next_event(Duration::from_millis(50)).unwrap()
        {
            return done;
        }
    }
    panic!("session never ended");
}

/// Serializes every test that opens a PTY in this process (here and in
/// `host_pty`): their descriptor baselines (`pty_fds`) count every PTY open.
pub(crate) fn lock() -> std::sync::MutexGuard<'static, ()> {
    PTY_TESTS.lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
fn c51_trace_is_exactly_incus_exec_t_for_the_resolved_sandbox_and_never_a_host_shell() {
    let _serial = lock();
    let mut shim = Shim::new("echo");
    let views = Arc::new(Mutex::new(Vec::<(String, Vec<String>, bool)>::new()));
    shim.runtime.client_mut().guest_spawn_hook =
        Some(super::client::TestGuestSpawnHook(Arc::new({
            let views = views.clone();
            move |command, inside| {
                for (key, value) in command.get_envs() {
                    assert!(
                        ["PATH", "HOME", "INCUS_DIR", "INCUS_SOCKET", "INCUS_CONF"]
                            .iter()
                            .any(|allowed| key == *allowed)
                    );
                    assert!(value.is_some());
                }
                views.lock().unwrap().push((
                    command.get_program().to_string_lossy().into_owned(),
                    command
                        .get_args()
                        .map(|a| a.to_string_lossy().into_owned())
                        .collect(),
                    inside,
                ));
            }
        })));
    let baseline = pty_fds();
    assert!(shim.runtime.pty_capability());
    let mut session = shim.runtime.open_pty(&request("term-1")).unwrap();
    let (mut text, ended) = read_until(&mut session, "sid=");
    assert!(ended.is_none(), "{text}");
    if !text.ends_with('\n') {
        text.push_str(&read_until(&mut session, "\n").0);
    }
    // The child really is on a PTY as its session leader (controlling tty).
    assert!(text.contains("READY 24 80 tty=1 sid=1"), "{text}");
    let pid = shim.child_pid();
    session.close(PtyCloseIntent::Client);
    assert_released(baseline, pid);

    let expected: Vec<String> = [
        "--project",
        "default",
        "exec",
        "--user",
        "1000",
        "--group",
        "1000",
        "--cwd",
        "/home/user",
        "--env",
        "HOME=/home/user",
        "--env",
        "SHELL=/bin/bash",
        "--env",
        "TERM=xterm-256color",
        "-t",
        NAME,
        "--",
        "/bin/bash",
    ]
    .map(String::from)
    .to_vec();
    let execs = shim.execs();
    assert_eq!(execs.len(), 1, "exactly one PTY child: {execs:?}");
    let exec = &execs[0];
    // argv[0] is the configured Incus client, never a host shell.
    assert_eq!(exec[0], shim.runtime.client().binary);
    assert_eq!(&exec[1..], expected.as_slice());
    assert_eq!(&exec[exec.len() - 4..], ["-t", NAME, "--", "/bin/bash"]);
    for host_shell in ["sh", "/bin/sh", "bash", "-c", "-lc", "-T"] {
        assert!(
            !exec[1..exec.len() - 1].iter().any(|a| a == host_shell),
            "host shell/flag `{host_shell}` before the guest shell: {exec:?}"
        );
    }
    // Every other invocation is a read-only metadata query.
    for argv in shim.invocations() {
        assert!(
            argv.get(1).map(String::as_str) == Some("query")
                || argv.get(3).map(String::as_str) == Some("exec"),
            "unexpected incus invocation {argv:?}"
        );
    }
    // The shared guest-spawn admission section saw the same argv, both
    // before and inside the policy-refusal critical section.
    let views = views.lock().unwrap();
    assert_eq!(views.len(), 2, "{views:?}");
    for (inside, (program, args, seen_inside)) in [false, true].iter().zip(views.iter()) {
        assert_eq!(program, &shim.runtime.client().binary);
        assert_eq!(args, &expected);
        assert_eq!(seen_inside, inside);
    }
    // The Incus client process gets a scrubbed environment.
    let env = fs::read_to_string(shim.dir.join("exec.env")).unwrap();
    for line in env.lines() {
        let key = line.split('=').next().unwrap();
        assert!(
            [
                "PATH",
                "HOME",
                "INCUS_DIR",
                "INCUS_SOCKET",
                "INCUS_CONF",
                "TERM",
                "SHELL",
                "PWD",
                "SHLVL",
                "_",
                "OLDPWD"
            ]
            .contains(&key),
            "host environment leaked to the incus client: {key}"
        );
    }
    assert!(env.lines().any(|l| l == "TERM=xterm-256color"), "{env}");
}

#[test]
fn c51_stdin_echo_output_streaming_and_eof_reap() {
    let _serial = lock();
    let shim = Shim::new("echo");
    let baseline = pty_fds();
    let mut session = shim.runtime.open_pty(&request("term-echo")).unwrap();
    read_until(&mut session, "READY");
    let pid = shim.child_pid();
    session.write_input(b"hello world\n").unwrap();
    let (text, ended) = read_until(&mut session, "IN:hello world");
    assert!(ended.is_none(), "{text}");
    session.write_input(b"second\n").unwrap();
    read_until(&mut session, "IN:second");
    // ^D at line start is EOF on the child's tty.
    session.write_input(b"\x04").unwrap();
    let (text, ended) = read_until(&mut session, "\u{0}never");
    assert!(text.contains("EOF"), "{text}");
    assert_eq!(
        ended,
        Some(PtyTermination::ChildExited { exit_code: Some(7) })
    );
    assert_released(baseline, pid);
    // Close after exit reports the exit, issues nothing, and stays stable.
    assert_eq!(
        session.close(PtyCloseIntent::Client),
        PtyTermination::ChildExited { exit_code: Some(7) }
    );
    assert_eq!(
        session.write_input(b"x").unwrap_err().code,
        SandboxErrorCode::StateConflict
    );
    // Oversized input is refused without reaching the queue.
    assert_eq!(
        session
            .write_input(&vec![b'a'; crate::PTY_INPUT_MAX_BYTES + 1])
            .unwrap_err()
            .code,
        SandboxErrorCode::RequestTooLarge
    );
}

#[test]
fn c51_resize_reaches_the_child_through_the_pty() {
    let _serial = lock();
    let shim = Shim::new("echo");
    let baseline = pty_fds();
    let mut session = shim.runtime.open_pty(&request("term-resize")).unwrap();
    read_until(&mut session, "READY 24 80");
    let pid = shim.child_pid();
    session.resize(PtySize::new(40, 132).unwrap()).unwrap();
    read_until(&mut session, "WINCH 40 132");
    assert_eq!(session.size(), PtySize::new(40, 132).unwrap());
    session.resize(PtySize::new(1, 1).unwrap()).unwrap();
    read_until(&mut session, "WINCH 1 1");
    session.close(PtyCloseIntent::Client);
    assert_released(baseline, pid);
    assert_eq!(
        session
            .resize(PtySize::new(24, 80).unwrap())
            .unwrap_err()
            .code,
        SandboxErrorCode::StateConflict
    );
}

#[test]
fn c51_natural_exit_reaps_and_close_is_distinguished_and_idempotent() {
    let _serial = lock();
    let shim = Shim::new("echo");
    let baseline = pty_fds();
    let mut session = shim.runtime.open_pty(&request("term-exit")).unwrap();
    read_until(&mut session, "READY");
    let pid = shim.child_pid();
    session.write_input(b"exit\n").unwrap();
    let (text, ended) = read_until(&mut session, "\u{0}never");
    assert!(text.contains("BYE"), "queued output precedes Ended: {text}");
    assert_eq!(
        ended,
        Some(PtyTermination::ChildExited { exit_code: Some(3) })
    );
    assert_released(baseline, pid);
    assert_eq!(session.termination(), ended);

    // A runtime close of a live child: Closed with the intent; repeats no-op.
    fs::remove_file(shim.dir.join("child.pid")).unwrap();
    let mut session = shim.runtime.open_pty(&request("term-exit-2")).unwrap();
    read_until(&mut session, "READY");
    let pid = shim.child_pid();
    let first = session.close(PtyCloseIntent::Client);
    assert!(
        matches!(
            first,
            PtyTermination::Closed {
                intent: PtyCloseIntent::Client,
                ..
            }
        ),
        "{first:?}"
    );
    assert_released(baseline, pid);
    for intent in [PtyCloseIntent::Shutdown, PtyCloseIntent::Expired] {
        assert_eq!(session.close(intent), first);
    }
    assert_eq!(
        shim.runtime
            .close_pty_sessions(None, PtyCloseIntent::Shutdown),
        0
    );
    assert_eq!(
        session.next_event(Duration::ZERO).unwrap(),
        Some(PtyEvent::Ended(first))
    );
}

#[test]
fn c51_expiry_closes_and_reaps_without_a_consumer() {
    let _serial = lock();
    let shim = Shim::new("echo");
    let baseline = pty_fds();
    let mut req = request("term-expiry");
    req.max_duration = Some(Duration::from_millis(400));
    let mut session = shim.runtime.open_pty(&req).unwrap();
    let pid = shim.child_pid();
    // Nobody reads: the supervisor alone must expire, terminate and reap.
    assert_released(baseline, pid);
    assert!(matches!(
        session.termination(),
        Some(PtyTermination::Closed {
            intent: PtyCloseIntent::Expired,
            ..
        })
    ));
    assert!(matches!(
        wait_ended(&mut session),
        PtyTermination::Closed {
            intent: PtyCloseIntent::Expired,
            ..
        }
    ));
}

#[test]
fn c51_destroy_and_stop_close_and_reap_every_sandbox_terminal() {
    let _serial = lock();
    for (effect, intent) in [
        ("delete", PtyCloseIntent::SandboxDestroyed),
        ("stop", PtyCloseIntent::SandboxStopped),
    ] {
        let shim = Shim::new("echo");
        let baseline = pty_fds();
        let mut a = shim.runtime.open_pty(&request("term-a")).unwrap();
        read_until(&mut a, "READY");
        let pid_a = shim.child_pid();
        fs::remove_file(shim.dir.join("child.pid")).unwrap();
        let mut b = shim.runtime.open_pty(&request("term-b")).unwrap();
        read_until(&mut b, "READY");
        let pid_b = shim.child_pid();
        let bound = shim.bound();
        // The VM effect is the choke point every stop/destroy path uses.
        let client = shim.runtime.client();
        let _ = match effect {
            "delete" => client.delete_force(&bound).map(|_| ()),
            _ => client.stop_force(&bound).map(|_| ()),
        };
        assert_released(baseline, pid_a);
        assert_released(baseline, pid_b);
        for session in [&mut a, &mut b] {
            assert!(
                matches!(wait_ended(session), PtyTermination::Closed { intent: got, reaped: true, .. } if got == intent),
                "{effect}"
            );
        }
        // The sandbox is gone/stopped: a new terminal is refused before spawn.
        let execs = shim.execs().len();
        assert!(shim.runtime.open_pty(&request("term-c")).is_err());
        assert_eq!(shim.execs().len(), execs, "no spawn after {effect}");
    }
}

#[test]
fn c51_close_escalates_past_an_ignored_hangup_and_reaps() {
    let _serial = lock();
    let shim = Shim::new("hupignore");
    let baseline = pty_fds();
    let mut session = shim.runtime.open_pty(&request("term-hup")).unwrap();
    read_until(&mut session, "READY");
    let pid = shim.child_pid();
    let done = session.close(PtyCloseIntent::Client);
    // Killed by SIGKILL after the SIGHUP grace: no exit code.
    assert_eq!(
        done,
        PtyTermination::Closed {
            intent: PtyCloseIntent::Client,
            exit_code: None,
            reaped: true,
        }
    );
    assert_released(baseline, pid);
}

#[test]
fn c51_close_unblocks_a_writer_stuck_on_a_stalled_child_and_leaks_nothing() {
    let _serial = lock();
    let shim = Shim::new("stall");
    let baseline = pty_fds();
    let mut session = shim.runtime.open_pty(&request("term-stall")).unwrap();
    read_until(&mut session, "READY");
    let pid = shim.child_pid();
    // Raw-mode child never reads: fill the tty input queue and then ours.
    let chunk = vec![b'x'; crate::PTY_INPUT_MAX_BYTES];
    let mut limited = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !limited && Instant::now() < deadline {
        match session.write_input(&chunk) {
            Ok(()) => std::thread::sleep(Duration::from_millis(5)),
            Err(err) => {
                assert_eq!(err.code, SandboxErrorCode::RateLimited);
                limited = true;
            }
        }
    }
    assert!(limited, "input queue must be bounded");
    let started = Instant::now();
    session.close(PtyCloseIntent::Client);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "close must not hang"
    );
    assert_released(baseline, pid);
}

#[test]
fn c51_injection_attempts_are_refused_before_any_incus_invocation() {
    let _serial = lock();
    let shim = Shim::new("echo");
    for sandbox_id in [
        "-sbx",
        "--project=evil",
        "sbx-1 --",
        "sbx-1;sh",
        "sbx-1\n",
        "../sbx-1",
        "sbx/1",
        "",
    ] {
        let mut req = request("term-inj");
        req.sandbox_id = sandbox_id.into();
        let err = shim.runtime.open_pty(&req).unwrap_err();
        assert_eq!(err.code, SandboxErrorCode::ProtocolError, "{sandbox_id:?}");
    }
    for session_id in ["-t", "--", "a b", "a\u{1f}b"] {
        let err = shim.runtime.open_pty(&request(session_id)).unwrap_err();
        assert_eq!(err.code, SandboxErrorCode::ProtocolError, "{session_id:?}");
    }
    for shell in ["-c", "bash", "/bin/../bin/sh", "/bin/sh\u{7}"] {
        let mut req = request("term-inj");
        req.guest.guest_shell = shell.into();
        assert!(shim.runtime.open_pty(&req).is_err(), "{shell:?}");
    }
    assert!(shim.invocations().is_empty(), "{:?}", shim.invocations());
    // A foreign template fingerprint never spawns.
    let mut req = request("term-inj");
    req.template_fingerprint = format!("sha256:{}", "0".repeat(64));
    assert_eq!(
        shim.runtime.open_pty(&req).unwrap_err().code,
        SandboxErrorCode::IdempotencyConflict
    );
    assert!(shim.execs().is_empty());
}

#[test]
fn c51_hostile_identity_values_stay_structurally_inert_argv_elements() {
    let _serial = lock();
    let shim = Shim::new("echo");
    let baseline = pty_fds();
    let mut req = request("term-inert");
    req.guest.guest_shell = "/bin/sh -c id;--project=evil".into();
    req.guest.guest_home = "/--project=evil".into();
    let mut session = shim.runtime.open_pty(&req).unwrap();
    read_until(&mut session, "READY");
    let pid = shim.child_pid();
    session.close(PtyCloseIntent::Client);
    assert_released(baseline, pid);
    let exec = shim.execs().pop().unwrap();
    assert_eq!(exec[1..3], ["--project", "default"]);
    assert_eq!(
        exec.iter().filter(|a| a.as_str() == "--project").count(),
        1,
        "{exec:?}"
    );
    let cwd = exec.iter().position(|a| a == "--cwd").unwrap();
    assert_eq!(exec[cwd + 1], "/--project=evil");
    assert_eq!(
        &exec[exec.len() - 4..],
        ["-t", NAME, "--", "/bin/sh -c id;--project=evil"]
    );
}

#[test]
fn c51_single_attachment_admission_fence_and_running_requirement() {
    let _serial = lock();
    let shim = Shim::new("echo");
    let baseline = pty_fds();
    let mut session = shim.runtime.open_pty(&request("term-one")).unwrap();
    read_until(&mut session, "READY");
    let pid = shim.child_pid();
    let err = shim.runtime.open_pty(&request("term-one")).unwrap_err();
    assert_eq!(err.code, SandboxErrorCode::StateConflict);
    assert_eq!(shim.execs().len(), 1, "second attach must not spawn");
    session.close(PtyCloseIntent::Client);
    assert_released(baseline, pid);
    // The same id may attach again once the first session ended.
    let mut again = shim.runtime.open_pty(&request("term-one")).unwrap();
    again.close(PtyCloseIntent::Client);

    // Policy-refusal fence in the shared spawn admission refuses the PTY.
    shim.runtime
        .client()
        .policy_refusals
        .lock()
        .unwrap()
        .insert("sbx-1".into());
    let execs = shim.execs().len();
    assert!(shim.runtime.open_pty(&request("term-fenced")).is_err());
    assert_eq!(shim.execs().len(), execs, "fenced open must not spawn");
    shim.runtime
        .client()
        .policy_refusals
        .lock()
        .unwrap()
        .clear();

    // A revoked runtime permit refuses before spawn.
    let permit = Arc::new(crate::RuntimePermit::default());
    permit.revoke();
    let scoped = shim.runtime.with_cancellation(permit);
    assert!(scoped.open_pty(&request("term-revoked")).is_err());
    assert_eq!(shim.execs().len(), execs);

    // A stopped VM refuses before spawn.
    fs::write(shim.dir.join("stopped"), b"").unwrap();
    assert_eq!(
        shim.runtime
            .open_pty(&request("term-stopped"))
            .unwrap_err()
            .code,
        SandboxErrorCode::SandboxNotRunning
    );
    assert_eq!(shim.execs().len(), execs);
    assert_eq!(pty_fds(), baseline);
}

fn hup_records(dir: &Path) -> Vec<String> {
    let mut records: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.ok()?;
            entry
                .file_name()
                .to_str()?
                .starts_with("hup-")
                .then(|| fs::read_to_string(entry.path()).unwrap_or_default())
        })
        .collect();
    records.sort();
    records
}

/// C51-CC-1: terminal close never precedes the VM stop/delete effect and so
/// never spends the caller's runtime-permit budget. With N hangup-ignoring
/// terminals and a small budget the VM is still stopped/deleted, every
/// terminal observes the hangup only AFTER the effect ran, and an open still
/// in flight is doomed by the post-effect close.
#[test]
fn c51_stop_and_delete_effects_run_before_any_terminal_close() {
    let _serial = lock();
    const SESSIONS: usize = 6;
    for (effect, marker, intent) in [
        ("stop", "stopped", PtyCloseIntent::SandboxStopped),
        ("delete", "deleted", PtyCloseIntent::SandboxDestroyed),
    ] {
        let shim = Shim::new("hupignore");
        let baseline = pty_fds();
        let mut sessions = Vec::new();
        let mut pids = Vec::new();
        for i in 0..SESSIONS {
            let _ = fs::remove_file(shim.dir.join("child.pid"));
            let mut session = shim.runtime.open_pty(&request(&format!("t{i}"))).unwrap();
            read_until(&mut session, "READY");
            pids.push(shim.child_pid());
            sessions.push(session);
        }
        // An open in flight across the effect (reserved, not yet started).
        let pending = shim
            .runtime
            .client()
            .pty_sessions
            .reserve("t-pending", "sbx-1")
            .unwrap();
        let bound = shim.bound();
        let mut client = shim.runtime.client().clone();
        // Lease expiry runs stop on a 5 s permit; a 1 s budget is far less
        // than SESSIONS serial hangup graces would cost.
        client.cancelled = Some(Arc::new(crate::RuntimePermit::with_timeout(
            Duration::from_secs(1),
        )));
        let started = Instant::now();
        let outcome = match effect {
            "stop" => client.stop_force(&bound).map(|_| ()),
            _ => client.delete_force(&bound).map(|_| ()),
        };
        let elapsed = started.elapsed();
        eprintln!("c51 {effect}: {SESSIONS} hup-ignoring terminals, effect+close took {elapsed:?}");
        assert!(outcome.is_ok(), "{effect} preempted: {:?}", outcome.err());
        assert!(shim.dir.join(marker).exists(), "VM {effect} never ran");
        // Every terminal saw its hangup only after the effect had run.
        let records = hup_records(&shim.dir);
        assert_eq!(
            records,
            vec!["effect_done=1".to_string(); SESSIONS],
            "{effect}: a terminal was closed before the VM effect"
        );
        for session in &mut sessions {
            assert_eq!(
                wait_ended(session),
                PtyTermination::Closed {
                    intent,
                    exit_code: None,
                    reaped: true,
                },
                "{effect}"
            );
        }
        for pid in pids {
            assert_released(baseline, pid);
        }
        // The post-effect close doomed the in-flight open.
        let size = PtySize::new(24, 80).unwrap();
        let (control, parts) =
            crate::fake::pty::fake_parts(NAME.into(), GuestIdentity::default(), size);
        let err = PtySession::start(pending, size, Duration::from_secs(60), parts).unwrap_err();
        assert_eq!(err.code, SandboxErrorCode::SandboxNotRunning, "{effect}");
        assert!(control.terminated() && control.reaped() && control.released());
    }
}

/// C51-CC-6: a stop/delete that FAILED still closes the sandbox's terminals
/// (conservatively), but never labels them stopped/destroyed.
#[test]
fn c51_failed_stop_or_delete_closes_with_an_unconfirmed_intent() {
    let _serial = lock();
    for effect in ["stop", "delete"] {
        let shim = Shim::new("echo");
        let baseline = pty_fds();
        let mut session = shim.runtime.open_pty(&request("term-f")).unwrap();
        read_until(&mut session, "READY");
        let pid = shim.child_pid();
        fs::write(shim.dir.join("effectfail"), b"").unwrap();
        let bound = shim.bound();
        let client = shim.runtime.client();
        let outcome = match effect {
            "stop" => client.stop_force(&bound).map(|_| ()),
            _ => client.delete_force(&bound).map(|_| ()),
        };
        assert!(outcome.is_err(), "{effect} must fail for this leg");
        assert_eq!(
            wait_ended(&mut session),
            PtyTermination::Closed {
                intent: PtyCloseIntent::LifecycleUnconfirmed,
                exit_code: None,
                reaped: true,
            },
            "{effect}"
        );
        assert_released(baseline, pid);
    }
}

/// Kills the grandchild whatever the test outcome.
struct KillOnDrop(u32);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &self.0.to_string()])
            .stderr(std::process::Stdio::null())
            .status();
    }
}

fn grandchild_pid(dir: &Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(pid) = fs::read_to_string(dir.join("gk.pid"))
            .ok()
            .and_then(|t| t.trim().parse().ok())
        {
            return pid;
        }
        assert!(Instant::now() < deadline, "grandchild never started");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_until(what: &str, cond: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// C51-TB-1: a descendant of the `incus exec` client that ignores SIGHUP and
/// holds the tty dies with the session, on a runtime close AND on a natural
/// exit: the whole process group is killed before the leader is reaped. No
/// pump thread or PTY descriptor outlives the session, and close is bounded
/// well below the pump-join bound.
#[test]
fn c51_session_end_kills_descendants_that_hold_the_tty() {
    let _serial = lock();
    // `grandkid`: raw-mode leader that never reads (closed by the runtime);
    // `grandkid-echo`: line-mode leader that exits on `exit`.
    for (ending, mode) in [("close", "grandkid"), ("exit", "grandkid-echo")] {
        let shim = Shim::new(mode);
        let baseline = pty_fds();
        let mut session = shim.runtime.open_pty(&request("term-gk")).unwrap();
        read_until(&mut session, "READY");
        let pid = shim.child_pid();
        let grandchild = grandchild_pid(&shim.dir);
        let _cleanup = KillOnDrop(grandchild);
        assert!(!process_gone(grandchild));
        let started = Instant::now();
        let termination = match ending {
            "close" => session.close(PtyCloseIntent::Client),
            _ => {
                session.write_input(b"exit\n").unwrap();
                wait_ended(&mut session)
            }
        };
        let elapsed = started.elapsed();
        match ending {
            "close" => {
                assert!(
                    matches!(
                        termination,
                        PtyTermination::Closed {
                            intent: PtyCloseIntent::Client,
                            reaped: true,
                            ..
                        }
                    ),
                    "{termination:?}"
                );
                // The pump join bound is 5 s; a blocked reader would hit it.
                assert!(elapsed < Duration::from_secs(4), "close took {elapsed:?}");
                assert!(session.pumps_released(), "pump outlived the close");
            }
            _ => {
                assert_eq!(
                    termination,
                    PtyTermination::ChildExited { exit_code: Some(3) }
                );
                wait_until("pump outlived the natural exit", || {
                    session.pumps_released()
                });
            }
        }
        wait_until(
            &format!("{ending}: grandchild {grandchild} survived"),
            || process_gone(grandchild),
        );
        assert_released(baseline, pid);
        drop(session);
    }
}

/// C55 kill scope (FS-PROBE-2): a terminal close kills the supervised shell's
/// whole group (including a HUP-ignoring grandchild) and nothing else: a
/// bystander in the daemon's own group and one in an unrelated group both
/// survive. The host group-kill guard then refuses `-0`, the daemon's pid and
/// the daemon's own group on the real `kill` path. The body runs in a
/// contained child (`run_contained`), so a guard regression kills only that
/// child's group and fails this test instead of killing the test runner.
/// (`-1` is checked by the pure `host_group_kill_arg` test only: a regression
/// there would signal every process this user owns, beyond any containment.)
#[test]
fn c55_close_kill_scope_is_the_shell_group_only() {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    let _serial = lock();
    let Some(dir) = super::shim_tests::contained_dir() else {
        let dir = std::env::temp_dir().join(format!(
            "wssp-kill-scope-{}-{}",
            std::process::id(),
            DIRS.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // The unrelated-group bystander outlives a failed child; kill it.
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                if let Some(pid) = fs::read_to_string(self.0.join("bystander.pid"))
                    .ok()
                    .and_then(|t| t.trim().parse::<u32>().ok())
                {
                    drop(KillOnDrop(pid));
                }
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        super::shim_tests::run_contained(
            "incus::pty_shim_tests::c55_close_kill_scope_is_the_shell_group_only",
            &dir,
        );
        return;
    };
    let me = std::process::id();
    let own = super::client::process_group_of("self").expect("own process group");
    assert_ne!(
        own, me,
        "precondition: the test child is not a group leader"
    );
    // Null stdio: a leaked bystander must not hold the parent's output pipes.
    let mut own_group_bystander = Command::new("sleep")
        .arg("60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut other_group_bystander = Command::new("sleep")
        .arg("60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
        .unwrap();
    fs::write(
        dir.join("bystander.pid"),
        other_group_bystander.id().to_string(),
    )
    .unwrap();
    let shim = Shim::new("grandkid");
    let mut session = shim.runtime.open_pty(&request("term-scope")).unwrap();
    read_until(&mut session, "READY");
    let pid = shim.child_pid();
    let grandchild = grandchild_pid(&shim.dir);
    let _gk_cleanup = KillOnDrop(grandchild);
    assert!(!process_gone(grandchild) && !process_gone(pid));
    let done = session.close(PtyCloseIntent::Client);
    assert!(
        matches!(done, PtyTermination::Closed { reaped: true, .. }),
        "{done:?}"
    );
    wait_until(
        "HUP-ignoring grandchild in the shell group survived close",
        || process_gone(grandchild),
    );
    assert!(process_gone(pid), "shell {pid} survived close");
    // The real kill path: none of these may signal anything.
    for target in [0, me, own] {
        super::client::kill_process_group(target);
        assert!(
            IncusClient::kill_process_group(target).is_err(),
            "group kill of {target} must be refused"
        );
    }
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        own_group_bystander.try_wait().unwrap().is_none(),
        "own-group bystander killed"
    );
    assert!(
        other_group_bystander.try_wait().unwrap().is_none(),
        "unrelated-group bystander killed"
    );
    for bystander in [&mut own_group_bystander, &mut other_group_bystander] {
        let _ = bystander.kill();
        let _ = bystander.wait();
    }
    fs::remove_file(dir.join("bystander.pid")).unwrap();
}

pub(super) fn scrub_environment_pty_cases() {
    c51_trace_is_exactly_incus_exec_t_for_the_resolved_sandbox_and_never_a_host_shell();
    c51_close_escalates_past_an_ignored_hangup_and_reaps();
}

// A real nested PTY: the outer client starts cooked+echo, switches to raw as
// Incus does, and bridges a second initially cooked+echo tty running the ACTUAL
// isolated helper. Only the modeled guest target receives workload values.
const NESTED_ENV_SHIM: &str = r#"
import os, sys, tty, termios, pty, subprocess, select, signal, time, pathlib, fcntl, struct
root = pathlib.Path(__file__).parent
args = sys.argv[1:]
if '-t' not in args:
    marker = args[-1]
    print('WSSP_ENV_TOOLS '+marker+'\n/usr/bin/python3\n/usr/bin/setsid')
    sys.exit(0)
mode = (root/'mode').read_text()
program = args[args.index('--')+1:]
nonce = program[5]
(root/'child.pid').write_text(str(os.getpid()))
(root/'starting').touch()
# Both layers start cooked+echo. The host must VERIFY the outer switch at READY.
outer = termios.tcgetattr(0)
assert outer[3] & termios.ECHO and outer[3] & termios.ICANON
if mode != 'env-outer-cooked':
    tty.setraw(0, termios.TCSANOW)
master, slave = pty.openpty()
m = termios.tcgetattr(slave)
m[0] |= termios.ICRNL | termios.IXON
m[1] |= termios.OPOST | termios.ONLCR
m[3] |= termios.ECHO | termios.ICANON | termios.ISIG
termios.tcsetattr(slave, termios.TCSANOW, m)
# A test-only gate is a blocking IO barrier, not a sleep-based deadline proof.
if mode == 'env-delayed':
    while not (root/'release').exists():
        select.select([], [], [], .005)
if mode == 'env-eof':
    os._exit(1)
if mode == 'env-silent':
    select.select([], [], [], 60)
if mode == 'env-overflow':
    os.write(1, b'x'*8193)
    select.select([], [], [], 60)
if mode == 'env-wrong-nonce':
    os.write(1, b'\x1eWSSP_ENV_READY wrong\x1f')
    select.select([], [], [], 60)
if mode == 'env-forged-done':
    os.write(1, ('\x1eWSSP_ENV_READY '+nonce+'\x1f\x1eWSSP_ENV_DONE '+nonce+'\x1f').encode())
    select.select([], [], [], 60)
if mode == 'env-wrong-order':
    os.write(1, ('\x1eWSSP_ENV_DONE '+nonce+'\x1f').encode())
    select.select([], [], [], 60)
if mode == 'env-never-reads':
    tty.setraw(slave, termios.TCSANOW)
    os.write(slave, ('\x1eWSSP_ENV_READY '+nonce+'\x1f').encode())
    data = os.read(master, 4096)
    os.write(1, data)
    (root/'ready.observed').touch()
    # Real raw outer tty input queue fills: hangup alone cannot unblock write.
    select.select([], [], [], 60)
if mode == 'env-no-done':
    tty.setraw(slave, termios.TCSANOW)
    os.write(slave, ('\x1eWSSP_ENV_READY '+nonce+'\x1f').encode())
    os.write(1, os.read(master, 4096))
    (root/'ready.observed').touch()
    while True:
        os.read(0, 4096)
guest_env = {'PATH':'/usr/bin:/bin','HOME':'/home/wssp','SHELL':program[-1],'TERM':'xterm-256color'}
child = subprocess.Popen(program, stdin=slave, stdout=slave, stderr=slave, env=guest_env, close_fds=True)
(root/'guest.pid').write_text(str(child.pid))
os.close(slave)
def cleanup(*_):
    child.kill()
    child.wait()
    os._exit(0)
signal.signal(signal.SIGHUP, cleanup)
def resize(*_):
    size = fcntl.ioctl(0, termios.TIOCGWINSZ, b'\0'*8)
    fcntl.ioctl(master, termios.TIOCSWINSZ, size)
    os.kill(child.pid, signal.SIGWINCH)
signal.signal(signal.SIGWINCH, resize)
resize()
ready = False
observed = b''
while True:
    inputs, _, _ = select.select([0,master], [], [], 5)
    for fd in inputs:
        try:
            data = os.read(fd, 4096)
        except OSError:
            cleanup()
        if not data:
            cleanup()
        if fd == 0:
            if not ready:
                (root/'early-input').touch()
            if mode == 'env-corrupt-frame':
                data = b'00000004:!!!!'
            if mode == 'env-truncated-frame':
                data = b'00000008:AAAA'
            os.write(master, data)
        else:
            observed += data
            # Every marker byte is a separate bridge write; the parser also
            # has a one-byte-chunk unit test, independent of kernel coalescing.
            for byte in data:
                os.write(1, bytes([byte]))
            (root/'guest.output').open('ab').write(data)
            if ('\x1eWSSP_ENV_READY '+nonce+'\x1f').encode() in observed:
                ready = True
                (root/'ready.observed').touch()
"#;

const ENV_TARGET: &str = r#"#!/usr/bin/python3 -I
import os, sys, pathlib, json, termios, signal, fcntl, struct
root = pathlib.Path(__file__).parent
mode = termios.tcgetattr(0)
(root/'target.json').write_text(json.dumps({'env':dict(os.environ),'echo':bool(mode[3]&termios.ECHO),'canonical':bool(mode[3]&termios.ICANON),'signals':bool(mode[3]&termios.ISIG)}))
def resized(*_):
    rows, cols, _, _ = struct.unpack('HHHH',fcntl.ioctl(0,termios.TIOCGWINSZ,b'\0'*8))
    os.write(1, ('RESIZED %d %d\n'%(rows,cols)).encode())
signal.signal(signal.SIGWINCH,resized)
os.write(1,b'SHELL_READY\n')
while True:
    line = os.read(0,4096)
    if not line: break
    os.write(1,b'INPUT='+line)
"#;

fn env_shim(mode: &str) -> (Shim, OpenPtyRequest) {
    let shim = Shim::new(mode);
    fs::write(shim.dir.join("nested.py"), NESTED_ENV_SHIM).unwrap();
    super::shim_tests::install_executable(&shim.dir.join("target-shell"), ENV_TARGET, 0o755);
    let mut req = request("env-pty");
    req.guest.guest_shell = shim.dir.join("target-shell").to_string_lossy().into_owned();
    req.env = vec![("APP".into(), "synthetic-pty-private\n\r\u{3}é".into())];
    (shim, req)
}
/// Overall setup deadline for the tests whose guest must start (and, for
/// `env-no-done`, print READY) before that deadline fires. The deadline runs
/// from before the tool probe, so it also pays for two shim `incus exec`
/// spawns and two Python interpreter starts. A whole successful open took
/// 0.47-0.80 s at load ~23 here; the former 400 / 450 ms deadlines fired
/// before the guest even started (6/6 under load). 4 s leaves 5x headroom
/// over that worst case while keeping the cut far below production's 30 s.
const SHIM_SETUP_OVERALL: Duration = Duration::from_secs(4);
fn shortened(overall: Duration, handshake: Duration) {
    super::pty::env::TEST_LIMITS
        .with(|limits| limits.set(super::pty::env::Limits { overall, handshake }));
}
/// Production setup limits, for an open that must simply succeed: a
/// shortened limit there only measures how fast the shim's processes start
/// on a busy host (a 3 s / 1 s replacement open failed under load), not
/// anything the test asserts.
fn production_limits() {
    shortened(super::pty::env::OVERALL, super::pty::env::HANDSHAKE);
}
fn wait_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "barrier did not arrive: {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}
fn observe_setup() -> Arc<super::pty::env::Observation> {
    let observation = Arc::new(super::pty::env::Observation::default());
    super::pty::env::TEST_OBSERVATION.with(|value| *value.borrow_mut() = Some(observation.clone()));
    observation
}
fn output_until(session: &mut PtySession, needle: &str) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut output = Vec::new();
    while !String::from_utf8_lossy(&output).contains(needle) {
        assert!(Instant::now() < deadline, "missing output {needle}");
        if let Some(PtyEvent::Output(bytes)) =
            session.next_event(Duration::from_millis(50)).unwrap()
        {
            output.extend(bytes);
        }
    }
    output
}

#[test]
fn pty_env_handshake_never_echoes_frame() {
    let _serial = PTY_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    let (shim, req) = env_shim("env-normal");
    production_limits();
    assert!(!format!("{req:?}").contains("synthetic-pty-private"));
    let mut session = shim.runtime.open_pty(&req).unwrap();
    let mut output = output_until(&mut session, "SHELL_READY");
    assert!(!shim.dir.join("early-input").exists());
    let target: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(shim.dir.join("target.json")).unwrap()).unwrap();
    assert_eq!(target["env"]["APP"], req.env[0].1);
    assert_eq!(target["env"]["TERM"], "xterm-256color");
    for key in ["echo", "canonical", "signals"] {
        assert_eq!(
            target[key], true,
            "guest mode must be restored with TCSANOW"
        );
    }
    let pid = shim.child_pid();
    assert!(
        !fs::read(format!("/proc/{pid}/environ"))
            .unwrap()
            .windows(b"synthetic-pty-private".len())
            .any(|s| s == b"synthetic-pty-private")
    );
    session.write_input(b"hello\n").unwrap();
    output.extend(output_until(&mut session, "INPUT=hello"));
    session.resize(PtySize::new(40, 100).unwrap()).unwrap();
    output.extend(output_until(&mut session, "RESIZED 40 100"));
    let frame = super::env_frame::encode(&req.env).unwrap().unwrap();
    let envelope = super::pty::env::envelope(&frame).unwrap();
    for bytes in [
        &output,
        &fs::read(shim.dir.join("guest.output")).unwrap(),
        &fs::read(shim.dir.join("argv.log")).unwrap(),
        &fs::read(shim.dir.join("exec.env")).unwrap(),
    ] {
        assert!(
            !bytes
                .windows(b"synthetic-pty-private".len())
                .any(|b| b == b"synthetic-pty-private")
        );
        assert!(!bytes.windows(envelope.len()).any(|b| b == envelope));
        assert!(
            !bytes
                .windows(envelope.len() - 9)
                .any(|b| b == &envelope[9..])
        );
    }
    assert!(!String::from_utf8_lossy(&output).contains("WSSP_ENV_"));
    assert!(matches!(
        session.close(PtyCloseIntent::Client),
        PtyTermination::Closed { reaped: true, .. }
    ));
    assert!(session.pumps_released());
    assert!(process_gone(pid));
}

#[test]
fn pty_env_handshake_guest_silent() {
    let _serial = PTY_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    let (shim, req) = env_shim("env-silent");
    shortened(SHIM_SETUP_OVERALL, Duration::from_millis(200));
    let observation = observe_setup();
    let start = Instant::now();
    let failure = shim.runtime.open_pty(&req).unwrap_err();
    assert_eq!(failure.message, "terminal setup failed");
    assert!(failure.cleanup.is_none());
    // Premise: the guest started and then stayed silent; the deadline did
    // not merely cut the shim's startup.
    assert!(
        shim.dir.join("starting").exists(),
        "the guest started before the overall deadline ({SHIM_SETUP_OVERALL:?})"
    );
    assert!(start.elapsed() >= SHIM_SETUP_OVERALL - Duration::from_millis(50));
    assert!(start.elapsed() < SHIM_SETUP_OVERALL + Duration::from_millis(2600));
    assert!(process_gone(shim.child_pid()));
    assert!(observation.deadline_fired.load(Ordering::Acquire));
    assert!(observation.ready.lock().unwrap().is_none());
    assert!(
        observation
            .closed
            .lock()
            .unwrap()
            .unwrap()
            .duration_since(start)
            < SHIM_SETUP_OVERALL + Duration::from_millis(800)
    );
    assert!(observation.workers_finished.load(Ordering::Acquire));
}

#[test]
fn pty_env_handshake_guest_never_reads() {
    let _serial = PTY_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    let (shim, mut req) = env_shim("env-never-reads");
    req.env = (0..4)
        .map(|i| (format!("K{i}"), "x".repeat(4000)))
        .collect();
    shortened(Duration::from_secs(3), Duration::from_millis(300));
    let observation = observe_setup();
    let start = Instant::now();
    let failure = shim.runtime.open_pty(&req).unwrap_err();
    assert!(shim.dir.join("ready.observed").exists());
    assert_eq!(failure.message, "terminal setup failed");
    assert!(failure.cleanup.is_none());
    assert!(start.elapsed() >= Duration::from_millis(280));
    assert!(start.elapsed() < Duration::from_secs(3));
    assert!(process_gone(shim.child_pid()));
    assert!(observation.deadline_fired.load(Ordering::Acquire));
    assert!(observation.writer_blocked_at_close.load(Ordering::Acquire));
    assert!(observation.workers_finished.load(Ordering::Acquire));
    let ready = observation.ready.lock().unwrap().unwrap();
    let closed = observation.closed.lock().unwrap().unwrap();
    assert!(closed.duration_since(ready) >= Duration::from_millis(300));
    assert!(closed.duration_since(ready) < Duration::from_millis(900));
}

#[test]
fn pty_env_handshake_startup_does_not_spend_ready_budget() {
    let _serial = PTY_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    let (shim, req) = env_shim("env-delayed");
    let runtime = shim.runtime.clone();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    // The gated startup is held for twice the handshake budget before it is
    // released: a setup that charged startup to the READY budget would fail.
    // The budget itself (1.5 s) only has to cover the real READY-to-DONE
    // exchange, which a 250 ms budget lost to process start-up under load.
    let handshake = Duration::from_millis(1500);
    let open = std::thread::spawn(move || {
        shortened(super::pty::env::OVERALL, handshake);
        tx.send(runtime.open_pty(&req)).unwrap();
    });
    wait_file(&shim.dir.join("starting"));
    assert!(matches!(
        rx.recv_timeout(handshake * 2),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));
    fs::write(shim.dir.join("release"), "").unwrap();
    let mut session = rx.recv_timeout(super::pty::env::OVERALL).unwrap().unwrap();
    output_until(&mut session, "SHELL_READY");
    session.close(PtyCloseIntent::Client);
    open.join().unwrap();
}

#[test]
fn pty_env_handshake_refuses_outer_echo_wrong_markers_and_capture_overflow() {
    let _serial = PTY_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    for mode in [
        "env-outer-cooked",
        "env-eof",
        "env-corrupt-frame",
        "env-truncated-frame",
        "env-overflow",
        "env-wrong-nonce",
        "env-wrong-order",
        "env-forged-done",
        "env-no-done",
    ] {
        let (shim, req) = env_shim(mode);
        shortened(Duration::from_secs(3), Duration::from_millis(300));
        let observation = observe_setup();
        let failure = shim.runtime.open_pty(&req).unwrap_err();
        assert_eq!(failure.message, "terminal setup failed");
        assert!(failure.cleanup.is_none(), "{mode}");
        if [
            "env-outer-cooked",
            "env-wrong-nonce",
            "env-wrong-order",
            "env-overflow",
        ]
        .contains(&mode)
        {
            assert!(
                !observation.deadline_fired.load(Ordering::Acquire),
                "refusal must precede the watchdog: {mode}"
            );
        }
        if mode == "env-outer-cooked" {
            assert!(!observation.writer_started.load(Ordering::Acquire));
        }
        assert!(!shim.dir.join("target.json").exists());
        assert!(process_gone(shim.child_pid()));
    }
}

#[test]
fn pty_env_handshake_takeover_cancels_opening_session() {
    let _serial = PTY_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    for mode in ["env-delayed", "env-never-reads"] {
        let (shim, mut req) = env_shim(mode);
        req.env = (0..4)
            .map(|i| (format!("K{i}"), "x".repeat(4000)))
            .collect();
        let cancel = req.setup_cancel.clone();
        let runtime = shim.runtime.clone();
        let worker = std::thread::spawn(move || {
            shortened(Duration::from_secs(4), Duration::from_secs(2));
            runtime.open_pty(&req)
        });
        wait_file(&shim.dir.join(if mode == "env-delayed" {
            "starting"
        } else {
            "ready.observed"
        }));
        cancel.store(true, Ordering::Release);
        // Unblock only the shim's startup gate. A late READY must not revive it.
        fs::write(shim.dir.join("release"), "").unwrap();
        let failure = worker.join().unwrap().unwrap_err();
        assert_eq!(failure.message, "terminal setup failed");
        assert!(failure.cleanup.is_none());
        assert!(process_gone(shim.child_pid()));
        fs::write(shim.dir.join("mode"), "env-normal").unwrap();
        let mut replacement = request("replacement");
        replacement.guest.guest_shell =
            shim.dir.join("target-shell").to_string_lossy().into_owned();
        replacement.env = vec![("APP".into(), "replacement".into())];
        production_limits();
        let mut session = shim.runtime.open_pty(&replacement).unwrap();
        output_until(&mut session, "SHELL_READY");
        session.close(PtyCloseIntent::Client);
    }
}

#[test]
fn pty_env_handshake_overall_deadline_still_caps_blocked_done_and_stop_revoke() {
    let _serial = PTY_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    let (shim, req) = env_shim("env-no-done");
    // READY arrives well inside the overall deadline, and READY plus the
    // handshake budget lies far beyond it: only the overall deadline can end
    // this setup.
    let handshake = Duration::from_secs(30);
    shortened(SHIM_SETUP_OVERALL, handshake);
    let observation = observe_setup();
    let start = Instant::now();
    let failure = shim.runtime.open_pty(&req).unwrap_err();
    assert_eq!(failure.message, "terminal setup failed");
    let ready = observation
        .ready
        .lock()
        .unwrap()
        .expect("READY arrived before the overall deadline");
    assert!(ready.duration_since(start) + handshake > SHIM_SETUP_OVERALL * 2);
    assert!(observation.deadline_fired.load(Ordering::Acquire));
    let closed = observation.closed.lock().unwrap().unwrap();
    assert!(
        closed.duration_since(start) < SHIM_SETUP_OVERALL + Duration::from_millis(800),
        "the overall deadline, not the handshake budget, closed setup: {:?}",
        closed.duration_since(start)
    );
    assert!(start.elapsed() < SHIM_SETUP_OVERALL + Duration::from_millis(2600));
    assert!(observation.workers_finished.load(Ordering::Acquire));
    for mode in ["env-silent", "env-never-reads"] {
        for revoke in [false, true] {
            let (shim, mut req) = env_shim(mode);
            req.env = (0..4)
                .map(|i| (format!("K{i}"), "x".repeat(4000)))
                .collect();
            let permit = Arc::new(crate::RuntimePermit::default());
            let runtime = shim.runtime.with_cancellation(permit.clone());
            let worker = std::thread::spawn(move || {
                shortened(Duration::from_secs(4), Duration::from_secs(2));
                runtime.open_pty(&req)
            });
            wait_file(&shim.dir.join(if mode == "env-silent" {
                "starting"
            } else {
                "ready.observed"
            }));
            if revoke {
                permit.revoke();
            } else {
                assert_eq!(
                    shim.runtime
                        .close_pty_sessions(Some("sbx-1"), PtyCloseIntent::SandboxStopped),
                    1
                );
            }
            let failure = worker.join().unwrap().unwrap_err();
            assert_eq!(failure.message, "terminal setup failed");
            assert!(failure.cleanup.is_none());
            assert!(process_gone(shim.child_pid()));
        }
    }
}

#[test]
fn pty_env_handshake_exec_failure_after_done_is_constant_and_suppresses_helper_output() {
    let _serial = PTY_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    let (shim, req) = env_shim("env-normal");
    super::shim_tests::install_executable(
        &shim.dir.join("target-shell"),
        "#!/missing/interpreter\n",
        0o755,
    );
    production_limits();
    let mut session = shim.runtime.open_pty(&req).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        assert!(Instant::now() < deadline);
        match session.next_event(Duration::from_millis(10)) {
            Err(error) => {
                assert_eq!(error.message, "terminal setup failed");
                break;
            }
            Ok(Some(PtyEvent::Output(bytes))) => {
                panic!("helper output leaked ({} bytes)", bytes.len())
            }
            Ok(Some(PtyEvent::Ended(_))) => panic!("exec refusal lost its typed setup error"),
            Ok(None) => {}
        }
    }
    session.close(PtyCloseIntent::Client);
    assert!(process_gone(shim.child_pid()));
}

#[test]
fn pty_env_handshake_admission_close_does_not_cancel_already_admitted_setup() {
    let _serial = PTY_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    let (shim, req) = env_shim("env-delayed");
    let permit = Arc::new(crate::RuntimePermit::default());
    let runtime = shim.runtime.with_cancellation(permit.clone());
    let worker = std::thread::spawn(move || {
        production_limits();
        runtime.open_pty(&req)
    });
    wait_file(&shim.dir.join("starting"));
    permit.close();
    fs::write(shim.dir.join("release"), "").unwrap();
    let mut session = worker.join().unwrap().unwrap();
    output_until(&mut session, "SHELL_READY");
    session.close(PtyCloseIntent::Client);
}

#[test]
fn pty_env_handshake_maximal_contract_frame_reaches_only_target_environment() {
    let _serial = PTY_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    let (shim, mut req) = env_shim("env-normal");
    req.env = (0..4)
        .map(|i| {
            (
                format!("K{i}"),
                "x".repeat(if i == 3 { 4063 } else { 4096 }),
            )
        })
        .collect();
    assert_eq!(
        sandbox_protocol::canonical_env_json(&req.env)
            .unwrap()
            .len(),
        16384
    );
    let frame = super::env_frame::encode(&req.env).unwrap().unwrap();
    assert_eq!(super::pty::env::envelope(&frame).unwrap().len(), 21873);
    production_limits();
    let mut session = shim.runtime.open_pty(&req).unwrap();
    output_until(&mut session, "SHELL_READY");
    let target: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(shim.dir.join("target.json")).unwrap()).unwrap();
    for (key, value) in &req.env {
        assert_eq!(target["env"][key], *value);
    }
    session.close(PtyCloseIntent::Client);
}
