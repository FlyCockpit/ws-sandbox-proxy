//! 4b, approved Branch A: the real group-pidfd helper and the exact
//! `/bin/sh` + `setsid` wrapper, run locally in temp dirs (no VM).
use super::effect_completion::pidfd_signal_outcome;
use super::exec::{set_test_guest_ops_dir, wrap_user_command};
use super::frames::parse_supervised_frames;
use crate::IncusCommandOutput;
use sandbox_protocol::SandboxErrorCode;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const HELPER: &str = include_str!("signal-helper.py");

/// Optional fault harness: patch the helper's runtime before executing it.
fn run_helper(prelude: &str, args: &[&str]) -> (String, String) {
    let harness = format!(
        "import builtins, os, signal, sys\nEVENTS = []\n{prelude}\nsys.argv = ['-c'] + sys.argv[1:]\nsrc = sys.stdin.read()\ntry:\n    exec(compile(src, 'signal-helper', 'exec'), {{'__name__': '__main__'}})\nexcept SystemExit:\n    pass\nprint('\\n'.join(EVENTS))\n"
    );
    let mut child = Command::new("python3")
        .args(["-I", "-c", &harness])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("python3");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(HELPER.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        String::from_utf8(out.stderr).unwrap(),
        String::from_utf8(out.stdout).unwrap(),
    )
}

struct Leader {
    child: Child,
    pid: u32,
    nonce: String,
    _ops: super::exec::test_guest_ops::Override,
    dir: std::path::PathBuf,
}

impl Drop for Leader {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-KILL", "--", &format!("-{}", self.pid)])
            .stderr(Stdio::null())
            .status();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Spawn the EXACT production wrapper; return once its start record exists.
fn spawn_wrapper(user: &str) -> (Leader, super::frames::StartReady) {
    let dir = std::env::temp_dir().join(format!(
        "wssp-sig-{}-{}",
        std::process::id(),
        super::client::random_nonce().unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let ops = set_test_guest_ops_dir(Some(dir.clone()));
    let (wrapped, nonce) = wrap_user_command(
        "op-sig",
        &["/bin/sh".into(), "-c".into(), user.into()],
        &Default::default(),
    )
    .unwrap();
    let mut child = Command::new(&wrapped[0])
        .args(&wrapped[1..])
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let mut head = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    let ready = loop {
        let mut byte = [0u8; 1];
        if stderr.read(&mut byte).unwrap() == 0 {
            panic!("wrapper ended before READY: {head:?}");
        }
        head.push(byte[0]);
        if let Some(ready) = parse_supervised_frames(b"", &head, &nonce).ready {
            break ready;
        }
        assert!(Instant::now() < deadline);
    };
    // Keep draining stderr so the wrapper can never block on it.
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut stderr, &mut std::io::sink());
    });
    let pid = ready.pid;
    (
        Leader {
            child,
            pid,
            nonce,
            _ops: ops,
            dir,
        },
        ready,
    )
}

fn uid() -> String {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|ids| ids.split_whitespace().next().map(str::to_string))
        .unwrap()
}

fn helper_args<'a>(
    leader: &'a Leader,
    ready: &'a super::frames::StartReady,
    ticks: &'a str,
    uid: &'a str,
    name: &'a str,
) -> Vec<String> {
    [
        "wssp-signal",
        "host-nonce",
        &ready.pid.to_string(),
        &ready.boot_id,
        ticks,
        uid,
        &leader.nonce,
        name,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn args_ref(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

fn wait_exit(child: &mut Child, limit: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    None
}

/// The plan's required local regression: a flags=0 TERM to the wrapper leader
/// reaches only its no-op trap (never the user command), while the verified
/// group delivery reaches the actual user child and descendants, preserves
/// open stdin up to delivery and keeps the command's real exit status.
#[test]
fn leader_only_send_is_a_no_op_and_group_delivery_reaches_the_user_command() {
    let user = "trap 'echo term-child; exit 143' TERM; (trap 'exit 129' TERM; sleep 60) & read line; echo got:$line; wait";
    let (mut leader, ready) = spawn_wrapper(user);
    for signal in ["TERM", "INT", "HUP"] {
        // Leader-only (flags=0) delivery: the wrapper traps it with `:`.
        let status = Command::new("kill")
            .args(["-s", signal, &leader.pid.to_string()])
            .status()
            .unwrap();
        assert!(status.success());
    }
    assert!(
        wait_exit(&mut leader.child, Duration::from_millis(300)).is_none(),
        "a wrapper-only signal must never be reported or act as user delivery"
    );
    let mut stdin = leader.child.stdin.take().unwrap();
    stdin.write_all(b"still-open\n").unwrap();
    let uid = uid();
    let ticks = ready.start_ticks.to_string();
    let args = helper_args(&leader, &ready, &ticks, &uid, "TERM");
    let (stderr, _) = run_helper("", &args_ref(&args));
    assert_eq!(
        stderr,
        "WSSP_SIGNAL host-nonce verified\nWSSP_SIGNAL host-nonce delivered\n"
    );
    let status = wait_exit(&mut leader.child, Duration::from_secs(5)).expect("exited");
    let mut stdout = String::new();
    leader
        .child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    assert!(stdout.contains("got:still-open"), "{stdout}");
    assert!(stdout.contains("term-child"), "{stdout}");
    assert_eq!(status.code(), Some(143), "real user exit status survives");
    let verdict = pidfd_signal_outcome(
        "host-nonce",
        &IncusCommandOutput {
            stdout: String::new(),
            stderr,
            exit_code: 0,
        },
    );
    assert!(verdict.is_ok());
}

#[test]
fn every_identity_mismatch_refuses_before_any_nonzero_signal() {
    let (mut leader, ready) = spawn_wrapper("sleep 30");
    let uid = uid();
    let good_ticks = ready.start_ticks.to_string();
    let wrong_ticks = (ready.start_ticks + 1).to_string();
    let wrong_uid = (uid.parse::<u32>().unwrap() + 1).to_string();
    let record_sends = "real = signal.pidfd_send_signal\ndef spy(fd, sig, *rest):\n    EVENTS.append('send %d' % sig)\n    return real(fd, sig, *rest)\nsignal.pidfd_send_signal = spy";
    for (ticks, uid, nonce_ok) in [
        (wrong_ticks.as_str(), uid.as_str(), true),
        (good_ticks.as_str(), wrong_uid.as_str(), true),
        (good_ticks.as_str(), uid.as_str(), false),
    ] {
        let mut args = helper_args(&leader, &ready, ticks, uid, "TERM");
        if !nonce_ok {
            args[6] = "forged-command-nonce".into();
        }
        let (stderr, events) = run_helper(record_sends, &args_ref(&args));
        assert_eq!(stderr, "WSSP_SIGNAL host-nonce mismatch\n", "{args:?}");
        assert!(
            !events
                .lines()
                .any(|e| e.starts_with("send ") && e != "send 0"),
            "nonzero signal before verification: {events}"
        );
    }
    let mut args = helper_args(&leader, &ready, &good_ticks, &uid, "TERM");
    args[3] = "00000000-0000-4000-8000-000000000000".into();
    let (stderr, _) = run_helper("", &args_ref(&args));
    assert_eq!(
        stderr, "WSSP_SIGNAL host-nonce mismatch\n",
        "reboot / foreign boot"
    );
    assert!(wait_exit(&mut leader.child, Duration::from_millis(100)).is_none());
    // A PID that is no longer alive is gone, never "delivered".
    drop(leader);
    let (stderr, _) = run_helper("", &args_ref(&args));
    assert!(
        stderr == "WSSP_SIGNAL host-nonce gone\n" || stderr == "WSSP_SIGNAL host-nonce mismatch\n",
        "{stderr}"
    );
}

/// Mutate one /proc field at a time, preserving ticks/UID/nonce/boot.
/// The nonzero syscall is intercepted so an inverse fault cannot signal.
#[test]
fn pgid_and_session_leadership_each_refuse_before_delivery() {
    let (leader, ready) = spawn_wrapper("sleep 30");
    let uid = uid();
    let ticks = ready.start_ticks.to_string();
    let args = helper_args(&leader, &ready, &ticks, &uid, "TERM");
    for field in [2, 3] {
        let prelude = format!(
            r#"
import io
real_open = builtins.open
def forged(path, *args, **kwargs):
    handle = real_open(path, *args, **kwargs)
    if str(path) == '/proc/{pid}/stat':
        raw = handle.read()
        handle.close()
        cut = raw.rindex(b') ') + 2
        fields = raw[cut:].split()
        fields[{field}] = b'1'
        return io.BytesIO(raw[:cut] + b' '.join(fields))
    return handle
builtins.open = forged
def spy(fd, sig, *rest):
    EVENTS.append('send %d' % sig)
signal.pidfd_send_signal = spy
"#,
            pid = ready.pid
        );
        let (stderr, events) = run_helper(&prelude, &args_ref(&args));
        assert_eq!(
            stderr, "WSSP_SIGNAL host-nonce mismatch\n",
            "stat field {field}"
        );
        assert!(events.lines().all(|e| e == "send 0"), "{events}");
    }
}

#[test]
fn death_after_proc_verification_reports_gone_before_verified_or_delivery() {
    let (leader, ready) = spawn_wrapper("sleep 30");
    let uid = uid();
    let ticks = ready.start_ticks.to_string();
    let args = helper_args(&leader, &ready, &ticks, &uid, "HUP");
    let prelude = r#"
def spy(fd, sig, info=None, flags=0):
    EVENTS.append('send %d %d' % (sig, flags))
    if sig == 0 and flags == 0:
        raise ProcessLookupError()
signal.pidfd_send_signal = spy
"#;
    let (stderr, events) = run_helper(prelude, &args_ref(&args));
    assert_eq!(stderr, "WSSP_SIGNAL host-nonce gone\n");
    assert_eq!(events, "send 0 4\nsend 0 0\n");
}

/// 24.04 GA (6.8) or a Python without pidfd: typed pre-effect refusal; no
/// nonzero signal and no flags=0 fallback is ever attempted.
#[test]
fn kernels_or_pythons_without_group_pidfd_refuse_with_no_fallback() {
    let (mut leader, ready) = spawn_wrapper("sleep 30");
    let uid = uid();
    let ticks = ready.start_ticks.to_string();
    let args = helper_args(&leader, &ready, &ticks, &uid, "INT");
    let kernel_6_8 = "import errno\nreal = signal.pidfd_send_signal\ndef old(fd, sig, info=None, flags=0):\n    EVENTS.append('send %d %d' % (sig, flags))\n    if flags:\n        raise OSError(errno.EINVAL, 'flags')\n    return real(fd, sig)\nsignal.pidfd_send_signal = old";
    for prelude in [
        kernel_6_8,
        "del os.pidfd_open",
        "del signal.pidfd_send_signal",
    ] {
        let (stderr, events) = run_helper(prelude, &args_ref(&args));
        assert_eq!(stderr, "WSSP_SIGNAL host-nonce unsupported\n", "{prelude}");
        assert!(
            events.lines().all(|e| e.is_empty() || e == "send 0 4"),
            "only the zero-signal self probe may run: {events}"
        );
        let verdict = pidfd_signal_outcome(
            "host-nonce",
            &IncusCommandOutput {
                stdout: String::new(),
                stderr,
                exit_code: 0,
            },
        )
        .map_err(crate::EffectError::from)
        .unwrap_err();
        assert_eq!(verdict.code, SandboxErrorCode::SignalUnsupportedOnGuest);
        assert!(matches!(verdict, crate::EffectError::Completed(_)));
    }
    assert!(wait_exit(&mut leader.child, Duration::from_millis(100)).is_none());
}

/// The support probe the host runs once a guest is ready is the delivery
/// path's own `group_signal_supported`: `group` where the kernel knows the
/// flag, `unsupported` on 6.8 or a Python without pidfd, and only a zero
/// signal is ever sent. The parser trusts only exact nonce-bound records.
#[test]
fn support_probe_reuses_the_delivery_probe_and_sends_no_signal() {
    use super::effect_completion::group_signal_probe_outcome;
    let out = |stderr: String, exit_code| IncusCommandOutput {
        stdout: String::new(),
        stderr,
        exit_code,
    };
    let record = |prelude: &str| {
        let watch = "real_send = signal.pidfd_send_signal\ndef watched(fd, sig, info=None, flags=0):\n    EVENTS.append('send %d %d' % (sig, flags))\n    return real_send(fd, sig, info, flags)\nsignal.pidfd_send_signal = watched";
        run_helper(
            &format!("{watch}\n{prelude}"),
            &["wssp-signal-probe", "probe-nonce"],
        )
    };
    // This host's kernel (>= 6.9 on CI and dev hosts) knows the group flag.
    let (stderr, events) = record("");
    assert_eq!(stderr, "WSSP_SIGNAL probe-nonce group\n");
    assert_eq!(events.trim(), "send 0 4", "only the zero-signal self probe");
    assert_eq!(
        group_signal_probe_outcome("probe-nonce", &out(stderr, 0)),
        Some(true)
    );
    let kernel_6_8 = "import errno\ninner = signal.pidfd_send_signal\ndef old(fd, sig, info=None, flags=0):\n    if flags:\n        EVENTS.append('send %d %d' % (sig, flags))\n        raise OSError(errno.EINVAL, 'flags')\n    return inner(fd, sig)\nsignal.pidfd_send_signal = old";
    for prelude in [
        kernel_6_8,
        "del os.pidfd_open",
        "del signal.pidfd_send_signal",
    ] {
        let (stderr, events) = record(prelude);
        assert_eq!(stderr, "WSSP_SIGNAL probe-nonce unsupported\n", "{prelude}");
        assert!(
            events.lines().all(|e| e.is_empty() || e == "send 0 4"),
            "only the zero-signal self probe may run: {events}"
        );
        assert_eq!(
            group_signal_probe_outcome("probe-nonce", &out(stderr, 0)),
            Some(false)
        );
    }
    // No interpreter: the launcher's exact record, as a signal call sees it.
    let missing = Command::new("/bin/sh")
        .args([
            "-c",
            super::exec::SIGNAL_HELPER_LAUNCH,
            "wssp-signal",
            HELPER,
            "wssp-signal-probe",
            "probe-nonce",
        ])
        .env_clear()
        .env("PATH", "/no-python-here")
        .output()
        .unwrap();
    assert_eq!(
        group_signal_probe_outcome(
            "probe-nonce",
            &out(String::from_utf8(missing.stderr).unwrap(), 127)
        ),
        Some(false)
    );
    for (stderr, exit_code) in [
        ("WSSP_SIGNAL other group\n", 0),
        ("WSSP_SIGNAL probe-nonce group", 0),
        ("WSSP_SIGNAL probe-nonce group\n", 1),
        ("WSSP_SIGNAL probe-nonce verified\n", 0),
        ("WSSP_SIGNAL probe-nonce interpreter_missing\n", 0),
        ("", 0),
    ] {
        assert_eq!(
            group_signal_probe_outcome("probe-nonce", &out(stderr.into(), exit_code)),
            None,
            "{stderr:?} {exit_code}"
        );
    }
}

/// Open-then-verify: the pidfd is opened before ANY /proc read of the target.
#[test]
fn the_leader_pidfd_is_opened_before_any_identity_read() {
    let (_leader, ready) = spawn_wrapper("sleep 30");
    let uid = uid();
    let ticks = ready.start_ticks.to_string();
    let args = helper_args(&_leader, &ready, &ticks, &uid, "HUP");
    let order = format!(
        "real_open = builtins.open\nreal_pidfd = os.pidfd_open\nreal_stat = os.stat\ndef o(path, *a, **k):\n    if str(path).startswith('/proc/{pid}'):\n        EVENTS.append('read')\n    return real_open(path, *a, **k)\ndef p(pid, *a):\n    if pid == {pid}:\n        EVENTS.append('pidfd')\n    return real_pidfd(pid, *a)\ndef st(path, *a, **k):\n    if str(path).startswith('/proc/{pid}'):\n        EVENTS.append('read')\n    return real_stat(path, *a, **k)\nbuiltins.open = o\nos.pidfd_open = p\nos.stat = st\nreal_send = signal.pidfd_send_signal\ndef s(fd, sig, *rest):\n    if sig:\n        EVENTS.append('send')\n        return None\n    return real_send(fd, sig, *rest)\nsignal.pidfd_send_signal = s",
        pid = ready.pid
    );
    let (stderr, events) = run_helper(&order, &args_ref(&args));
    assert!(stderr.ends_with("delivered\n"), "{stderr}");
    let events: Vec<_> = events.lines().collect();
    assert_eq!(events.first(), Some(&"pidfd"), "{events:?}");
    assert_eq!(events.last(), Some(&"send"), "{events:?}");
    assert!(
        events.iter().filter(|e| **e == "pidfd").count() == 1,
        "no reopen: {events:?}"
    );
}

#[test]
fn helper_verdict_parser_accepts_only_exact_nonce_bound_records() {
    let out = |stderr: &str, exit_code| IncusCommandOutput {
        stdout: String::new(),
        stderr: stderr.into(),
        exit_code,
    };
    let code = |stderr: &str, exit_code| {
        pidfd_signal_outcome("n", &out(stderr, exit_code))
            .map(|_| SandboxErrorCode::UnknownOutcome)
            .map_err(crate::EffectError::from)
            .map_or_else(
                |e| (e.code, matches!(e, crate::EffectError::Unknown(_))),
                |_| (SandboxErrorCode::Internal, false),
            )
    };
    assert!(
        pidfd_signal_outcome(
            "n",
            &out("WSSP_SIGNAL n verified\nWSSP_SIGNAL n delivered\n", 0)
        )
        .is_ok()
    );
    assert_eq!(
        code("WSSP_SIGNAL n gone\n", 0),
        (SandboxErrorCode::ProcessExited, false)
    );
    assert_eq!(
        code("WSSP_SIGNAL n mismatch\n", 0),
        (SandboxErrorCode::ProcessStale, false)
    );
    assert_eq!(
        code("WSSP_SIGNAL n verified\nWSSP_SIGNAL n exited\n", 0),
        (SandboxErrorCode::ProcessExited, false)
    );
    for unknown in [
        "WSSP_SIGNAL n verified\n", // lost after the effect boundary
        "WSSP_SIGNAL n verified\nWSSP_SIGNAL n failed\n",
        "WSSP_SIGNAL other delivered\n", // foreign nonce
        "WSSP_SIGNAL n delivered\n",     // success without verification
        "WSSP_SIGNAL n verified\nWSSP_SIGNAL n delivered", // no terminator
        "noise\nWSSP_SIGNAL n verified\nWSSP_SIGNAL n delivered\n",
        "",
    ] {
        assert_eq!(
            code(unknown, 0),
            (SandboxErrorCode::UnknownOutcome, true),
            "{unknown:?}"
        );
    }
    assert_eq!(
        code("WSSP_SIGNAL n verified\nWSSP_SIGNAL n delivered\n", 1),
        (SandboxErrorCode::UnknownOutcome, true)
    );
}

#[test]
fn missing_interpreter_is_typed_but_other_nonzero_exits_stay_unknown() {
    let out = Command::new("/bin/sh")
        .args([
            "-c",
            super::exec::SIGNAL_HELPER_LAUNCH,
            "wssp-signal",
            HELPER,
            "wssp-signal",
            "host-nonce",
        ])
        .env_clear()
        .env("PATH", "/no-python-here")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(127));
    let result = IncusCommandOutput {
        stdout: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8(out.stderr).unwrap(),
        exit_code: 127,
    };
    let error = pidfd_signal_outcome("host-nonce", &result)
        .map_err(crate::EffectError::from)
        .unwrap_err();
    assert!(matches!(error, crate::EffectError::Completed(_)));
    assert_eq!(error.code, SandboxErrorCode::SignalUnsupportedOnGuest);
    for exit_code in [1, 126, 127, 128] {
        for stderr in [
            "",
            "WSSP_SIGNAL other-nonce interpreter_missing\n",
            "WSSP_SIGNAL host-nonce verified\n",
        ] {
            let result = IncusCommandOutput {
                stdout: String::new(),
                stderr: stderr.into(),
                exit_code,
            };
            let error = pidfd_signal_outcome("host-nonce", &result)
                .map_err(crate::EffectError::from)
                .unwrap_err();
            assert!(
                matches!(error, crate::EffectError::Unknown(_)),
                "{exit_code} {stderr}"
            );
        }
    }
}
