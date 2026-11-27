//! Real helper plus executable Incus transport shims. No VM or global env edits.
use super::managed_child::ManagedChild;
use super::{
    env_frame::{self, ENV_HELPER},
    exec::ExecSupervisor,
    shim_tests::{PYTHON_TRANSPORT_HOOK, client_for, install_executable, run_req, write_shim},
};
use crate::{EffectError, RunCommandRequest, WriteStdinRequest};
use sandbox_protocol::{OperationState, SandboxErrorCode, env_limits};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, atomic::AtomicBool},
    thread,
    time::{Duration, Instant},
};

fn frame(payload: &[u8]) -> Vec<u8> {
    [
        b"WSSPENV\0\x01".as_slice(),
        &(payload.len() as u32).to_be_bytes(),
        payload,
    ]
    .concat()
}
fn helper_args(target: &Path) -> Vec<String> {
    let l = env_limits();
    vec![
        "-I".into(),
        "-c".into(),
        ENV_HELPER.into(),
        "piped".into(),
        "nonce".into(),
        "1000".into(),
        l.max_entries.to_string(),
        l.key_bytes.to_string(),
        l.value_bytes.to_string(),
        l.json_bytes.to_string(),
        "--".into(),
        "/bin/sh".into(),
        "-c".into(),
        format!("printf ran > '{}'", target.display()),
    ]
}
fn invalid_frames() -> Vec<Vec<u8>> {
    let mut bad_magic = frame(b"{}");
    bad_magic[0] = b'X';
    let mut bad_version = frame(b"{}");
    bad_version[8] = 2;
    let mut oversized = frame(b"{}");
    oversized[9..13].copy_from_slice(&((env_limits().json_bytes + 1) as u32).to_be_bytes());
    let mut cases = vec![
        vec![],
        b"WSSPENV".to_vec(),
        frame(b"{\"A\":")[..14].to_vec(),
        oversized,
        bad_magic,
        bad_version,
    ];
    for payload in [
        br#"{"BAD-NAME":"v"}"#.as_slice(),
        br#"{"A":"\ud800"}"#,
        b"{\"A\":\"\xff\"}",
        br#"{"A":"x","\u0041":"y"}"#,
        br#"{"HOME":"x"}"#,
        br#"{"SHELL":"x"}"#,
        br#"{"constructor":"x"}"#,
        br#"{"A":"x\u0000"}"#,
        b"[]",
    ] {
        cases.push(frame(payload));
    }
    cases
}
fn wait_file(path: &Path) {
    let until = Instant::now() + Duration::from_secs(8);
    while !path.exists() {
        assert!(
            Instant::now() < until,
            "barrier timed out: {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn env_frame_refusal_is_not_issued() {
    let (shim, _) = write_shim("passthrough");
    let target = shim.parent().unwrap().join("ran");
    for input in invalid_frames() {
        let mut child = ManagedChild::spawn(
            crate::host_child::command(
                "/usr/bin/python3",
                crate::host_child::Environment::PathOnly,
            )
            .args(helper_args(&target))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        )
        .unwrap();
        let pid = child.id();
        child.stdin.take().unwrap().write_all(&input).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(!out.status.success());
        assert!(!target.exists(), "refused frame must never run target");
        assert!(out.stdout.is_empty());
        let stderr = String::from_utf8(out.stderr.clone()).unwrap();
        assert!(
            stderr.starts_with(&format!("WSSP_PID nonce {pid}\n\nWSSP_SETUP_FAILED nonce ")),
            "{stderr}"
        );
        let error: EffectError = super::effect_completion::command_outcome(
            &run_req("refused"),
            &out.stdout,
            &out.stderr,
            "nonce",
        )
        .unwrap_err()
        .into();
        assert_eq!(error.code, SandboxErrorCode::HostEffectNotIssued);
        assert_eq!(error.state(), OperationState::Failed);
    }
}

// Model the transport, not validation: production host code still creates and
// queues the real frame, and the real helper consumes it in an isolated guest.
const TRANSPORT: &str = include_str!("../../fixtures/env-transport.py");
fn rig(mode: &str) -> (ExecSupervisor, PathBuf) {
    let client = client_for("passthrough");
    let shim = PathBuf::from(&client.binary);
    let root = shim.parent().unwrap().to_path_buf();
    fs::write(root.join("transport.py"), TRANSPORT).unwrap();
    fs::write(root.join("transport-mode"), mode).unwrap();
    let source = fs::read_to_string(&shim).unwrap();
    assert_eq!(
        source.matches(PYTHON_TRANSPORT_HOOK).count(),
        1,
        "environment transport hook must be present exactly once"
    );
    let script = source.replace(
        PYTHON_TRANSPORT_HOOK,
        &format!(
            "if [ \"$mode\" = \"passthrough\" ]; then exec /usr/bin/python3 '{}' \"$@\"; fi",
            root.join("transport.py").display()
        ),
    );
    install_executable(&shim, &script, 0o755);
    (ExecSupervisor::new(client), root)
}
fn output(response: &crate::RunCommandResponse) -> Vec<u8> {
    response
        .command
        .chunks
        .iter()
        .filter(|c| c.stream == crate::CommandStream::Stdout)
        .flat_map(|c| c.bytes.clone())
        .collect()
}
fn write(supervisor: &ExecSupervisor, req: &RunCommandRequest, bytes: Vec<u8>, eof: bool) {
    supervisor
        .write_stdin(&WriteStdinRequest {
            operation_id: req.operation_id.clone(),
            generation: req.generation,
            attempt: req.attempt,
            bytes,
            eof,
        })
        .unwrap();
}
fn run_stream(
    supervisor: &ExecSupervisor,
    req: &RunCommandRequest,
) -> crate::EffectOutcome<crate::RunCommandResponse> {
    supervisor.run_with_admission(&supervisor.bind(req).unwrap(), req, || {
        Ok((Arc::new(AtomicBool::new(false)), ()))
    })
}

#[test]
fn env_frame_refusal_with_late_stdin_error_is_unknown() {
    for source in ["initial", "pending", "streamed"] {
        let (supervisor, root) = rig("late");
        let target = root.join("ran");
        let error_barrier = Arc::new(std::sync::Barrier::new(2));
        *supervisor.stdin_error_barrier.lock().unwrap() = Some(error_barrier.clone());
        let mut request = run_req("late");
        request.env = vec![("PAYLOAD".into(), "fixture\nquote'界😀".into())];
        request.argv = vec![
            "/bin/sh".into(),
            "-c".into(),
            format!("printf ran > '{}'", target.display()),
        ];
        request.timeout_ms = Some(8000);
        fs::write(
            root.join("invalid-frame"),
            frame(br#"{"HOME":"invalid-stored-default"}"#),
        )
        .unwrap();
        let bytes = vec![0xff; 1024 * 1024];
        if source == "initial" {
            request.stdin = Some(bytes.clone());
        }
        if source == "pending" {
            write(&supervisor, &request, bytes.clone(), true);
        }
        let worker = supervisor.clone();
        let req = request.clone();
        let handle = thread::spawn(move || run_stream(&worker, &req));
        wait_file(&root.join("proof-finished"));
        // Both complete frames have already been emitted before the EPIPE.
        let proof = fs::read_to_string(root.join("helper-stderr")).unwrap();
        assert!(proof.contains("WSSP_PID ") && proof.contains("\nWSSP_SETUP_FAILED "));
        if source == "streamed" {
            write(&supervisor, &request, bytes, true);
        }
        fs::write(root.join("close-stdin"), b"").unwrap();
        error_barrier.wait(); // actual EPIPE, after both refusal frames
        fs::write(root.join("finish-wait"), b"").unwrap();
        let error = handle.join().unwrap().unwrap_err();
        assert_eq!(error.state(), OperationState::UnknownOutcome, "{source}");
        assert_eq!(error.code, SandboxErrorCode::UnknownOutcome, "{source}");
        assert!(!target.exists());
    }
}

#[test]
fn env_frame_stdin_exactness() {
    let (supervisor, root) = rig("pass");
    let ops = root.join("ops");
    fs::create_dir(&ops).unwrap();
    let _ops = super::exec::set_test_guest_ops_dir(Some(ops));
    let mut req = run_req("stdin");
    req.env = vec![("APP".into(), "value".into())];
    req.argv = vec!["/bin/cat".into()];
    // Initial data retains today's initial-data-then-Close semantics.
    req.stdin = Some(vec![0, 255, 10, 13, 1]);
    assert_eq!(
        output(&run_stream(&supervisor, &req).unwrap()),
        req.stdin.clone().unwrap()
    );
    // Pending bytes precede streamed bytes; binary NUL/invalid UTF-8 survives.
    req.operation_id = "queued".into();
    req.stdin = None;
    write(&supervisor, &req, vec![0, 254, 10], false);
    let worker = supervisor.clone();
    let request = req.clone();
    let handle = thread::spawn(move || run_stream(&worker, &request));
    let until = Instant::now() + Duration::from_secs(5);
    while supervisor.active_guest_pid(&req.operation_id).is_none() {
        assert!(Instant::now() < until);
        thread::sleep(Duration::from_millis(5));
    }
    write(&supervisor, &req, vec![253, 13, 0], true);
    assert_eq!(
        output(&handle.join().unwrap().unwrap()),
        vec![0, 254, 10, 253, 13, 0]
    );
    // Direct run with no original pipe sends frame+Close and target sees EOF.
    req.operation_id = "direct".into();
    let ready = root.join("direct-ready");
    let resume = root.join("direct-resume");
    req.argv = vec![
        "/bin/sh".into(),
        "-c".into(),
        format!(
            "printf ready > '{}'; while [ ! -f '{}' ]; do /bin/sleep 0.002; done; /bin/cat",
            ready.display(),
            resume.display()
        ),
    ];
    let worker = supervisor.clone();
    let request = req.clone();
    let handle = thread::spawn(move || worker.run(&worker.bind(&request).unwrap(), &request));
    wait_file(&ready);
    // The active command has no streaming pipe. Refuse input instead of
    // silently retaining it for a different future execution of this ID.
    assert_eq!(
        supervisor
            .write_stdin(&WriteStdinRequest {
                operation_id: req.operation_id.clone(),
                generation: req.generation,
                attempt: req.attempt,
                bytes: vec![42],
                eof: true,
            })
            .unwrap_err()
            .code,
        SandboxErrorCode::NotFound,
    );
    assert_eq!(supervisor.test_pending_stdin(&req), None);
    fs::write(&resume, b"").unwrap();
    assert!(output(&handle.join().unwrap().unwrap()).is_empty());
    req.argv = vec!["/bin/cat".into()];
    write(&supervisor, &req, vec![42], true);
    assert_eq!(
        output(
            &supervisor
                .run(&supervisor.bind(&req).unwrap(), &req)
                .unwrap()
        ),
        vec![42]
    );
}

#[test]
fn maximal_contract_env_passes_frame_encoder() {
    let cases: serde_json::Value = serde_json::from_str(include_str!(
        "../../../sandbox-protocol/fixtures/env_cases.json"
    ))
    .unwrap();
    for case in cases
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["valid"] == true)
    {
        let env: Vec<(String, String)> = case["pairs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                (
                    p["key"].as_str().unwrap().into(),
                    p["unit"]
                        .as_str()
                        .unwrap()
                        .repeat(p["repeat"].as_u64().unwrap() as usize)
                        + p["tail"].as_str().unwrap(),
                )
            })
            .collect();
        let encoded = env_frame::encode(&env).unwrap();
        if env.iter().all(|(k, _)| k == "HOME" || k == "SHELL") {
            assert!(encoded.is_none());
            continue;
        }
        let encoded = encoded.unwrap();
        assert!(encoded.len() <= 13 + env_limits().json_bytes);
        if case["name"].as_str().unwrap().starts_with("maximal-")
            && case["name"] != "maximal-reserved"
        {
            assert_eq!(encoded.len(), 13 + env_limits().json_bytes);
        }
        // Exercise the actual helper and target with every accepted shared map.
        let (supervisor, root) = rig("pass");
        let ops = root.join("ops");
        fs::create_dir(&ops).unwrap();
        let _ops = super::exec::set_test_guest_ops_dir(Some(ops));
        let keys: Vec<_> = env
            .iter()
            .filter(|(k, _)| k != "HOME" && k != "SHELL")
            .map(|(k, _)| k.clone())
            .collect();
        let mut req = run_req("maximum");
        req.env = env;
        req.argv = vec!["/usr/bin/python3".into(), "-I".into(), "-c".into(), "import json,os,sys,pathlib; pathlib.Path(sys.argv[2]).write_bytes(json.dumps({k:os.environ[k] for k in json.loads(sys.argv[1])},sort_keys=True,ensure_ascii=False,separators=(',',':')).encode('utf-8'))".into(), serde_json::to_string(&keys).unwrap(), root.join("target-bytes").to_string_lossy().into_owned()];
        let response = supervisor
            .run(&supervisor.bind(&req).unwrap(), &req)
            .unwrap();
        assert!(output(&response).is_empty());
        assert!(
            fs::read(root.join("target-bytes")).unwrap() == encoded[13..],
            "{}",
            case["name"]
        );
    }
    assert!(
        env_frame::encode(&[
            ("HOME".into(), "ignored".into()),
            ("SHELL".into(), "ignored".into())
        ])
        .unwrap()
        .is_none()
    );
    assert!(
        env_frame::encode(&[("HOME".into(), "x".repeat(env_limits().value_bytes + 1))]).is_err()
    );
}

#[test]
fn command_env_bytes_absent_from_argv_proc_and_errors() {
    let (supervisor, root) = rig("pass");
    let ops = root.join("ops");
    fs::create_dir(&ops).unwrap();
    let _ops = super::exec::set_test_guest_ops_dir(Some(ops));
    let sentinel = "s3sb-private-quote'\"-newline\n界😀";
    let mut req = run_req("secrecy");
    req.env = vec![
        ("PAYLOAD".into(), sentinel.into()),
        ("HOME".into(), "ignored-private-home".into()),
        ("SHELL".into(), "ignored-private-shell".into()),
        ("TERM".into(), "piped-term".into()),
    ];
    let target = root.join("target-env.json");
    req.argv = vec![
        "/usr/bin/python3".into(),
        "-I".into(),
        "-c".into(),
        format!(
            "import os,json,pathlib; pathlib.Path({:?}).write_text(json.dumps({{k:os.environ[k] for k in ('PAYLOAD','HOME','SHELL','TERM')}})); pathlib.Path({:?}).write_bytes(pathlib.Path('/proc/self/cmdline').read_bytes())",
            target.to_string_lossy(),
            root.join("target-proc").to_string_lossy()
        ),
    ];
    let response = supervisor
        .run(&supervisor.bind(&req).unwrap(), &req)
        .unwrap();
    assert!(output(&response).is_empty());
    let received: serde_json::Value = serde_json::from_slice(&fs::read(&target).unwrap()).unwrap();
    assert_eq!(received["PAYLOAD"], sentinel);
    assert_eq!(received["HOME"], "/home/user");
    assert_eq!(received["SHELL"], "/bin/bash");
    assert_eq!(received["TERM"], "piped-term");
    let encodings = [
        sentinel.to_owned(),
        serde_json::to_string(sentinel).unwrap(),
        "czNzYi1wcml2YXRlLXF1b3RlJyItbmV3bGluZQrnlYzwn5iA".into(),
    ];
    for file in ["actual-argv", "actual-proc", "target-proc", "incus.log"] {
        let bytes = fs::read(root.join(file)).unwrap();
        for secret in &encodings {
            assert!(
                !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
                "secret in {file}"
            );
        }
        assert!(!String::from_utf8_lossy(&bytes).contains("ignored-private-"));
    }
    assert!(
        response
            .command
            .chunks
            .iter()
            .all(|c| !String::from_utf8_lossy(&c.bytes).contains(sentinel))
    );
}

#[test]
fn env_helper_absolute_tools_workload_path() {
    use std::os::unix::fs::symlink;
    let (supervisor, root) = rig("pass");
    let ops = root.join("ops");
    fs::create_dir(&ops).unwrap();
    let _ops = super::exec::set_test_guest_ops_dir(Some(ops));
    let bin = root.join("workload-bin");
    fs::create_dir(&bin).unwrap();
    symlink("/bin/mkdir", bin.join("mkdir")).unwrap();
    let redirected = root.join("redirected");
    for tool in ["python3", "setsid"] {
        install_executable(
            &bin.join(tool),
            &format!(
                "#!/bin/sh\nprintf redirected > '{}'\nexit 91\n",
                redirected.display()
            ),
            0o755,
        );
    }
    install_executable(
        &bin.join("only-on-workload-path"),
        "#!/bin/sh\nprintf workload-target",
        0o755,
    );
    let mut req = run_req("tools");
    req.env = vec![("PATH".into(), bin.to_string_lossy().into_owned())];
    req.argv = vec!["only-on-workload-path".into()];
    let response = supervisor
        .run(&supervisor.bind(&req).unwrap(), &req)
        .unwrap();
    assert_eq!(response.command.exit_code, Some(0));
    assert_eq!(output(&response), b"workload-target");
    assert!(!redirected.exists());
}

#[test]
fn env_frame_runtime_refusal_without_stdin_error_is_failed() {
    for input in invalid_frames() {
        let (supervisor, root) = rig("refuse");
        fs::write(root.join("invalid-frame"), input).unwrap();
        let mut req = run_req("refused");
        req.env = vec![("APP".into(), "frame-content-canary".into())];
        req.argv = vec![
            "/bin/sh".into(),
            "-c".into(),
            format!("printf ran > '{}'", root.join("ran").display()),
        ];
        let error = run_stream(&supervisor, &req).unwrap_err();
        assert_eq!(error.code, SandboxErrorCode::HostEffectNotIssued);
        assert_eq!(error.state(), OperationState::Failed);
        assert!(!root.join("ran").exists());
        for file in [
            "actual-argv",
            "actual-proc",
            "helper-proc",
            "helper-stderr",
            "incus.log",
        ] {
            assert!(
                !String::from_utf8_lossy(&fs::read(root.join(file)).unwrap())
                    .contains("frame-content-canary")
            );
        }
    }
}

#[test]
fn env_frame_setup_deadline_and_exec_failure_never_run_target() {
    let (shim, _) = write_shim("passthrough");
    let target = shim.parent().unwrap().join("ran");
    let mut args = helper_args(&target);
    args[5] = "80".into();
    let mut child = ManagedChild::spawn(
        crate::host_child::command("/usr/bin/python3", crate::host_child::Environment::PathOnly)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )
    .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"WSSPENV").unwrap();
    let started = Instant::now();
    let out = child.wait_with_output().unwrap();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(String::from_utf8_lossy(&out.stderr).ends_with("WSSP_SETUP_FAILED nonce 3\n"));
    drop(stdin);
    args[11] = "/no-such-wssp-env-wrapper".into();
    let mut child = ManagedChild::spawn(
        crate::host_child::command("/usr/bin/python3", crate::host_child::Environment::PathOnly)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )
    .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&frame(b"{\"A\":\"x\"}"))
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(String::from_utf8_lossy(&out.stderr).ends_with("WSSP_SETUP_FAILED nonce 4\n"));
    assert!(!target.exists());
}

#[test]
fn empty_and_identity_only_env_keep_spawn_and_stdin_parity() {
    for env in [
        vec![],
        vec![
            ("HOME".into(), "ignored".into()),
            ("SHELL".into(), "ignored".into()),
        ],
    ] {
        let (supervisor, root) = rig("pass");
        let ops = root.join("ops");
        fs::create_dir(&ops).unwrap();
        let _ops = super::exec::set_test_guest_ops_dir(Some(ops));
        let mut req = run_req("empty");
        req.env = env;
        req.argv = vec!["/bin/cat".into()];
        assert!(
            output(
                &supervisor
                    .run(&supervisor.bind(&req).unwrap(), &req)
                    .unwrap()
            )
            .is_empty()
        );
        assert!(
            !root.join("actual-argv").exists(),
            "no env helper on the empty path"
        );
        let log = fs::read_to_string(root.join("incus.log")).unwrap();
        assert!(log.contains("-- python3 -I -S -c"));
        assert!(log.contains("1000 1000 setsid -w /bin/sh -c"));
        assert!(!log.contains("wssp-env-tools"));
        assert!(!log.contains("WSSPENV"));
    }
}

#[test]
fn env_frame_preserves_timeout_cancel_and_expiry_cleanup() {
    for mode in ["timeout", "cancel", "expiry"] {
        let (supervisor, root) = rig("pass");
        let ops = root.join("ops");
        fs::create_dir(&ops).unwrap();
        let _ops = super::exec::set_test_guest_ops_dir(Some(ops));
        // The expiry lease runs on a logical clock that only this test
        // advances, once the command is running: a wall-clock lease short
        // enough to bound setup below its 5 s cap could lapse on a loaded
        // machine before the helper chain even started the command. (The
        // logical clock also drives the command timer, so the timeout and
        // cancel cases keep a wall-clock permit.)
        let clock = Arc::new(std::sync::Mutex::new(Instant::now()));
        let lease = Duration::from_millis(3000);
        let permit = Arc::new(if mode == "expiry" {
            crate::RuntimePermit::with_test_clock(lease, clock.clone())
        } else {
            crate::RuntimePermit::with_timeout(Duration::from_millis(8000))
        });
        let supervisor = supervisor.with_cancellation(permit);
        let mut req = run_req("cleanup");
        req.env = vec![("APP".into(), "workload-value".into())];
        req.argv = vec!["/bin/sleep".into(), "120".into()];
        req.timeout_ms = Some(if mode == "timeout" { 500 } else { 8000 });
        let worker = supervisor.clone();
        let request = req.clone();
        let handle = thread::spawn(move || run_stream(&worker, &request));
        let until = Instant::now() + Duration::from_secs(5);
        let pid = loop {
            if let Some(pid) = supervisor.active_guest_pid(&req.operation_id) {
                break pid;
            }
            assert!(Instant::now() < until);
            thread::sleep(Duration::from_millis(5));
        };
        if mode == "timeout" || mode == "expiry" {
            let args: Vec<String> =
                serde_json::from_slice(&fs::read(root.join("actual-argv")).unwrap()).unwrap();
            // Setup is independent of the command's execution timer (D-20),
            // but remains at most 5s and never exceeds remaining lease authority.
            let setup_max = if mode == "expiry" { 3000 } else { 5000 };
            assert!(
                (1..=setup_max).contains(&args[6].parse::<u64>().unwrap()),
                "helper budget exceeds finite setup/lease remainder"
            );
        }
        // The real wrapper is still the session/group leader after helper execve.
        assert_eq!(super::client::process_group_of(&pid.to_string()), Some(pid));
        if mode == "cancel" {
            supervisor.cancel(&req.operation_id).unwrap();
        }
        if mode == "expiry" {
            *clock.lock().unwrap() += lease;
        }
        let result = handle.join().unwrap();
        // Expired authority leaves guest outcome uncertain; the test owns this
        // modeled guest group and reaps it without inventing runtime evidence.
        if mode == "expiry" {
            let _ =
                crate::host_child::command("/bin/kill", crate::host_child::Environment::PathOnly)
                    .args(["-KILL", "--", &format!("-{pid}")])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
        }
        match mode {
            "timeout" => assert_eq!(result.unwrap_err().code, SandboxErrorCode::Timeout),
            "cancel" => assert_eq!(result.unwrap().command.state, OperationState::Cancelled),
            _ => assert_eq!(result.unwrap_err().state(), OperationState::UnknownOutcome),
        }
        assert!(supervisor.active_guest_pid(&req.operation_id).is_none());
    }
}

#[test]
fn env_frame_lost_refusal_proof_is_unknown() {
    let (supervisor, root) = rig("lost");
    fs::write(
        root.join("invalid-frame"),
        frame(br#"{"HOME":"invalid-default"}"#),
    )
    .unwrap();
    let mut req = run_req("lost-proof");
    req.env = vec![("APP".into(), "value".into())];
    req.argv = vec![
        "/bin/sh".into(),
        "-c".into(),
        format!("printf ran > '{}'", root.join("ran").display()),
    ];
    let error = run_stream(&supervisor, &req).unwrap_err();
    assert_eq!(error.state(), OperationState::UnknownOutcome);
    assert!(!root.join("ran").exists());
    assert!(
        fs::read_to_string(root.join("helper-stderr"))
            .unwrap()
            .contains("WSSP_SETUP_FAILED")
    );
}
