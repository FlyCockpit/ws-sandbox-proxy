//! B9 start/ready over FakeRuntime: start runs after boot as the guest user,
//! READY waits for the ready command, a timeout fails with a typed code, and
//! a cold reconnect runs startup again.

use super::*;
use crate::sandbox_relay::supervisor::execute_launch_for_test;
use sandbox_protocol::OperationState;
use sandbox_runtime::{CreateSandboxRequest, FakeRuntime, StopSandboxRequest};
use serde_json::json;

const SANDBOX: &str = "sbx-start";

fn launch(
    operation: &str,
    kind: &str,
    generation: u64,
    startup: serde_json::Value,
) -> OperationDispatch {
    let request = CreateSandboxRequest::for_test(SANDBOX, operation);
    let mut frame = json!({
        "sandboxOwnerId": "owner", "operationId": operation, "sandboxId": SANDBOX,
        "idempotencyKey": operation, "kind": kind,
        "allocation": crate::sandbox_relay::test_support::allocation(),
        "cpuCount": 1, "memoryMiB": 1024, "generation": generation, "attempt": 1,
        "templateDigest": request.template_digest, "incusFingerprint": request.incus_fingerprint,
        "architecture": "x86_64", "lease": request.lease,
        "guestUid": 1000, "guestGid": 1000, "guestHome": "/home/user", "guestShell": "/bin/bash",
    });
    if !startup.is_null() {
        frame["startup"] = startup;
    }
    serde_json::from_value(frame).unwrap()
}

fn runtime() -> FakeRuntime {
    let fake = FakeRuntime::new();
    fake.fixture_root().unwrap();
    fake
}

fn env() -> Vec<(String, String)> {
    vec![("APP_PORT".to_string(), "3000".to_string())]
}

#[test]
fn launch_script_detaches_quoted_command_under_a_lock() {
    let script = launch_script("echo 'hi' && npm start");
    assert!(script.contains(
        "setsid flock -n /tmp/wssp-start.lock /bin/sh -c 'echo '\\''hi'\\'' && npm start'"
    ));
    assert!(script.contains("</dev/null >>/tmp/wssp-start.log 2>&1 &"));
    // Never a root wrapper: the guest-user command runs `sh` itself.
    assert!(!script.contains("sudo") && !script.contains("su "));
}

#[test]
fn create_runs_start_as_guest_user_then_reports_ready() {
    let fake = runtime();
    let d = launch(
        "create",
        "sandbox.create",
        1,
        json!({"command": "npm start", "cwd": "/home/user/app"}),
    );
    let finished = execute_launch_for_test(&fake, d, &env());
    assert_eq!(
        finished.state,
        OperationState::Succeeded,
        "{:?}",
        finished.error
    );
    assert_eq!(finished.payload.unwrap()["state"], "ready");
    let start = fake
        .command_stdout("create_1_startup")
        .expect("start launched");
    assert!(start.starts_with("exec:script:"), "{start}");
    assert!(
        !start.contains("[root]"),
        "start runs as the guest user: {start}"
    );
    assert!(
        start.contains("npm start") && start.contains("env:APP_PORT=3000"),
        "{start}"
    );
    // No ready command: nothing is polled.
    assert!(fake.command_stdout("create_1_ready_0").is_none());
}

#[test]
fn ready_success_gates_ready() {
    let fake = runtime();
    let d = launch(
        "create",
        "sandbox.create",
        1,
        json!({"command": "npm start", "ready": "curl -sf localhost:3000", "readyTimeoutMs": 5000}),
    );
    let finished = execute_launch_for_test(&fake, d, &env());
    assert_eq!(
        finished.state,
        OperationState::Succeeded,
        "{:?}",
        finished.error
    );
    let ready = fake
        .command_stdout("create_1_ready_0")
        .expect("ready polled");
    assert!(ready.contains("script:curl -sf localhost:3000") && !ready.contains("[root]"));
}

#[test]
fn ready_timeout_fails_with_a_typed_code_and_keeps_the_vm_uncertain() {
    let fake = runtime();
    let d = launch(
        "create",
        "sandbox.create",
        1,
        // The fake exits 1 for a script containing `false`.
        json!({"command": "npm start", "ready": "false", "readyTimeoutMs": 1000}),
    );
    let finished = execute_launch_for_test(&fake, d, &env());
    // The VM exists: the outcome is uncertain, never a released failure.
    assert_eq!(finished.state, OperationState::UnknownOutcome);
    assert_eq!(
        finished.error.unwrap().code,
        SandboxErrorCode::StartupTimeout
    );
    assert!(fake.command_stdout("create_1_ready_0").is_some());
    assert!(
        fake.command_stdout("create_1_ready_1").is_some(),
        "ready is polled until the deadline"
    );
}

#[test]
fn start_launch_failure_is_typed() {
    let fake = runtime();
    let d = launch("create", "sandbox.create", 1, json!({"command": "exit 1"}));
    let finished = execute_launch_for_test(&fake, d, &[]);
    assert_eq!(finished.state, OperationState::UnknownOutcome);
    assert_eq!(
        finished.error.unwrap().code,
        SandboxErrorCode::StartupFailed
    );
}

#[test]
fn cold_reconnect_reruns_startup() {
    let fake = runtime();
    let startup = json!({"command": "npm start", "ready": "curl -sf localhost:3000"});
    let created = execute_launch_for_test(
        &fake,
        launch("create", "sandbox.create", 1, startup.clone()),
        &env(),
    );
    assert_eq!(
        created.state,
        OperationState::Succeeded,
        "{:?}",
        created.error
    );
    let request = CreateSandboxRequest::for_test(SANDBOX, "create");
    fake.stop_sandbox(&StopSandboxRequest {
        template_fingerprint: request.template_digest.clone(),
        sandbox_id: SANDBOX.into(),
        instance_name: request.instance_name.clone(),
        operation_id: "stop".into(),
        idempotency_key: "stop".into(),
    })
    .unwrap();
    let reconnected = execute_launch_for_test(
        &fake,
        launch("reconnect", "sandbox.reconnect", 2, startup),
        &env(),
    );
    assert_eq!(
        reconnected.state,
        OperationState::Succeeded,
        "{:?}",
        reconnected.error
    );
    assert!(
        fake.command_stdout("reconnect_1_startup")
            .unwrap()
            .contains("npm start")
    );
    assert!(fake.command_stdout("reconnect_1_ready_0").is_some());
}

#[test]
fn launch_without_startup_runs_no_guest_command() {
    let fake = runtime();
    let finished = execute_launch_for_test(
        &fake,
        launch("create", "sandbox.create", 1, serde_json::Value::Null),
        &[],
    );
    assert_eq!(
        finished.state,
        OperationState::Succeeded,
        "{:?}",
        finished.error
    );
    assert!(fake.command_stdout("create_1_startup").is_none());
}
