use sandbox_protocol::{SandboxErrorCode, SandboxLifecycleState};
use sandbox_runtime::{
    BuildStep, CreateSandboxRequest, FakeRuntime, GuestIdentity, ListProcessesRequest,
    ProbeSandboxRequest, ProcessSignal, RunCommandRequest, SandboxLiveProbeState, SandboxRuntime,
    SignalProcessRequest, WriteStdinRequest,
};

fn guest() -> GuestIdentity {
    GuestIdentity::default()
}

#[test]
fn create_is_idempotent_by_key() {
    let runtime = FakeRuntime::new();
    let req = CreateSandboxRequest::for_test("sbx-1", "key-1");
    let first = runtime
        .create_sandbox_on_storage(&req, &runtime.fixture_root().expect("fixture root"))
        .expect("first");
    assert_eq!(first.sandbox.state, SandboxLifecycleState::Ready);
    let second = runtime
        .create_sandbox_on_storage(&req, &runtime.fixture_root().expect("fixture root"))
        .expect("second");
    assert_eq!(second.sandbox.sandbox_id, first.sandbox.sandbox_id);
}

#[test]
fn run_command_after_create() {
    let runtime = FakeRuntime::new();
    runtime
        .create_sandbox_on_storage(
            &CreateSandboxRequest::for_test("sbx-2", "key-2"),
            &runtime.fixture_root().expect("fixture root"),
        )
        .expect("create");
    let out = runtime
        .run_command(&RunCommandRequest {
            template_fingerprint: sandbox_runtime::CreateSandboxRequest::for_test("sbx", "key")
                .template_digest,
            generation: 1,
            attempt: 1,
            sandbox_id: "sbx-2".into(),
            instance_name: "wssp-sbx-sbx-2".into(),
            operation_id: "op-1".into(),
            idempotency_key: "cmd-key-1".into(),
            argv: vec!["echo".into(), "hi".into()],
            script: None,
            cwd: None,
            timeout_ms: None,
            env: Vec::new(),
            stdin: None,
            guest: guest(),
            build_step: None,
        })
        .expect("run");
    assert_eq!(out.command.exit_code, Some(0));
}

#[test]
fn process_list_is_empty_and_signal_is_not_found() {
    let runtime = FakeRuntime::new();
    runtime
        .create_sandbox_on_storage(
            &CreateSandboxRequest::for_test("sbx-3", "key-3"),
            &runtime.fixture_root().expect("fixture root"),
        )
        .expect("create");
    let listed = runtime
        .list_processes(&ListProcessesRequest {
            sandbox_id: "sbx-3".into(),
            instance_name: "wssp-sbx-sbx-3".into(),
            operation_id: "op-list".into(),
            idempotency_key: "list-1".into(),
        })
        .expect("list");
    assert!(listed.processes.is_empty());
    let err = runtime
        .signal_process(&SignalProcessRequest {
            template_fingerprint: sandbox_runtime::CreateSandboxRequest::for_test("sbx", "key")
                .template_digest,
            guest: Default::default(),
            sandbox_id: "sbx-3".into(),
            instance_name: "wssp-sbx-sbx-3".into(),
            operation_id: "op-sig".into(),
            idempotency_key: "sig-1".into(),
            pid: 9,
            signal: ProcessSignal::Sigterm,
            target: None,
        })
        .expect_err("naked pid");
    assert_eq!(err.code, SandboxErrorCode::UnsupportedCapability);
    runtime
        .write_stdin(&WriteStdinRequest {
            operation_id: "op-1".into(),
            generation: 1,
            attempt: 1,
            bytes: b"x".to_vec(),
            eof: true,
        })
        .expect("stdin");
}

#[test]
fn command_failures_leave_vm_ready() {
    let runtime = FakeRuntime::new();
    runtime
        .create_sandbox_on_storage(
            &CreateSandboxRequest::for_test("sbx-4", "key-4"),
            &runtime.fixture_root().expect("fixture root"),
        )
        .expect("create");
    let exit1 = runtime
        .run_command(&RunCommandRequest {
            template_fingerprint: sandbox_runtime::CreateSandboxRequest::for_test("sbx", "key")
                .template_digest,
            generation: 1,
            attempt: 1,
            sandbox_id: "sbx-4".into(),
            instance_name: "wssp-sbx-sbx-4".into(),
            operation_id: "op-false".into(),
            idempotency_key: "false-1".into(),
            argv: vec!["false".into()],
            script: None,
            cwd: None,
            timeout_ms: None,
            env: Vec::new(),
            stdin: None,
            guest: guest(),
            build_step: None,
        })
        .expect("exit 1");
    assert_eq!(exit1.command.exit_code, Some(1));
    let timeout = runtime
        .clone()
        .with_force_command_timeout(true)
        .run_command(&RunCommandRequest {
            template_fingerprint: sandbox_runtime::CreateSandboxRequest::for_test("sbx", "key")
                .template_digest,
            generation: 1,
            attempt: 1,
            sandbox_id: "sbx-4".into(),
            instance_name: "wssp-sbx-sbx-4".into(),
            operation_id: "op-sleep".into(),
            idempotency_key: "sleep-1".into(),
            argv: vec!["sleep".into(), "9".into()],
            script: None,
            cwd: None,
            timeout_ms: Some(10),
            env: Vec::new(),
            stdin: None,
            guest: guest(),
            build_step: None,
        })
        .expect_err("timeout");
    assert_eq!(timeout.code, SandboxErrorCode::Timeout);
    let next = runtime
        .run_command(&RunCommandRequest {
            template_fingerprint: sandbox_runtime::CreateSandboxRequest::for_test("sbx", "key")
                .template_digest,
            generation: 1,
            attempt: 1,
            sandbox_id: "sbx-4".into(),
            instance_name: "wssp-sbx-sbx-4".into(),
            operation_id: "op-ok".into(),
            idempotency_key: "ok-1".into(),
            argv: vec!["true".into()],
            script: None,
            cwd: None,
            timeout_ms: None,
            env: Vec::new(),
            stdin: None,
            guest: guest(),
            build_step: None,
        })
        .expect("next command");
    assert_eq!(next.command.exit_code, Some(0));
}

#[test]
fn probe_reports_guest_ready_and_absent() {
    let runtime = FakeRuntime::new();
    runtime
        .create_sandbox_on_storage(
            &CreateSandboxRequest::for_test("sbx-probe", "key-probe"),
            &runtime.fixture_root().expect("fixture root"),
        )
        .expect("create");
    let ready = runtime
        .probe_sandbox(&ProbeSandboxRequest {
            template_fingerprint: crate::CreateSandboxRequest::for_test("default", "default")
                .template_digest,
            architecture: Some("x86_64".into()),
            sandbox_id: "sbx-probe".into(),
            instance_name: "wssp-sbx-sbx-probe".into(),
            operation_id: "probe-1".into(),
            idempotency_key: "probe-1".into(),
            guest: guest(),
        })
        .expect("probe");
    assert_eq!(ready.state, SandboxLiveProbeState::GuestReady);
    let absent = runtime
        .probe_sandbox(&ProbeSandboxRequest {
            template_fingerprint: crate::CreateSandboxRequest::for_test("default", "default")
                .template_digest,
            architecture: Some("x86_64".into()),
            sandbox_id: "missing".into(),
            instance_name: "wssp-sbx-missing".into(),
            operation_id: "probe-2".into(),
            idempotency_key: "probe-2".into(),
            guest: guest(),
        })
        .expect("absent");
    assert_eq!(absent.state, SandboxLiveProbeState::ConfirmedAbsent);
}

#[test]
fn alias_movement_keeps_registered_fingerprint_on_new_create_and_replay() {
    let runtime = FakeRuntime::new();
    let mut request = CreateSandboxRequest::for_test("pinned", "pinned-create");
    let fp = request.template_digest.clone();
    runtime.register_image("local:base", &fp, "x86_64");
    let registered = runtime.resolve_image_ref("local:base").unwrap();
    runtime.register_image(
        "local:base",
        &format!("sha256:{}", "b".repeat(64)),
        "aarch64",
    );
    request.incus_fingerprint = Some(registered.fingerprint);
    // Success proves the old x86 image is used even though the alias is now arm.
    let first = runtime
        .create_sandbox_on_storage(&request, &runtime.fixture_root().expect("fixture root"))
        .unwrap();
    let replay = runtime
        .create_sandbox_on_storage(&request, &runtime.fixture_root().expect("fixture root"))
        .unwrap();
    assert_eq!(first, replay);
    assert_eq!(
        runtime
            .resolve_image_ref("local:base")
            .unwrap()
            .architecture,
        "aarch64"
    );
}

#[test]
fn fake_readiness_rejects_wrong_host_architecture_missing_user_and_agent() {
    let runtime = FakeRuntime::new();
    for defect in ["host", "architecture", "user", "agent"] {
        let mut request = CreateSandboxRequest::for_test(defect, defect);
        match defect {
            "host" => {
                request.incus_fingerprint = Some(format!("sha256:{}", "b".repeat(64)));
                request.template_digest = format!("sha256:{}", "b".repeat(64));
            }
            "architecture" => request.architecture = Some("aarch64".into()),
            "user" => request.guest.guest_uid = 1234,
            "agent" => runtime.set_image_guest(&request.template_digest, Default::default(), false),
            _ => unreachable!(),
        }
        assert_eq!(
            runtime
                .create_sandbox_on_storage(&request, &runtime.fixture_root().expect("fixture root"))
                .unwrap_err()
                .code,
            SandboxErrorCode::GuestUnavailable
        );
        assert_eq!(runtime.query_sandbox(defect, None, None).unwrap(), None);
    }
}

#[test]
fn paired_template_identity_boundaries() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../sandbox-protocol/fixtures/template_identity.json"
    ))
    .unwrap();
    for case in fixture["fingerprints"].as_array().unwrap() {
        let value = case["value"].as_str().unwrap();
        assert_eq!(
            sandbox_runtime::is_incus_fingerprint(value),
            case["valid"].as_bool().unwrap(),
            "{value}"
        );
    }
    for case in fixture["guestPaths"].as_array().unwrap() {
        for home in [true, false] {
            let mut guest = GuestIdentity::default();
            if home {
                guest.guest_home = case["value"].as_str().unwrap().into();
            } else {
                guest.guest_shell = case["value"].as_str().unwrap().into();
            }
            assert_eq!(
                guest.validate().is_ok(),
                case["valid"].as_bool().unwrap(),
                "{guest:?}"
            );
        }
    }
}

#[test]
fn fake_reentry_rechecks_guest_and_template_instead_of_stored_ready() {
    use sandbox_runtime::{ReconnectSandboxRequest, SandboxRuntime};
    for defect in ["agent", "uid", "architecture", "fingerprint"] {
        let runtime = FakeRuntime::default();
        let mut create = CreateSandboxRequest::for_test("reentry", "reentry");
        runtime
            .create_sandbox_on_storage(&create, &runtime.fixture_root().expect("fixture root"))
            .unwrap();
        if defect == "agent" {
            runtime.set_image_guest(&create.template_digest, create.guest.clone(), false);
        }
        if defect == "uid" {
            create.guest.guest_uid = 1001;
        }
        if defect == "architecture" {
            create.architecture = Some("aarch64".into());
        }
        if defect == "fingerprint" {
            create.template_digest = format!("sha256:{}", "b".repeat(64));
            create.incus_fingerprint = Some(create.template_digest.clone());
        }
        assert!(
            runtime
                .create_sandbox_on_storage(&create, &runtime.fixture_root().expect("fixture root"))
                .is_err(),
            "{defect}: replay"
        );
        assert!(
            runtime
                .reconnect_sandbox_on_storage(
                    &ReconnectSandboxRequest {
                        vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
                        lease: sandbox_protocol::HostLease::for_test(),
                        template_fingerprint: create.template_digest.clone(),
                        architecture: create.architecture,
                        guest: create.guest,
                        sandbox_id: create.sandbox_id.clone(),
                        instance_name: create.instance_name,
                        operation_id: "reconnect".into(),
                        idempotency_key: "reconnect".into(),
                        egress_policy: None,
                        egress_policy_hash: None,
                        egress_admission: sandbox_runtime::egress::EgressAdmission::PERMITTED,
                        guest_sudo: false,
                    },
                    &runtime.fixture_root().expect("fixture root")
                )
                .is_err(),
            "{defect}: reconnect"
        );
        if defect == "agent" {
            assert!(
                runtime
                    .query_sandbox(&create.sandbox_id, None, Some(&create.template_digest))
                    .is_err()
            );
        }
    }
}

/// 4b FakeRuntime conformance: exact tracked targets, SIGKILL→single cancel owner, typed refusal on guests without
/// group pidfd, and no wrapper-only success variant.
#[test]
fn fake_tracked_signals_follow_branch_a() {
    use sandbox_runtime::{CommandOutput, SignalOutcome, SignalTarget};
    let runtime = FakeRuntime::with_command_delay(std::time::Duration::from_millis(600));
    runtime
        .create_sandbox_on_storage(
            &sandbox_runtime::CreateSandboxRequest::for_test("sbx-sig", "sig"),
            &runtime.fixture_root().expect("fixture root"),
        )
        .expect("create");
    let request = sandbox_runtime::RunCommandRequest {
        template_fingerprint: sandbox_runtime::CreateSandboxRequest::for_test("sbx-sig", "sig")
            .template_digest,
        generation: 1,
        attempt: 1,
        sandbox_id: "sbx-sig".into(),
        instance_name: "wssp-sbx-sbx-sig".into(),
        operation_id: "op-run".into(),
        idempotency_key: "op-run".into(),
        argv: vec!["sleep".into(), "1".into()],
        script: None,
        cwd: None,
        timeout_ms: None,
        env: Vec::new(),
        stdin: None,
        guest: Default::default(),
        build_step: None,
    };
    let output = CommandOutput::default();
    let worker = runtime.clone();
    let live = request.clone();
    let sink = output.clone();
    let handle = std::thread::spawn(move || worker.run_command_stream(&live, &sink).map(|_| ()));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let birth = loop {
        if let Some(birth) = output.start() {
            break birth;
        }
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    let signal = |signal: ProcessSignal, target: Option<SignalTarget>| {
        runtime.signal_process(&SignalProcessRequest {
            template_fingerprint: request.template_fingerprint.clone(),
            guest: Default::default(),
            sandbox_id: "sbx-sig".into(),
            instance_name: "wssp-sbx-sbx-sig".into(),
            operation_id: "op-sig".into(),
            idempotency_key: "op-sig".into(),
            pid: birth.pid,
            signal,
            target,
        })
    };
    let target = SignalTarget {
        target_operation_id: "op-run".into(),
        generation: 1,
        attempt: 1,
        pid: birth.pid,
    };
    let code = |result: sandbox_runtime::EffectOutcome<SignalOutcome>| result.unwrap_err().code;
    assert_eq!(
        code(signal(ProcessSignal::Sigint, None)),
        SandboxErrorCode::UnsupportedCapability
    );
    let stale = SignalTarget {
        attempt: 2,
        ..target.clone()
    };
    assert_eq!(
        code(signal(ProcessSignal::Sighup, Some(stale))),
        SandboxErrorCode::ProcessNotFound
    );
    runtime.set_guest_group_signal_support(false);
    assert_eq!(
        code(signal(ProcessSignal::Sigterm, Some(target.clone()))),
        SandboxErrorCode::SignalUnsupportedOnGuest
    );
    assert!(runtime.delivered_signals().is_empty());
    runtime.set_guest_group_signal_support(true);
    assert_eq!(
        signal(ProcessSignal::Sigterm, Some(target.clone()))
            .unwrap()
            .into_value(),
        SignalOutcome::ProcessGroup
    );
    assert_eq!(
        runtime.delivered_signals(),
        vec![("op-run".to_string(), ProcessSignal::Sigterm)]
    );
    assert_eq!(
        signal(ProcessSignal::Sigkill, Some(target.clone()))
            .unwrap()
            .into_value(),
        SignalOutcome::CancelRequested
    );
    assert_eq!(
        code(signal(ProcessSignal::Sigterm, Some(target.clone()))),
        SandboxErrorCode::ProcessCancelPending
    );
    let finished = handle.join().unwrap();
    assert_eq!(finished.unwrap_err().code, SandboxErrorCode::Cancelled);
    assert_eq!(
        code(signal(ProcessSignal::Sigterm, Some(target))),
        SandboxErrorCode::UnknownOutcome
    );
}

/// B1: the relay wire bound is absolute (the far-future "no lease timer"
/// deadline); the 24-hour bound is gone from the runtime pre-checks.
#[test]
fn fake_runtime_accepts_leases_beyond_24h_and_the_unlimited_deadline() {
    use sandbox_protocol::{HostLease, LEASE_UNLIMITED_DEADLINE_MS};
    use sandbox_runtime::ReconnectSandboxRequest;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64;
    let lease = |deadline_unix_ms| HostLease {
        deadline_unix_ms,
        ..HostLease::for_test()
    };
    let runtime = FakeRuntime::new();
    let root = runtime.fixture_root().expect("fixture root");
    let mut create = CreateSandboxRequest::for_test("long", "long-create");
    create.lease = lease(now + 25 * 3_600_000);
    runtime
        .create_sandbox_on_storage(&create, &root)
        .expect("25h create");
    let reconnect = |deadline, key: &str| ReconnectSandboxRequest {
        vm_size: sandbox_protocol::VmSize::defaults().expect("defaults"),
        lease: lease(deadline),
        template_fingerprint: create.template_digest.clone(),
        architecture: create.architecture.clone(),
        guest: create.guest.clone(),
        sandbox_id: create.sandbox_id.clone(),
        instance_name: create.instance_name.clone(),
        operation_id: key.into(),
        idempotency_key: key.into(),
        egress_policy: None,
        egress_policy_hash: None,
        egress_admission: sandbox_runtime::egress::EgressAdmission::PERMITTED,
        guest_sudo: false,
    };
    runtime
        .reconnect_sandbox_on_storage(&reconnect(LEASE_UNLIMITED_DEADLINE_MS, "forever"), &root)
        .expect("unlimited reconnect");
    let refused = runtime
        .reconnect_sandbox_on_storage(&reconnect(LEASE_UNLIMITED_DEADLINE_MS + 1, "beyond"), &root)
        .expect_err("past the unlimited deadline");
    assert_eq!(refused.code, SandboxErrorCode::StateConflict);
    let mut unlimited = CreateSandboxRequest::for_test("forever", "forever-create");
    unlimited.lease = lease(LEASE_UNLIMITED_DEADLINE_MS);
    runtime
        .create_sandbox_on_storage(&unlimited, &root)
        .expect("unlimited create");
}

/// D1: the fake runtime reports a build-root step and the fixed COPY helper
/// distinctly, so daemon-level tests can prove which identity ran.
#[test]
fn fake_runtime_marks_build_root_steps_and_copy_helper() {
    let runtime = FakeRuntime::new();
    runtime
        .create_sandbox_on_storage(
            &CreateSandboxRequest::for_test("sbx-root", "key-root"),
            &runtime.fixture_root().expect("fixture root"),
        )
        .expect("create");
    let request = |op: &str, argv: Vec<String>, step: Option<BuildStep>| RunCommandRequest {
        template_fingerprint: sandbox_runtime::CreateSandboxRequest::for_test("sbx", "key")
            .template_digest,
        generation: 1,
        attempt: 1,
        sandbox_id: "sbx-root".into(),
        instance_name: "wssp-sbx-sbx-root".into(),
        operation_id: op.into(),
        idempotency_key: format!("key-{op}"),
        argv,
        script: None,
        cwd: None,
        timeout_ms: None,
        env: Vec::new(),
        stdin: None,
        guest: guest(),
        build_step: step,
    };
    let stdout = |out: &sandbox_runtime::RunCommandResponse| {
        String::from_utf8(out.command.chunks[0].bytes.clone()).unwrap()
    };
    let id = vec!["id".to_string(), "-u".to_string()];
    let user = runtime
        .run_command(&request("op-u", id.clone(), None))
        .unwrap();
    assert_eq!(stdout(&user), "exec:id -u\n");
    let root = runtime
        .run_command(&request("op-r", id.clone(), Some(BuildStep::Root)))
        .unwrap();
    assert_eq!(stdout(&root), "exec:[root] id -u\n");
    let copy = sandbox_protocol::BuildCopyV11 {
        context_path: "/var/tmp/wssp-build/b-1/context.tar".into(),
        sha256: "a".repeat(64),
        src: vec!["app".into()],
        dest: "/srv/app/".into(),
        owner: sandbox_protocol::BuildCopyOwnerV11::User,
        mode: None,
    };
    let out = runtime
        .run_command(&request(
            "op-c",
            Vec::new(),
            Some(BuildStep::Copy(copy.clone())),
        ))
        .unwrap();
    assert_eq!(
        stdout(&out),
        format!(
            "exec:[root] build-copy /var/tmp/wssp-build/b-1/context.tar {} /srv/app/ 1000 1000 - app\n",
            "a".repeat(64)
        )
    );
    // A COPY step never carries its own argv, and an invalid body is refused.
    assert!(
        runtime
            .run_command(&request("op-c2", id, Some(BuildStep::Copy(copy.clone()))))
            .is_err()
    );
    let bad = sandbox_protocol::BuildCopyV11 {
        src: vec!["../x".into()],
        ..copy
    };
    assert!(
        runtime
            .run_command(&request("op-c3", Vec::new(), Some(BuildStep::Copy(bad))))
            .is_err()
    );
}

/// Community bases (I12 backstop, I11) on the fake: a raw upstream image
/// (`ubuntu` 1000:1001, `/home/ubuntu`) never passes standard readiness for
/// the declared 1000:1000 `/home/user`; bootstrap readiness passes, and
/// allocation recovery and probes read the persisted mode.
#[test]
fn a_raw_upstream_guest_is_ready_only_under_bootstrap_readiness() {
    let runtime = FakeRuntime::new();
    let root = runtime.fixture_root().expect("fixture root");
    let standard = CreateSandboxRequest::for_test("sbx-raw", "key-raw");
    runtime.set_image_guest(
        &standard.template_digest,
        sandbox_runtime::raw_upstream_identity(),
        true,
    );
    let err = runtime
        .create_sandbox_on_storage(&standard, &root)
        .expect_err("standard readiness on a raw guest");
    assert_eq!(err.code, SandboxErrorCode::GuestUnavailable);
    assert_eq!(
        err.readiness_reason(),
        Some(sandbox_protocol::ReadinessFailureReason::GuestUser)
    );

    let mut bootstrap = CreateSandboxRequest::for_test("sbx-boot", "key-boot");
    bootstrap.readiness = sandbox_runtime::ReadinessMode::BuildBootstrap;
    let created = runtime
        .create_sandbox_on_storage(&bootstrap, &root)
        .expect("bootstrap readiness");
    assert_eq!(created.sandbox.state, SandboxLifecycleState::Ready);
    // Recovery (a daemon restart) uses the persisted mode, not a request.
    assert_eq!(
        runtime
            .query_sandbox(
                "sbx-boot",
                Some("key-boot"),
                Some(&bootstrap.template_digest)
            )
            .expect("recovery"),
        Some(SandboxLifecycleState::Ready)
    );
    let probe = runtime
        .probe_sandbox(&ProbeSandboxRequest {
            template_fingerprint: bootstrap.template_digest.clone(),
            architecture: bootstrap.architecture.clone(),
            sandbox_id: "sbx-boot".into(),
            instance_name: bootstrap.instance_name.clone(),
            operation_id: "probe".into(),
            idempotency_key: "probe".into(),
            guest: guest(),
        })
        .expect("probe");
    assert_eq!(probe.state, SandboxLiveProbeState::GuestReady);
}
