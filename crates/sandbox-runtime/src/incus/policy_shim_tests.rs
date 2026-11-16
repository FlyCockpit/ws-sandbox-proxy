//! C38 adversarial tests against the executable shim, never packet evidence.
use super::*;
use crate::EnforcementLossStage::{Complete, Prepare};

fn ids() -> Vec<String> {
    vec!["sbx-1".into()]
}

/// Each production adapter parks AFTER its own argv/preparation (including
/// file read staging), before shared spawn admission. A real periodic pass
/// publishes uncertainty without revoking the still-current RuntimePermit.
fn guest_spawn_race(adapter: &'static str) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    for evidence in ["refused", "healthy", "reverified", "revoked"] {
        let (runtime, log) = runtime_for("fix6_cold_ready");
        runtime.create_bound(&create_with_policy()).unwrap();
        let dir = log.parent().unwrap();
        let bound = runtime
            .client()
            .bind_owned_instance("wssp-sbx-sbx-1", "sbx-1")
            .unwrap();
        let mut client = runtime.client().clone();
        let permit = Arc::new(crate::RuntimePermit::default());
        client.cancelled = Some(permit.clone());
        let barrier = Arc::new(Barrier::new(2));
        let admitted = Arc::new(AtomicUsize::new(0));
        let refusals = client.policy_refusals.clone();
        let lock = client.sandbox_lock("sbx-1");
        client.guest_spawn_hook = Some(crate::incus::client::TestGuestSpawnHook(Arc::new({
            let barrier = barrier.clone();
            let admitted = admitted.clone();
            move |command, inside| {
                let is_file = command.get_args().any(|arg| arg == "python3");
                // Park transfer spawns after FileStaging::new has returned.
                // Metadata uses its independent bounded capture and the same
                // bound admission path.
                if adapter.starts_with("file-") && !is_file {
                    return;
                }
                if inside {
                    assert!(
                        refusals.try_lock().is_err(),
                        "admission must span local spawn"
                    );
                    admitted.fetch_add(1, Ordering::SeqCst);
                } else {
                    assert!(
                        refusals.try_lock().is_ok(),
                        "no admission during preparation"
                    );
                    assert!(lock.try_lock().is_ok(), "no unrelated lifecycle lock");
                    barrier.wait();
                    barrier.wait();
                }
            }
        })));
        let worker = std::thread::spawn(move || match adapter {
            "helper" => client.exec_argv(&bound, &["true".into()]).map(|out| {
                assert_eq!(out.exit_code, 0);
            }),
            "supervised" => {
                let request = create_req();
                let request = crate::RunCommandRequest {
                    sandbox_id: request.sandbox_id,
                    instance_name: request.instance_name,
                    template_fingerprint: request.template_digest,
                    operation_id: "spawn-admission".into(),
                    idempotency_key: "spawn-admission".into(),
                    generation: 1,
                    attempt: 1,
                    argv: vec!["true".into()],
                    script: None,
                    cwd: None,
                    timeout_ms: None,
                    env: Vec::new(),
                    stdin: None,
                    guest: Default::default(),
                    build_step: None,
                };
                crate::incus::exec::ExecSupervisor::new(client)
                    .run(&bound, &request)
                    .map(|out| assert_eq!(out.command.exit_code, Some(0)))
                    .map_err(|err| {
                        assert!(matches!(err, crate::EffectError::NotIssued(_)));
                        err.into_error()
                    })
            }
            "file-read" => client.file_pull(&bound, "/tmp/race").map(|bytes| {
                assert_eq!(bytes.read_chunk(0, 64).unwrap(), b"guest-file-bytes\n");
            }),
            "metadata" => client.guest_stat(&bound, "/tmp/race").map(|entry| {
                assert!(entry.validate());
                assert_eq!(entry.size, 4);
            }),
            "file-put" => client
                .file_put(
                    &bound,
                    "/tmp/race",
                    &crate::FileContent::from_bytes(b"payload").unwrap(),
                    &"a".repeat(64),
                )
                .map(|_| ())
                .map_err(crate::EffectError::into_error),
            _ => unreachable!(),
        });
        barrier.wait();
        let before = log_lines(&log).len();
        if evidence == "refused" || evidence == "reverified" {
            fs::write(dir.join("fail-acl-read"), "1000").unwrap();
            runtime.reconcile_policies(&ids()).unwrap();
            assert_eq!(runtime.policy_reconciler_health().inconclusive, 1);
            assert!(
                runtime
                    .client()
                    .policy_refusals
                    .lock()
                    .unwrap()
                    .contains("sbx-1")
            );
            if evidence == "reverified" {
                fs::remove_file(dir.join("fail-acl-read")).unwrap();
                runtime.reconcile_policies(&ids()).unwrap();
                assert_eq!(runtime.policy_reconciler_health().verified, 1);
                assert!(
                    !runtime
                        .client()
                        .policy_refusals
                        .lock()
                        .unwrap()
                        .contains("sbx-1")
                );
            }
        } else {
            // The retained identity must select sbx-1, not an unrelated entry.
            runtime
                .client()
                .policy_refusals
                .lock()
                .unwrap()
                .insert("sbx-other".into());
            runtime.reconcile_policies(&ids()).unwrap();
            assert_eq!(runtime.policy_reconciler_health().verified, 1);
        }
        assert!(
            !permit.is_cancelled(),
            "uncertainty must not revoke authority"
        );
        if evidence == "revoked" {
            permit.revoke();
        }
        barrier.wait();
        let result = worker.join().unwrap();
        let invocations = log_lines(&log)[before..]
            .iter()
            .filter(|line| line.starts_with("exec "))
            .count();
        if evidence == "refused" || evidence == "revoked" {
            let err = result.unwrap_err();
            if evidence == "refused" {
                assert_eq!(err.code, SandboxErrorCode::Internal, "{adapter}");
                assert!(err.is_enforcement_inconclusive(), "{adapter}");
            } else {
                assert_eq!(err.code, SandboxErrorCode::UnknownOutcome);
                assert!(!err.is_enforcement_inconclusive());
            }
            assert_eq!(
                invocations, 0,
                "{adapter}: no guest invocation after refusal wins"
            );
            assert_eq!(admitted.load(Ordering::SeqCst), 0);
        } else {
            result.unwrap();
            assert_eq!(
                invocations, 1,
                "{adapter}/{evidence}: positive inverse must execute"
            );
            assert_eq!(admitted.load(Ordering::SeqCst), 1);
        }
        assert!(!dir.join("stopped-instance").exists());
        assert!(!dir.join("deleted-instance").exists());
        assert!(!loss_record(dir).exists());
    }
}

#[test]
fn guest_spawn_admission_helper_barrier_and_inverse() {
    guest_spawn_race("helper");
}
#[test]
fn guest_spawn_admission_metadata_barrier_and_inverse() {
    guest_spawn_race("metadata");
}
#[test]
fn guest_spawn_admission_supervised_barrier_and_inverse() {
    guest_spawn_race("supervised");
}
#[test]
fn guest_spawn_admission_file_read_barrier_and_inverse() {
    guest_spawn_race("file-read");
}
#[test]
fn guest_spawn_admission_file_put_barrier_and_inverse() {
    guest_spawn_race("file-put");
}

/// Structural regression guard complements executable races: every production
/// guest exec constructor reaches the identity-carrying boundary; raw spawn is
/// confined to the shared boundary and the separate host-only command runner.
#[test]
fn guest_spawn_admission_all_production_adapters_use_shared_boundary() {
    let client = include_str!("client.rs")
        .split("#[cfg(test)]\nmod tests")
        .next()
        .unwrap();
    let exec = include_str!("exec.rs")
        .split("#[cfg(test)]\nmod tests")
        .next()
        .unwrap();
    let files = include_str!("files.rs")
        .split("#[cfg(test)]\nmod tests")
        .next()
        .unwrap();
    // Files has three admitted adapters: metadata capture, byte capture and
    // the shared metadata/put mutation executor.
    for (source, expected) in [(client, 1), (exec, 1), (files, 3)] {
        assert_eq!(source.matches(".spawn_guest(").count(), expected);
        assert!(!source.contains("command.spawn("));
    }
    assert!(!exec.contains("pre::spawn("));
    assert!(!files.contains("pre::spawn("));
    // Guest spawn, bounded host capture (storage marker reads), and the
    // ordinary host command runner are the only raw spawn boundaries.
    assert_eq!(client.matches("pre::spawn(").count(), 3);
    // Piped spawns run `pre::spawn` only as the admitted spawn step (C51
    // split the admission section out so the PTY child shares it).
    let wrapper = client
        .split("pub(super) fn spawn_guest(")
        .nth(1)
        .unwrap()
        .split("pub(super) fn admit_guest_spawn<T>(")
        .next()
        .unwrap();
    assert!(wrapper.contains("self.admit_guest_spawn(bound, command, |before, command| {"));
    assert_eq!(wrapper.matches("pre::spawn(before, command)").count(), 1);
    let boundary = client
        .split("pub(super) fn admit_guest_spawn<T>(")
        .nth(1)
        .unwrap()
        .split("/// Only synthetic")
        .next()
        .unwrap();
    let check = boundary
        .find("refusals.contains(&bound.sandbox_id)")
        .unwrap();
    let spawn = boundary
        .find("let spawned = spawn(before, command);")
        .unwrap();
    let release = boundary.find("drop(refusals)").unwrap();
    assert!(check < spawn && spawn < release);
    // C51: the PTY child spawns only as the admitted step of the same section.
    let pty = include_str!("pty.rs");
    assert_eq!(pty.matches(".admit_guest_spawn(").count(), 1);
    assert_eq!(pty.matches("pre::spawn_pty(").count(), 1);
    assert!(!pty.contains(".spawn_command("));
    assert!(pty.find(".admit_guest_spawn(").unwrap() < pty.find("pre::spawn_pty(").unwrap());
    for source in [client, exec, files] {
        assert!(!source.contains("spawn_pty("));
    }
}

#[test]
fn guest_spawn_admission_releases_before_wait_and_keeps_cancellation() {
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    let (mut client, log) = client_for_with_log("passthrough");
    let bound = client
        .bind_owned_instance("wssp-sbx-sbx-1", "sbx-1")
        .unwrap();
    let marker = log.parent().unwrap().join("guest-entered");
    let permit = Arc::new(crate::RuntimePermit::default());
    client.cancelled = Some(permit.clone());
    let worker_client = client.clone();
    let marker_arg = marker.to_string_lossy().into_owned();
    let worker = std::thread::spawn(move || {
        worker_client.exec_argv(
            &bound,
            &[
                "sh".into(),
                "-c".into(),
                "printf ready > \"$1\"; sleep 60".into(),
                "wssp-test".into(),
                marker_arg,
            ],
        )
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while !marker.exists() {
        assert!(Instant::now() < deadline, "child must enter");
        std::thread::yield_now();
    }
    // The daemon/guest is still blocked. Publication must not wait for it,
    // nor may a child wait keep the independent RuntimePermit admission.
    let published = client
        .policy_refusals
        .try_lock()
        .map(|mut refusals| refusals.insert("sbx-1".into()))
        .is_ok();
    let start = Instant::now();
    permit.revoke();
    let err = worker.join().unwrap().unwrap_err();
    assert!(published, "no policy lock over wait");
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(err.code, SandboxErrorCode::UnknownOutcome);
}

#[test]
fn guest_spawn_admission_retains_bound_client_identity() {
    let (client, log) = client_for_with_log("fix6_cold_ready");
    let bound = client
        .bind_owned_instance("wssp-sbx-sbx-1", "sbx-1")
        .unwrap();
    let marker = log.parent().unwrap().join("binding-spawn");
    for mismatch in ["project", "binary", "healthy"] {
        let mut scoped = client.clone();
        if mismatch == "project" {
            scoped.project = "other-project".into();
        }
        if mismatch == "binary" {
            scoped.binary = "other-binary".into();
        }
        let mut command = std::process::Command::new("sh");
        command
            .args(["-c", "printf entered > \"$1\"", "wssp-test"])
            .arg(&marker);
        let result = scoped.spawn_guest(&bound, &mut command);
        if mismatch == "healthy" {
            assert!(result.unwrap().wait().unwrap().success());
            assert_eq!(fs::read(&marker).unwrap(), b"entered");
        } else {
            let err = result.unwrap_err();
            assert!(matches!(err, crate::EffectError::NotIssued(_)));
            assert_eq!(err.code, SandboxErrorCode::IdempotencyConflict);
            assert!(!marker.exists(), "foreign client must not spawn");
        }
    }
}

/// Actual runtime entry points, not just the poller's busy-lock branch.
/// Park after the first verified fence and run a whole periodic observation
/// before the next guest readiness probe. No sleeps order the interleaving.
#[test]
fn policy_reconciler_actual_readiness_uncertainty_and_confirmed_drift_inverse() {
    #[derive(Debug)]
    struct Counted {
        captures: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        inner: TestLossLifecycle,
    }
    impl crate::EnforcementLossLifecycle for Counted {
        fn capture(&self, id: &str) -> Box<dyn crate::EnforcementLossIntent> {
            self.captures
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            crate::EnforcementLossLifecycle::capture(&self.inner, id)
        }
    }
    for phase in ["before-agent", "after-agent"] {
        for producer in [
            "fresh-create",
            "existing-create",
            "warm-reconnect",
            "cold-reconnect",
        ] {
            for evidence in ["inconclusive", "drift", "healthy"] {
                let (mut runtime, log) = runtime_for(if producer == "fresh-create" {
                    "fix6_new_ready"
                } else {
                    "fix6_cold_ready"
                });
                let dir = log.parent().unwrap().to_path_buf();
                let request = create_with_policy();
                if producer.contains("reconnect") {
                    runtime.create_bound(&request).unwrap();
                    if producer == "cold-reconnect" {
                        fs::remove_file(dir.join("started")).unwrap();
                    }
                }
                let lifecycle = TestLossLifecycle::default();
                let captures = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
                runtime.set_enforcement_loss_lifecycle(std::sync::Arc::new(Counted {
                    captures: captures.clone(),
                    inner: lifecycle.clone(),
                }));
                let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
                if phase == "before-agent" {
                    runtime.client_mut().readiness_barrier = Some(barrier.clone());
                } else {
                    runtime.client_mut().readiness_after_agent_barrier = Some(barrier.clone());
                }
                let worker = runtime.clone();
                let operation = std::thread::spawn(move || {
                    if producer.contains("reconnect") {
                        worker
                            .reconnect_bound(&reconnect_req(
                                request.egress_policy,
                                request.egress_policy_hash,
                            ))
                            .map(|_| ())
                            .map_err(crate::EffectError::into_error)
                    } else {
                        worker
                            .create_bound(&request)
                            .map(|_| ())
                            .map_err(crate::EffectError::into_error)
                    }
                });
                barrier.wait();
                // The boot wait must not retain a lifecycle gate that would block
                // expiry or confirmed-breach restrictive action.
                let lock = runtime.client().sandbox_lock("sbx-1");
                assert!(lock.try_lock().is_ok(), "{producer}: boot must yield gate");
                match evidence {
                    "inconclusive" => fs::write(dir.join("fail-acl-read"), "1000").unwrap(),
                    "drift" => tamper_acl_allow_all(&dir),
                    _ => {}
                }
                runtime.reconcile_policies(&ids()).unwrap();
                let captured_before_resume = captures.load(std::sync::atomic::Ordering::SeqCst);
                barrier.wait();
                let outcome = operation.join().unwrap();
                if evidence != "drift" {
                    assert!(
                        captures.load(std::sync::atomic::Ordering::SeqCst) > captured_before_resume,
                        "{producer}/{phase}: readiness must freshly observe after yielding"
                    );
                }
                if evidence == "healthy" {
                    outcome.unwrap();
                    assert_eq!(runtime.policy_reconciler_health().verified, 1);
                } else if evidence == "inconclusive" {
                    let error = outcome.unwrap_err();
                    assert!(error.is_enforcement_inconclusive(), "{producer}: {error:?}");
                    assert_ne!(error.code, SandboxErrorCode::GuestUnavailable);
                    assert_eq!(runtime.policy_reconciler_health().inconclusive, 1);
                    runtime
                        .drain_enforcement_losses(&|_, _| panic!("uncertainty cannot settle"))
                        .unwrap();
                    assert!(lifecycle.prepared.lock().unwrap().is_empty());
                    assert!(!loss_record(&dir).exists());
                    assert!(!dir.join("stopped-instance").exists());
                    assert!(!dir.join("deleted-instance").exists());
                    fs::remove_file(dir.join("fail-acl-read")).unwrap();
                    runtime.client_mut().readiness_barrier = None;
                    runtime.client_mut().readiness_after_agent_barrier = None;
                    runtime.reconcile_policies(&ids()).unwrap();
                    // The same operation is retryable, never destructively cleaned.
                    if producer.contains("reconnect") {
                        let r = create_with_policy();
                        runtime
                            .reconnect_bound(&reconnect_req(r.egress_policy, r.egress_policy_hash))
                            .unwrap();
                    } else {
                        runtime.create_bound(&create_with_policy()).unwrap();
                    }
                } else {
                    outcome.unwrap_err();
                    assert_eq!(runtime.policy_reconciler_health().drift, 1);
                    assert!(dir.join("stopped-instance").exists());
                    assert!(loss_record(&dir).exists());
                    let stages = std::cell::RefCell::new(Vec::new());
                    runtime
                        .drain_enforcement_losses(&|_, stage| {
                            if stage == Complete {
                                assert!(dir.join("deleted-instance").exists());
                                runtime
                                    .client()
                                    .verify_sandbox_network_absent("sbx-1")
                                    .unwrap();
                            }
                            stages.borrow_mut().push(stage);
                            Ok(())
                        })
                        .unwrap();
                    assert_eq!(*stages.borrow(), [Prepare, Complete]);
                    assert!(!loss_record(&dir).exists());
                    assert!(!lifecycle.prepared.lock().unwrap().is_empty());
                }
            }
        }
    }
}

#[test]
fn policy_reconciler_probe_owns_the_shared_inspection_gate() {
    #[derive(Debug)]
    struct LockedCapture {
        lock: std::sync::Arc<std::sync::Mutex<()>>,
        inner: TestLossLifecycle,
    }
    impl crate::EnforcementLossLifecycle for LockedCapture {
        fn capture(&self, id: &str) -> Box<dyn crate::EnforcementLossIntent> {
            assert!(
                self.lock.try_lock().is_err(),
                "probe must exclude a concurrent periodic observation through its entire shared boundary"
            );
            crate::EnforcementLossLifecycle::capture(&self.inner, id)
        }
    }
    let (runtime, log) = runtime_for("fix6_cold_ready");
    runtime.create_bound(&create_with_policy()).unwrap();
    runtime.set_enforcement_loss_lifecycle(std::sync::Arc::new(LockedCapture {
        lock: runtime.client().sandbox_lock("sbx-1"),
        inner: TestLossLifecycle::default(),
    }));
    assert_eq!(
        runtime.probe_sandbox(&probe_req()).unwrap().state,
        crate::SandboxLiveProbeState::GuestReady
    );
    let request = create_with_policy();
    // An adopted fixture VM predates create; model its original launch's
    // persisted readiness record, as the existing query controls do.
    fs::write(
        log.parent()
            .unwrap()
            .join("config/user.flycockpit.readiness"),
        serde_json::to_string(&crate::incus::client::ReadinessSpec {
            guest: Default::default(),
            architecture: "x86_64".into(),
            mode: Default::default(),
            privilege: Default::default(),
            root_disk_bytes: None,
        })
        .unwrap(),
    )
    .unwrap();
    runtime
        .query_sandbox(
            "sbx-1",
            Some(&request.idempotency_key),
            Some(&request.template_digest),
        )
        .unwrap();
    runtime.sandbox_inventory().unwrap();
    runtime.create_bound(&request).unwrap();
    runtime
        .reconnect_bound(&reconnect_req(
            request.egress_policy,
            request.egress_policy_hash,
        ))
        .unwrap();
    let (fresh, _) = runtime_for("fix6_new_ready");
    fresh.set_enforcement_loss_lifecycle(std::sync::Arc::new(LockedCapture {
        lock: fresh.client().sandbox_lock("sbx-1"),
        inner: TestLossLifecycle::default(),
    }));
    fresh.create_bound(&create_with_policy()).unwrap();
}

#[test]
fn policy_reconciler_captures_authority_before_even_the_ownership_read() {
    #[derive(Debug)]
    struct BeforeIo {
        log: std::path::PathBuf,
        initial: usize,
        inner: TestLossLifecycle,
    }
    impl crate::EnforcementLossLifecycle for BeforeIo {
        fn capture(&self, id: &str) -> Box<dyn crate::EnforcementLossIntent> {
            assert_eq!(
                log_lines(&self.log).len(),
                self.initial,
                "no daemon IO may precede lifecycle capture"
            );
            crate::EnforcementLossLifecycle::capture(&self.inner, id)
        }
    }
    let (runtime, log) = runtime_for("fix6_cold_ready");
    runtime.create_bound(&create_with_policy()).unwrap();
    tamper_acl_allow_all(log.parent().unwrap());
    let inner = TestLossLifecycle::default();
    runtime.set_enforcement_loss_lifecycle(std::sync::Arc::new(BeforeIo {
        initial: log_lines(&log).len(),
        log,
        inner: inner.clone(),
    }));
    runtime.reconcile_policies(&ids()).unwrap();
    assert_eq!(*inner.prepared.lock().unwrap(), [0]);
    assert_eq!(runtime.policy_reconciler_health().drift, 1);
}

#[test]
fn policy_reconciler_detects_acl_network_and_nic_drift_and_restarts_cleanup() {
    for kind in ["acl", "network", "nic"] {
        let (runtime, log) = runtime_for("fix6_cold_ready");
        let dir = log.parent().unwrap();
        runtime.create_bound(&create_with_policy()).unwrap();
        let lifecycle = TestLossLifecycle::default();
        runtime.set_enforcement_loss_lifecycle(std::sync::Arc::new(lifecycle.clone()));
        match kind {
            "acl" => tamper_acl_allow_all(dir),
            "network" => {
                let (network, _) = sandbox_network_names("sbx-1");
                let path = dir.join("networks").join(format!("{network}.conf"));
                let body = fs::read_to_string(&path).unwrap().replace(
                    "security.acls.default.egress.action=drop",
                    "security.acls.default.egress.action=allow",
                );
                fs::write(path, body).unwrap();
            }
            _ => fs::write(dir.join("device-eth0"), "eth0,nictype=bridged,parent=br0").unwrap(),
        }
        runtime.reconcile_policies(&ids()).unwrap();
        assert_eq!(runtime.policy_reconciler_health().drift, 1, "{kind}");
        assert_eq!(*lifecycle.prepared.lock().unwrap(), [0], "{kind}");
        assert!(
            dir.join("stopped-instance").exists(),
            "halt before any next dispatch: {kind}"
        );
        assert!(loss_record(dir).exists(), "durable loss: {kind}");
        assert!(
            !log_lines(&log)
                .iter()
                .any(|line| line.starts_with("delete ")),
            "inspect never deletes"
        );
        let journal = dir.join("host-state/policy-reconciler/state.json");
        assert!(
            fs::read_to_string(journal)
                .unwrap()
                .contains("\"sbx-1\":\"drift\"")
        );
        // A NEW runtime, same external daemon and durable root. No in-memory
        // detector state or lifecycle callback survives.
        let mut restarted = crate::IncusKvmRuntime::new(crate::IncusConfig {
            binary: runtime.client().binary.clone(),
            project: runtime.client().project.clone(),
        })
        .unwrap();
        restarted.set_host_state_dir(dir.join("host-state"));
        restarted.override_network_test_state(dir.join("host-state"), Vec::new());
        assert_eq!(restarted.policy_reconciler_health().drift, 1);
        assert!(
            restarted
                .client()
                .policy_refusals
                .lock()
                .unwrap()
                .contains("sbx-1")
        );
        let stages = std::cell::RefCell::new(Vec::new());
        restarted
            .drain_enforcement_losses(&|_, stage| {
                if stage == Complete {
                    assert!(dir.join("deleted-instance").exists());
                    assert!(
                        restarted
                            .client()
                            .verify_sandbox_network_absent("sbx-1")
                            .is_ok()
                    );
                }
                stages.borrow_mut().push(stage);
                Ok(())
            })
            .unwrap();
        assert_eq!(*stages.borrow(), [Prepare, Complete]);
        assert!(!loss_record(dir).exists(), "{kind}");
        assert!(
            !restarted
                .client()
                .policy_refusals
                .lock()
                .unwrap()
                .contains("sbx-1"),
            "completed teardown reclaims the refusal"
        );
    }
}

#[test]
fn policy_reconciler_inconclusive_refuses_guest_dispatch_without_stop_or_delete() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let dir = log.parent().unwrap();
    runtime.create_bound(&create_with_policy()).unwrap();
    let lifecycle = TestLossLifecycle::default();
    runtime.set_enforcement_loss_lifecycle(std::sync::Arc::new(lifecycle.clone()));
    fs::write(dir.join("fail-acl-read"), "32").unwrap();
    runtime.reconcile_policies(&ids()).unwrap();
    assert_eq!(runtime.policy_reconciler_health().inconclusive, 1);
    assert!(lifecycle.prepared.lock().unwrap().is_empty());
    assert!(!loss_record(dir).exists());
    assert!(
        !log_lines(&log)
            .iter()
            .any(|line| line.starts_with("stop ") || line.starts_with("delete "))
    );
    let bound = runtime
        .client()
        .bind_owned_instance("wssp-sbx-sbx-1", "sbx-1")
        .unwrap();
    let before = log_lines(&log).len();
    let refused = runtime
        .client()
        .exec_argv(&bound, &["true".into()])
        .unwrap_err();
    assert_eq!(refused.code, SandboxErrorCode::Internal);
    assert!(
        refused.is_enforcement_inconclusive(),
        "common refusal must preserve evidence type"
    );
    assert!(
        !log_lines(&log)[before..]
            .iter()
            .any(|line| line.starts_with("exec ")),
        "refuse before issuing guest IO"
    );
    let request = create_req();
    let read = crate::ReadFileRequest {
        sandbox_owner_id: "owner".into(),
        template_fingerprint: request.template_digest.clone(),
        guest: Default::default(),
        sandbox_id: request.sandbox_id.clone(),
        instance_name: request.instance_name.clone(),
        operation_id: "policy-read".into(),
        idempotency_key: "policy-read".into(),
        path: "/tmp/x".into(),
    };
    let refused = runtime.read_file(&read).unwrap_err();
    assert_eq!(refused.code, SandboxErrorCode::Internal);
    assert!(refused.is_enforcement_inconclusive());
    let mkdir = crate::MkdirRequest {
        template_fingerprint: request.template_digest.clone(),
        guest: Default::default(),
        sandbox_id: request.sandbox_id.clone(),
        instance_name: request.instance_name.clone(),
        operation_id: "policy-mkdir".into(),
        idempotency_key: "policy-mkdir".into(),
        path: "/tmp/x".into(),
    };
    let refused = runtime.mkdir(&mkdir).unwrap_err().into_error();
    assert_eq!(refused.code, SandboxErrorCode::Internal);
    assert!(refused.is_enforcement_inconclusive());
    let command = crate::RunCommandRequest {
        template_fingerprint: request.template_digest,
        generation: 1,
        attempt: 1,
        sandbox_id: request.sandbox_id,
        instance_name: request.instance_name,
        operation_id: "policy-run".into(),
        idempotency_key: "policy-run".into(),
        argv: vec!["true".into()],
        script: None,
        cwd: None,
        timeout_ms: None,
        env: Vec::new(),
        stdin: None,
        guest: Default::default(),
        build_step: None,
    };
    let refused = runtime.run_command(&command).unwrap_err().into_error();
    assert_eq!(refused.code, SandboxErrorCode::Internal);
    assert!(refused.is_enforcement_inconclusive());
    assert!(
        !log_lines(&log)[before..]
            .iter()
            .any(|line| line.starts_with("exec ")),
        "all command/file/helper adapters refuse before guest spawn"
    );
    let mut restarted = crate::IncusKvmRuntime::new(crate::IncusConfig {
        binary: runtime.client().binary.clone(),
        project: runtime.client().project.clone(),
    })
    .unwrap();
    restarted.set_host_state_dir(dir.join("host-state"));
    assert_eq!(
        restarted
            .client()
            .exec_argv(&bound, &["true".into()])
            .unwrap_err()
            .code,
        SandboxErrorCode::Internal
    );
    // Positive inverse: fresh coherent evidence clears only retryable refusal.
    fs::remove_file(dir.join("fail-acl-read")).unwrap();
    runtime.reconcile_policies(&ids()).unwrap();
    assert_eq!(runtime.policy_reconciler_health().verified, 1);
    runtime
        .client()
        .exec_argv(&bound, &["true".into()])
        .unwrap();
    assert!(!dir.join("stopped-instance").exists());
}

#[test]
fn policy_reconciler_journals_foreign_vm_and_never_mutates_it() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let dir = log.parent().unwrap();
    runtime.create_bound(&create_with_policy()).unwrap();
    tamper_acl_allow_all(dir);
    fs::write(dir.join("config/user.flycockpit.sandbox_id"), "foreign").unwrap();
    let before = log_lines(&log).len();
    let lifecycle = TestLossLifecycle::default();
    runtime.set_enforcement_loss_lifecycle(std::sync::Arc::new(lifecycle.clone()));
    runtime.reconcile_policies(&ids()).unwrap();
    assert_eq!(runtime.policy_reconciler_health().foreign, 1);
    assert!(lifecycle.prepared.lock().unwrap().is_empty());
    assert!(!loss_record(dir).exists());
    assert!(
        !log_lines(&log)[before..]
            .iter()
            .any(|line| line.starts_with("stop ")
                || line.starts_with("delete ")
                || line.starts_with("network "))
    );
    assert!(
        fs::read_to_string(dir.join("host-state/policy-reconciler/state.json"))
            .unwrap()
            .contains("\"sbx-1\":\"foreign\"")
    );
}

#[test]
fn policy_reconciler_foreign_network_is_retained_during_owned_vm_cleanup() {
    for kind in ["network", "acl"] {
        let (runtime, log) = runtime_for("fix6_cold_ready");
        let dir = log.parent().unwrap();
        runtime.create_bound(&create_with_policy()).unwrap();
        let (network, acl) = sandbox_network_names("sbx-1");
        let path = if kind == "network" {
            dir.join("networks").join(format!("{network}.conf"))
        } else {
            dir.join("acls").join(format!("{acl}.conf"))
        };
        let bytes = fs::read_to_string(&path)
            .unwrap()
            .replace("user.wssp.sandbox_id=sbx-1", "user.wssp.sandbox_id=foreign");
        fs::write(&path, &bytes).unwrap();
        runtime.reconcile_policies(&ids()).unwrap();
        assert!(
            dir.join("stopped-instance").exists(),
            "our VM is stopped, not the foreign network"
        );
        let _ = runtime.drain_enforcement_losses(&|_, _| Ok(()));
        assert_eq!(
            fs::read_to_string(path).unwrap(),
            bytes,
            "foreign object bytes unchanged"
        );
        assert!(
            loss_record(dir).exists(),
            "foreign cleanup refusal retains the durable loss"
        );
    }
}

#[test]
fn policy_reconciler_status_storage_failure_does_not_suppress_restrictive_recovery() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    let dir = log.parent().unwrap();
    runtime.create_bound(&create_with_policy()).unwrap();
    tamper_acl_allow_all(dir);
    fs::write(
        dir.join("host-state/policy-reconciler"),
        "storage unavailable",
    )
    .unwrap();
    runtime.reconcile_policies(&ids()).unwrap_err();
    assert!(
        dir.join("stopped-instance").exists(),
        "status failure never suppresses confirmed-loss halt"
    );
    assert!(loss_record(dir).exists());
    runtime.drain_enforcement_losses(&|_, _| Ok(())).unwrap();
    assert!(
        !loss_record(dir).exists(),
        "the ordinary lifecycle-owned cleanup remains usable"
    );
}

#[test]
fn policy_reconciler_busy_first_sandbox_does_not_starve_later_or_block_health() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    runtime.create_bound(&create_with_policy()).unwrap();
    let lock = runtime.client().sandbox_lock("sbx-0");
    let _held = lock.lock().unwrap();
    runtime
        .reconcile_policies(&["sbx-0".into(), "sbx-1".into()])
        .unwrap();
    let health = runtime.policy_reconciler_health();
    assert_eq!(health.inconclusive, 0);
    assert_eq!(health.verified, 1);
    assert_eq!(health.pending, 1);
    assert!(!log.parent().unwrap().join("stopped-instance").exists());
    let bound = runtime
        .client()
        .bind_owned_instance("wssp-sbx-sbx-1", "sbx-1")
        .unwrap();
    let active = runtime.client().sandbox_lock("sbx-1");
    let _active = active.lock().unwrap();
    runtime.reconcile_policies(&ids()).unwrap();
    assert_eq!(runtime.policy_reconciler_health().pending, 1);
    runtime
        .client()
        .exec_argv(&bound, &["true".into()])
        .unwrap();
}

#[test]
fn retired_enforcement_loss_finishes_absent_cleanup_once() {
    let (runtime, log) = runtime_for("fix6_cold_ready");
    runtime.create_bound(&create_with_policy()).unwrap();
    runtime
        .client()
        .persist_enforcement_loss("sbx-1", "test loss")
        .unwrap();
    // Simulate the journal/VM having already completed destruction.
    fs::write(log.parent().unwrap().join("deleted-instance"), "").unwrap();
    let calls = std::sync::Mutex::new(Vec::new());
    let settle = |_: &str, stage| {
        calls.lock().unwrap().push(stage);
        if stage == Prepare {
            Err(crate::RuntimeError::new(
                sandbox_protocol::SandboxErrorCode::SandboxNotFound,
                "retired",
            ))
        } else {
            Ok(())
        }
    };
    runtime.drain_enforcement_losses(&settle).unwrap();
    assert!(!loss_record(log.parent().unwrap()).exists());
    assert_eq!(*calls.lock().unwrap(), vec![Prepare, Complete]);
    runtime.drain_enforcement_losses(&settle).unwrap();
    assert_eq!(calls.lock().unwrap().len(), 2);
}

#[test]
fn command_admission_reverifies_a_transient_policy_refusal_before_spawn() {
    for drift in [false, true] {
        let (runtime, log) = runtime_for("fix6_cold_ready");
        let create = create_with_policy();
        runtime.create_bound(&create).unwrap();
        runtime
            .client()
            .policy_refusals
            .lock()
            .unwrap()
            .insert("sbx-1".into());
        if drift {
            let (_, acl) = sandbox_network_names("sbx-1");
            fs::write(
                log.parent()
                    .unwrap()
                    .join("acls")
                    .join(format!("{acl}.egress")),
                "action=allow state=enabled destination=0.0.0.0/0 description=foreign\n",
            )
            .unwrap();
        }
        let request = crate::RunCommandRequest {
            template_fingerprint: create.template_digest,
            generation: 1,
            attempt: 1,
            sandbox_id: create.sandbox_id,
            instance_name: create.instance_name,
            operation_id: "reverified-command".into(),
            idempotency_key: "reverified-command".into(),
            argv: vec!["true".into()],
            script: None,
            cwd: None,
            timeout_ms: None,
            env: Vec::new(),
            stdin: None,
            guest: Default::default(),
            build_step: None,
        };
        let supervisor = crate::incus::exec::ExecSupervisor::new(runtime.client().clone());
        let result = supervisor.bind(&request);
        if drift {
            assert!(
                result.is_err(),
                "fresh verification must still refuse real drift"
            );
            assert!(
                runtime
                    .client()
                    .policy_refusals
                    .lock()
                    .unwrap()
                    .contains("sbx-1")
            );
        } else {
            let bound =
                result.expect("a transient refusal is cleared by fresh coherent verification");
            // Execution does not join the ACL edit queue. A held lane, even
            // for this sandbox, cannot stall a verified command's guest IO.
            let (_, acl) = sandbox_network_names("sbx-1");
            let _held = runtime
                .client()
                .acl_edit_turn(
                    &acl,
                    std::time::Instant::now() + std::time::Duration::from_secs(5),
                )
                .unwrap();
            let response = supervisor
                .run(&bound, &request)
                .expect("verified command runs while ACL edits are parked");
            assert_eq!(response.command.exit_code, Some(0));
            assert!(
                !runtime
                    .client()
                    .policy_refusals
                    .lock()
                    .unwrap()
                    .contains("sbx-1")
            );
        }
    }
}
