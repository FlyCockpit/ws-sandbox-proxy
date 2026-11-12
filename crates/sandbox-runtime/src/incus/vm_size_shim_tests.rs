//! Runtime allocation proof using the executable daemon double, never live Incus.
use super::shim_tests::{DnsTestClock, create_req, log_invoked, runtime_for, write_shim};
use super::{IncusClient, IncusKvmRuntime};
use crate::{ReconnectSandboxRequest, SandboxRuntime, StopSandboxRequest};
use sandbox_protocol::{SandboxErrorCode, VmSize};
use std::time::{Duration, Instant};
use std::{fs, path::Path};

fn sized_runtime() -> (IncusKvmRuntime, std::path::PathBuf) {
    let (mut runtime, log) = runtime_for("c37_start_gated");
    fs::write(log.parent().unwrap().join("allocation-list"), "").unwrap();
    let clock = DnsTestClock::install(runtime.client_mut());
    runtime.client_mut().cancelled =
        Some(std::sync::Arc::new(clock.permit(Duration::from_secs(600))));
    (runtime, log)
}
fn sized_request() -> crate::CreateSandboxRequest {
    let mut request = create_req();
    request.vm_size = VmSize::new(2, 2048).unwrap();
    request
}

#[test]
fn create_preflight_refusals_require_first_attempt_and_absence() {
    use sandbox_protocol::OperationState;
    // These refusals precede the ordinary existence preflight. The final
    // classifier must still observe absence, including pure policy/size refusals
    // on a journal-proven first attempt.
    for refusal in [
        "guest",
        "image",
        "policy",
        "size",
        "lease",
        "lease-beyond-unlimited",
        "profile",
        "template",
    ] {
        for first_attempt in [true, false] {
            for mode in ["gone", "running", "permission"] {
                let (runtime, log) = runtime_for(mode);
                clear(&log);
                let mut request = create_req();
                request.first_attempt = first_attempt;
                match refusal {
                    "guest" => request.guest.guest_uid = 0,
                    "image" => request.incus_fingerprint = Some("invalid image".into()),
                    "policy" => request.egress_policy_hash = Some("a".repeat(64)),
                    "size" => request.vm_size.cpu_count = 0,
                    "lease" => request.lease.deadline_unix_ms = 1,
                    "lease-beyond-unlimited" => {
                        request.lease.deadline_unix_ms =
                            sandbox_protocol::LEASE_UNLIMITED_DEADLINE_MS + 1
                    }
                    "profile" | "template" => {
                        let source = if refusal == "profile" {
                            "profile-config"
                        } else {
                            "image-config"
                        };
                        fs::write(
                            log.parent().unwrap().join(source),
                            "limits.cpu.allowance=50%\n",
                        )
                        .unwrap();
                    }
                    _ => unreachable!(),
                }
                let error = runtime.create_bound(&request).unwrap_err();
                assert_eq!(
                    error.state(),
                    if first_attempt && mode == "gone" {
                        OperationState::Failed
                    } else {
                        OperationState::UnknownOutcome
                    },
                    "{refusal}, first={first_attempt}, {mode}"
                );
                no_mutation(&log);
                if matches!(refusal, "policy" | "size") {
                    assert!(
                        fs::read_to_string(&log)
                            .unwrap()
                            .lines()
                            .all(|line| line.contains("query --raw /1.0/instances/wssp-sbx-sbx-1")),
                        "pure refusal may only observe existence"
                    );
                }
            }
        }
    }
}

/// B1: the Incus pre-phase lease checks are structural; a 25-hour lease and
/// the far-future "no lease timer" deadline both pass create, warm and cold
/// reconnect (the host ceiling lives in the daemon journal).
#[test]
fn incus_pre_phase_accepts_leases_beyond_24h_and_the_unlimited_deadline() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    for deadline in [
        now + 25 * 3_600_000,
        sandbox_protocol::LEASE_UNLIMITED_DEADLINE_MS,
    ] {
        let (runtime, _log) = sized_runtime();
        let mut request = sized_request();
        request.lease.deadline_unix_ms = deadline;
        runtime.create_bound(&request).expect("long create");
        runtime
            .reconnect_bound(&reconnect(&request))
            .expect("long warm reconnect");
        runtime
            .stop_sandbox(&StopSandboxRequest {
                template_fingerprint: request.template_digest.clone(),
                sandbox_id: request.sandbox_id.clone(),
                instance_name: request.instance_name.clone(),
                operation_id: "stop".into(),
                idempotency_key: "stop".into(),
            })
            .unwrap();
        runtime
            .reconnect_bound(&reconnect(&request))
            .expect("long cold reconnect");
    }
}

#[test]
fn reconnect_refusal_observation_requires_stopped_or_absent_vm() {
    for (mode, expected) in [
        ("gone", Some(false)),
        ("stopped", Some(false)),
        ("running", Some(true)),
        ("permission", None),
    ] {
        let (runtime, log) = runtime_for(mode);
        assert_eq!(
            runtime.sandbox_may_be_running("sbx-1").ok(),
            expected,
            "{mode}"
        );
        no_mutation(&log);
    }
    for status in ["Starting 106", "Stopping 107", "Frozen 110", "Error 112"] {
        let (runtime, log) = sized_runtime();
        fs::write(log.parent().unwrap().join("launched"), "").unwrap();
        fs::write(log.parent().unwrap().join("instance-status"), status).unwrap();
        assert_eq!(
            runtime.sandbox_may_be_running("sbx-1").ok(),
            Some(true),
            "{status}"
        );
        no_mutation(&log);
    }
}

#[test]
fn create_existence_check_error_is_unknown_before_any_mutation() {
    let (runtime, log) = runtime_for("permission");
    let error = runtime.create_bound(&create_req()).unwrap_err();
    assert_eq!(error.code, SandboxErrorCode::AccessDenied);
    assert_eq!(
        error.state(),
        sandbox_protocol::OperationState::UnknownOutcome
    );
    no_mutation(&log);

    for existing in [false, true] {
        for first_attempt in [true, false] {
            let (runtime, log) = sized_runtime();
            let mut request = sized_request();
            if existing {
                runtime.create_bound(&request).unwrap();
            }
            request.first_attempt = first_attempt;
            fs::write(log.parent().unwrap().join("fail-instance-read"), "").unwrap();
            clear(&log);
            let error = runtime.create_bound(&request).unwrap_err();
            assert_eq!(error.code, SandboxErrorCode::Internal);
            assert_eq!(
                error.state(),
                sandbox_protocol::OperationState::UnknownOutcome,
                "transient daemon failure, existing={existing}, first={first_attempt}"
            );
            no_mutation(&log);
        }
    }
}
fn reconnect(request: &crate::CreateSandboxRequest) -> ReconnectSandboxRequest {
    ReconnectSandboxRequest {
        vm_size: request.vm_size,
        lease: request.lease.clone(),
        sandbox_id: request.sandbox_id.clone(),
        instance_name: request.instance_name.clone(),
        template_fingerprint: request.template_digest.clone(),
        guest: request.guest.clone(),
        architecture: request.architecture.clone(),
        operation_id: "resume".into(),
        idempotency_key: "resume".into(),
        egress_policy: request.egress_policy.clone(),
        egress_policy_hash: request.egress_policy_hash.clone(),
        egress_admission: crate::egress::EgressAdmission::PERMITTED,
        guest_sudo: false,
    }
}
fn clear(log: &Path) {
    fs::write(log, "").unwrap();
}
fn no_start(log: &Path) {
    assert!(
        !log_invoked(log, "start"),
        "{}",
        fs::read_to_string(log).unwrap()
    );
}
// Reads may inspect networking, but a refusal must not mutate daemon or intent state.
fn no_mutation(log: &Path) {
    let text = fs::read_to_string(log).unwrap();
    for line in text.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        let mutates = matches!(
            words.first(),
            Some(&"init" | &"start" | &"stop" | &"delete" | &"config")
        ) || (words.first() == Some(&"network")
            && words.iter().any(|word| {
                matches!(
                    *word,
                    "set" | "unset" | "create" | "delete" | "edit" | "attach" | "detach"
                )
            }));
        assert!(!mutates, "refusal must precede mutation: {line}\n{text}");
    }
    assert!(
        !log.parent()
            .unwrap()
            .join("host-state/network-cleanups/sbx-1.json")
            .exists(),
        "refusal must not save a provisioning record"
    );
}

#[test]
fn profile_and_template_allocation_preflight_precedes_network_and_vm_creation() {
    for source in ["profile-config", "image-config"] {
        for injected in [
            "limits.cpu.allowance=50%",
            "limits.memory.swap=true",
            "limits.cpu.nodes=0",
            "limits.cpu=4",
            "limits.memory=4096MiB",
        ] {
            let (runtime, log) = sized_runtime();
            fs::write(log.parent().unwrap().join(source), format!("{injected}\n")).unwrap();
            let error = runtime
                .create_bound(&sized_request())
                .expect_err("preflight must refuse inherited sibling or mismatched limits");
            no_mutation(&log);
            assert_eq!(
                error.code,
                if injected.starts_with("limits.cpu=") || injected.starts_with("limits.memory=") {
                    SandboxErrorCode::VmSizeMismatch
                } else if source == "profile-config" {
                    SandboxErrorCode::Internal
                } else {
                    SandboxErrorCode::IdempotencyConflict
                },
                "{source}: {injected}"
            );
            assert!(!log.parent().unwrap().join("launched").exists());
        }
        let (runtime, log) = sized_runtime();
        fs::write(
            log.parent().unwrap().join(source),
            "limits.cpu=2\nlimits.memory=2048MiB\n",
        )
        .unwrap();
        runtime
            .create_bound(&sized_request())
            .expect("matching inherited limits remain allowed");
    }
}

fn bind(runtime: &IncusKvmRuntime) -> super::BoundInstance {
    runtime
        .client()
        .bind_instance(
            "wssp-sbx-sbx-1",
            "sbx-1",
            &create_req().template_digest,
            None,
        )
        .unwrap()
}

#[test]
fn nondefault_init_pins_both_keys_before_first_start_and_keeps_all_lifecycle_paths() {
    let (runtime, log) = sized_runtime();
    let request = sized_request();
    runtime.create_bound(&request).expect("nondefault create");
    let text = fs::read_to_string(&log).unwrap();
    let lines: Vec<_> = text.lines().collect();
    let init = lines.iter().position(|l| l.starts_with("init ")).unwrap();
    let first_start = lines.iter().position(|l| l.starts_with("start ")).unwrap();
    assert!(init < first_start);
    assert!(lines[init].contains("-c limits.cpu=2"), "{}", lines[init]);
    assert!(
        lines[init].contains("-c limits.memory=2048MiB"),
        "{}",
        lines[init]
    );
    let inventory = runtime.sandbox_inventory().unwrap();
    assert_eq!(
        inventory[0].configured_size,
        crate::ConfiguredSize::Configured(request.vm_size)
    );
    runtime
        .create_bound(&request)
        .expect("existing running retry");
    runtime
        .reconnect_bound(&reconnect(&request))
        .expect("warm reconnect");
    runtime
        .stop_sandbox(&StopSandboxRequest {
            template_fingerprint: request.template_digest.clone(),
            sandbox_id: request.sandbox_id.clone(),
            instance_name: request.instance_name.clone(),
            operation_id: "stop".into(),
            idempotency_key: "stop".into(),
        })
        .unwrap();
    // The shim's stopped flag models the daemon power state.
    runtime
        .reconnect_bound(&reconnect(&request))
        .expect("cold reconnect");
    runtime
        .client()
        .start_bound(&bind(&runtime), request.vm_size)
        .expect("direct start");
    let text = fs::read_to_string(log).unwrap();
    assert_eq!(text.lines().filter(|l| l.starts_with("init ")).count(), 1);
    assert!(text.lines().filter(|l| l.starts_with("start ")).count() >= 3);
}

#[test]
fn common_start_rejects_noncanonical_and_missing_nondefault_limits_without_mutation() {
    let (runtime, log) = sized_runtime();
    let request = sized_request();
    runtime.create_bound(&request).unwrap();
    let dir = log.parent().unwrap();
    for (key, value) in [
        ("limits.cpu", Some("02")),
        ("limits.cpu", Some("0-1")),
        ("limits.cpu", Some("1,2")),
        ("limits.cpu", Some("2 ")),
        ("limits.memory", Some("2GiB")),
        ("limits.memory", Some("2147483648")),
        ("limits.memory", Some("02048MiB")),
        ("limits.memory", Some("2048MiB ")),
        ("limits.memory", Some("50%")),
        ("limits.cpu", None),
        ("limits.memory", None),
    ] {
        fs::write(dir.join("config/limits.cpu"), "2").unwrap();
        fs::write(dir.join("config/limits.memory"), "2048MiB").unwrap();
        let path = dir.join("config").join(key);
        if let Some(value) = value {
            fs::write(path, value).unwrap();
        } else {
            fs::remove_file(path).unwrap();
        }
        clear(&log);
        let error = runtime
            .client()
            .start_bound(&bind(&runtime), request.vm_size)
            .expect_err("allocation mismatch must refuse common start");
        assert_eq!(
            error.code,
            SandboxErrorCode::VmSizeMismatch,
            "{key}={value:?}"
        );
        no_start(&log);
        assert!(
            !log_invoked(&log, "config"),
            "mismatch must not rewrite the VM"
        );
    }
}

#[test]
fn retry_warm_and_cold_reconnect_refuse_changed_size_and_keep_disk() {
    for stopped in [false, true] {
        let (mut runtime, log) = sized_runtime();
        let request = sized_request();
        runtime.create_bound(&request).unwrap();
        let planning = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        runtime.client_mut().network_planning_count = Some(planning.clone());
        let dir = log.parent().unwrap();
        if stopped {
            fs::write(dir.join("stopped-instance"), "").unwrap();
        }
        let mut changed = request.clone();
        changed.vm_size = VmSize::new(4, 4096).unwrap();
        clear(&log);
        let refused = runtime.create_bound(&changed).unwrap_err();
        assert_eq!(refused.code, SandboxErrorCode::VmSizeMismatch);
        assert!(
            matches!(refused, crate::EffectError::Unknown(_)),
            "existing VM refusal must retain a possibly effective create: {refused:?}"
        );
        no_mutation(&log);
        assert_eq!(
            planning.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "preflight must precede planning, including reuse without daemon IO"
        );
        clear(&log);
        let refused = runtime.reconnect_bound(&reconnect(&changed)).unwrap_err();
        assert_eq!(refused.code, SandboxErrorCode::VmSizeMismatch);
        assert!(matches!(refused, crate::EffectError::Unknown(_)));
        assert_eq!(
            refused.state(),
            sandbox_protocol::OperationState::UnknownOutcome
        );
        no_mutation(&log);
        no_start(&log);
        assert!(!log_invoked(&log, "delete"));
        assert_eq!(
            fs::read_to_string(dir.join("config/limits.memory")).unwrap(),
            "2048MiB"
        );
    }
}

/// Each fence has a separate observation window: removing any one alone
/// must expose drift even while the other fences remain intact.
#[test]
fn create_retry_rechecks_drift_at_locked_adoption_and_running_completion() {
    for phase in ["before_existing_adoption", "before_existing_start"] {
        for stopped in [false, true] {
            // The common start already covers the stopped completion path;
            // the running completion must independently check allocation.
            if stopped && phase == "before_existing_start" {
                continue;
            }
            let (mut runtime, log) = sized_runtime();
            let request = sized_request();
            runtime.create_bound(&request).unwrap();
            if stopped {
                fs::write(log.parent().unwrap().join("stopped-instance"), "").unwrap();
            }
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            runtime.client_mut().create_barrier = Some((phase, barrier.clone()));
            clear(&log);
            let worker = std::thread::spawn(move || runtime.create_bound(&request));
            barrier.wait();
            fs::write(
                log.parent().unwrap().join("config/limits.memory"),
                "4096MiB",
            )
            .unwrap();
            // Ignore already-completed adoption when testing the final fence.
            clear(&log);
            barrier.wait();
            assert_eq!(
                worker
                    .join()
                    .unwrap()
                    .expect_err("late allocation drift must be refused")
                    .code,
                SandboxErrorCode::VmSizeMismatch,
                "{phase}"
            );
            no_mutation(&log);
        }
    }
}

#[test]
fn effective_inherited_limits_exact_siblings_raw_and_foreign_bindings_stay_closed() {
    let (runtime, log) = sized_runtime();
    let request = sized_request();
    runtime.create_bound(&request).unwrap();
    let dir = log.parent().unwrap();
    // Inherit BOTH canonical keys. Effective config, rather than local keys,
    // determines allocation. Local absence is not a default over inheritance.
    fs::remove_file(dir.join("config/limits.cpu")).unwrap();
    fs::remove_file(dir.join("config/limits.memory")).unwrap();
    for source in ["profile-config", "image-config"] {
        fs::write(dir.join(source), "limits.cpu=2\nlimits.memory=2048MiB\n").unwrap();
        runtime
            .client()
            .start_bound(&bind(&runtime), request.vm_size)
            .unwrap();
        assert_eq!(
            runtime.sandbox_inventory().unwrap()[0].configured_size,
            crate::ConfiguredSize::Configured(request.vm_size),
            "inventory must read effective {source}"
        );
        fs::write(dir.join(source), "limits.cpu=2\nlimits.memory=4096MiB\n").unwrap();
        clear(&log);
        assert_eq!(
            runtime
                .client()
                .start_bound(&bind(&runtime), request.vm_size)
                .unwrap_err()
                .code,
            SandboxErrorCode::VmSizeMismatch
        );
        no_start(&log);
        fs::remove_file(dir.join(source)).unwrap();
    }
    fs::write(dir.join("config/limits.cpu"), "2").unwrap();
    fs::write(dir.join("config/limits.memory"), "2048MiB").unwrap();
    for key in [
        "limits.cpu.allowance",
        "limits.memory.swap",
        "limits.cpu.nodes",
        "raw.qemu",
        "raw.lxc",
    ] {
        fs::write(dir.join("config").join(key), "1").unwrap();
        clear(&log);
        assert_eq!(
            runtime
                .client()
                .start_bound(&bind(&runtime), request.vm_size)
                .expect_err("sibling/raw key must stay outside allowlist")
                .code,
            SandboxErrorCode::IdempotencyConflict
        );
        no_start(&log);
        fs::remove_file(dir.join("config").join(key)).unwrap();
    }
    let original = bind(&runtime);
    fs::write(dir.join("config/user.flycockpit.sandbox_id"), "foreign").unwrap();
    clear(&log);
    assert_eq!(
        runtime
            .client()
            .start_bound(&original, request.vm_size)
            .unwrap_err()
            .code,
        SandboxErrorCode::IdempotencyConflict
    );
    no_start(&log);
}

#[test]
fn absent_limits_mean_only_matching_dimension_defaults() {
    let (runtime, log) = sized_runtime();
    let mut request = sized_request();
    request.vm_size = VmSize::defaults().unwrap();
    runtime.create_bound(&request).unwrap();
    let dir = log.parent().unwrap();
    fs::remove_file(dir.join("config/limits.cpu")).unwrap();
    fs::remove_file(dir.join("config/limits.memory")).unwrap();
    runtime
        .client()
        .start_bound(&bind(&runtime), request.vm_size)
        .unwrap();
    for size in [VmSize::new(2, 1024).unwrap(), VmSize::new(1, 2048).unwrap()] {
        clear(&log);
        assert_eq!(
            runtime
                .client()
                .start_bound(&bind(&runtime), size)
                .unwrap_err()
                .code,
            SandboxErrorCode::VmSizeMismatch
        );
        no_start(&log);
    }
}

#[test]
fn invalid_runtime_size_allows_only_absence_observation() {
    let (runtime, log) = sized_runtime();
    for (cpu_count, memory_mi_b) in [(0, 1024), (33, 1024), (1, 513), (1, u32::MAX)] {
        let mut request = sized_request();
        request.vm_size = VmSize {
            cpu_count,
            memory_mi_b,
        };
        clear(&log);
        assert_eq!(
            runtime.create_bound(&request).unwrap_err().code,
            SandboxErrorCode::ProtocolError
        );
        assert_eq!(
            runtime
                .reconnect_bound(&reconnect(&request))
                .unwrap_err()
                .code,
            SandboxErrorCode::ProtocolError
        );
        assert!(
            fs::read_to_string(&log)
                .unwrap()
                .lines()
                .all(|line| line.contains("query --raw /1.0/instances/wssp-sbx-sbx-1"))
        );
    }
}

#[test]
fn resources_query_is_read_only_without_project_provisioning_and_uses_daemon_fixture() {
    let (binary, log) = write_shim("resources");
    let client = IncusClient::new(binary.to_string_lossy().into_owned(), "not-provisioned");
    let resources = client.host_resources().unwrap();
    let kernel_total = fs::read_to_string("/proc/meminfo")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse::<u64>()
        .unwrap()
        * 1024;
    assert_eq!(
        resources.memory_total_bytes(),
        1234567890123.min(kernel_total)
    );
    assert_eq!(resources.cpu_threads(), 93);
    let text = fs::read_to_string(log).unwrap();
    assert_eq!(text.lines().count(), 1, "query must not provision");
    assert!(text.contains("query --raw /1.0/resources"));
}

#[test]
fn resource_errors_malformed_missing_overflow_and_timeout_are_bounded_failures() {
    for mode in ["resources_denied", "resources_malformed"] {
        let (binary, _) = write_shim(mode);
        assert!(
            IncusClient::new(binary.to_string_lossy().into_owned(), "not-provisioned")
                .host_resources()
                .is_err()
        );
    }
    let (binary, log) = write_shim("resources");
    let client = IncusClient::new(binary.to_string_lossy().into_owned(), "not-provisioned");
    for metadata in [
        serde_json::json!({}),
        serde_json::json!({"memory":{"total":1}}),
        serde_json::json!({"memory":{"total":1},"cpu":{"total":0}}),
    ] {
        fs::write(log.parent().unwrap().join("resources-response"), serde_json::to_vec(&serde_json::json!({"type":"sync","status_code":200,"error_code":0,"metadata":metadata})).unwrap()).unwrap();
        assert!(client.host_resources().is_err());
    }
    // A bare JSON number beyond u64, not a string/type-error fixture.
    fs::write(log.parent().unwrap().join("resources-response"), br#"{"type":"sync","status_code":200,"error_code":0,"metadata":{"memory":{"total":18446744073709551616},"cpu":{"total":1}}}"#).unwrap();
    assert!(client.host_resources().is_err());
    let (binary, _) = write_shim("resources_timeout");
    let mut client = IncusClient::new(binary.to_string_lossy().into_owned(), "not-provisioned");
    client.agent_timeout = Duration::from_millis(200);
    let start = Instant::now();
    assert_eq!(
        client.host_resources().unwrap_err().code,
        SandboxErrorCode::Timeout
    );
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "resource query must have a bounded timeout"
    );
}

#[test]
fn local_inventory_distinguishes_invalid_config_and_transient_read_failure() {
    let (runtime, log) = sized_runtime();
    runtime.create_bound(&sized_request()).unwrap();
    let dir = log.parent().unwrap();
    fs::write(dir.join("stopped-instance"), "").unwrap();
    fs::write(dir.join("config/limits.memory"), "02048MiB").unwrap();
    let inventory = runtime.sandbox_inventory().unwrap();
    assert_eq!(inventory.len(), 1);
    assert_eq!(
        inventory[0].configured_size,
        crate::ConfiguredSize::Conflict
    );
    fs::write(dir.join("fail-instance-read"), "").unwrap();
    let inventory = runtime
        .sandbox_inventory()
        .expect("per-instance read failure preserves census");
    assert_eq!(inventory.len(), 1);
    assert!(
        matches!(&inventory[0].configured_size, crate::ConfiguredSize::Unobserved(error) if error.code != SandboxErrorCode::VmSizeMismatch),
        "{inventory:?}"
    );
}

#[test]
fn census_sizes_from_listed_expanded_config_and_falls_back_to_instance_query() {
    let (runtime, log) = sized_runtime();
    let request = sized_request();
    runtime.create_bound(&request).unwrap();
    let dir = log.parent().unwrap();
    fs::write(dir.join("stopped-instance"), "").unwrap();
    let instance_queries = |log: &Path| {
        fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .filter(|line| {
                line.starts_with("query ") && line.contains("/1.0/instances/wssp-sbx-sbx-1?")
            })
            .count()
    };
    // Rows carrying the effective config: no per-VM instance query.
    fs::write(dir.join("list-expanded-config"), "").unwrap();
    fs::write(&log, "").unwrap();
    let inventory = runtime.sandbox_inventory().unwrap();
    assert_eq!(
        inventory[0].configured_size,
        crate::ConfiguredSize::Configured(request.vm_size)
    );
    assert_eq!(instance_queries(&log), 0);
    // A transient instance-read failure is irrelevant on this path.
    fs::write(dir.join("fail-instance-read"), "").unwrap();
    assert_eq!(
        runtime.sandbox_inventory().unwrap()[0].configured_size,
        crate::ConfiguredSize::Configured(request.vm_size)
    );
    fs::remove_file(dir.join("fail-instance-read")).unwrap();
    // A noncanonical effective value is still a conflict.
    fs::write(dir.join("config/limits.memory"), "02048MiB").unwrap();
    assert_eq!(
        runtime.sandbox_inventory().unwrap()[0].configured_size,
        crate::ConfiguredSize::Conflict
    );
    assert_eq!(instance_queries(&log), 0);
    // Rows without it fall back to the per-VM query.
    fs::write(dir.join("config/limits.memory"), "2048MiB").unwrap();
    fs::remove_file(dir.join("list-expanded-config")).unwrap();
    fs::write(&log, "").unwrap();
    assert_eq!(
        runtime.sandbox_inventory().unwrap()[0].configured_size,
        crate::ConfiguredSize::Configured(request.vm_size)
    );
    assert!(instance_queries(&log) > 0);
}
