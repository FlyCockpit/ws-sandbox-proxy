//! Restore and binding identity against the
//! executable `incus` shim, never a live VM.

use super::shim_tests::{DnsTestClock, create_req, run_req, runtime_for};
use super::{BindingIdentity, IncusKvmRuntime};
use crate::{
    KillSandboxRequest, ReconnectSandboxRequest, RestoreLaunch, SandboxRuntime, StatPathRequest,
    StopSandboxRequest,
};
use sandbox_protocol::SandboxErrorCode;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The stored disk image (restore base) the restore launches.
const DISK: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const IID: &str = "iid-0b6f2c1e-restore";

fn disk() -> String {
    format!("sha256:{DISK}")
}

fn shim_runtime() -> (IncusKvmRuntime, PathBuf) {
    let (mut runtime, log) = runtime_for("c37_start_gated");
    fs::write(log.parent().unwrap().join("allocation-list"), "").unwrap();
    // A fresh name: the restore initializes a new instance.
    let config = log.parent().unwrap().join("config");
    let _ = fs::remove_dir_all(&config);
    fs::create_dir_all(&config).unwrap();
    let clock = DnsTestClock::install(runtime.client_mut());
    runtime.client_mut().cancelled =
        Some(std::sync::Arc::new(clock.permit(Duration::from_secs(600))));
    (runtime, log)
}

fn restore_req() -> crate::CreateSandboxRequest {
    let mut request = create_req();
    request.restore = Some(RestoreLaunch {
        fingerprint: disk(),
        cloud_init_instance_id: Some(IID.into()),
    });
    request
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

fn stop(request: &crate::CreateSandboxRequest) -> StopSandboxRequest {
    StopSandboxRequest {
        template_fingerprint: request.template_digest.clone(),
        sandbox_id: request.sandbox_id.clone(),
        instance_name: request.instance_name.clone(),
        operation_id: "stop".into(),
        idempotency_key: "stop".into(),
    }
}

fn stat(request: &crate::CreateSandboxRequest) -> StatPathRequest {
    StatPathRequest {
        template_fingerprint: request.template_digest.clone(),
        guest: request.guest.clone(),
        sandbox_id: request.sandbox_id.clone(),
        instance_name: request.instance_name.clone(),
        operation_id: "stat".into(),
        idempotency_key: "stat".into(),
        path: "/home/user".into(),
    }
}

fn config(log: &Path, key: &str) -> Option<String> {
    fs::read_to_string(log.parent().unwrap().join("config").join(key)).ok()
}

fn init_line(log: &Path) -> String {
    fs::read_to_string(log)
        .unwrap()
        .lines()
        .find(|line| line.starts_with("init "))
        .expect("init issued")
        .to_owned()
}

#[test]
fn restore_launches_the_disk_image_and_keeps_the_template_tag() {
    let (runtime, log) = shim_runtime();
    let request = restore_req();
    runtime.create_bound(&request).expect("restore create");
    let init = init_line(&log);
    // launch = restore.fingerprint; template tag = the template digest.
    assert!(
        init.ends_with(&format!("-- {DISK} wssp-sbx-sbx-1")),
        "{init}"
    );
    assert!(
        init.contains(&format!(
            "-c user.flycockpit.template_digest={}",
            request.template_digest
        )),
        "{init}"
    );
    assert!(
        init.contains(&format!("-c user.flycockpit.restore_base={}", disk())),
        "{init}"
    );
    assert!(
        init.contains(&format!("-c volatile.cloud-init.instance-id={IID}")),
        "{init}"
    );
    assert_eq!(config(&log, "volatile.base_image").as_deref(), Some(DISK));
    // A template create never writes the restore tag.
    let (runtime, log) = shim_runtime();
    runtime
        .create_bound(&create_req())
        .expect("template create");
    let init = init_line(&log);
    assert!(!init.contains("restore_base"), "{init}");
    assert!(!init.contains("cloud-init.instance-id"), "{init}");
}

#[test]
fn a_restored_lineage_binds_through_exec_stat_stop_and_cold_reconnect() {
    let (runtime, log) = shim_runtime();
    let request = restore_req();
    runtime.create_bound(&request).expect("restore create");
    runtime
        .create_bound(&request)
        .expect("existing restore retry adopts its instance");
    runtime.stat_path(&stat(&request)).expect("file IO binds");
    runtime
        .exec_supervisor()
        .bind(&run_req("restored-exec"))
        .expect("command binding");
    runtime
        .reconnect_bound(&reconnect(&request))
        .expect("warm reconnect");
    runtime.stop_sandbox(&stop(&request)).expect("stop");
    runtime
        .reconnect_bound(&reconnect(&request))
        .expect("cold reconnect of the restored root");
    let text = fs::read_to_string(log).unwrap();
    assert_eq!(text.lines().filter(|l| l.starts_with("init ")).count(), 1);
}

#[test]
fn a_restored_instance_binds_only_with_the_journaled_restore_base() {
    let (runtime, _log) = shim_runtime();
    let request = restore_req();
    runtime.create_bound(&request).expect("restore create");
    // A daemon that lost its binding (no lease record, no dispatch base)
    // binds the template lineage, which a restored instance never is.
    runtime.client().set_restore_base("sbx-1", None);
    for code in [
        runtime.stop_sandbox(&stop(&request)).unwrap_err().code,
        runtime.stat_path(&stat(&request)).unwrap_err().code,
        runtime
            .kill_bound(&KillSandboxRequest {
                template_fingerprint: request.template_digest.clone(),
                sandbox_id: "sbx-1".into(),
                instance_name: "wssp-sbx-sbx-1".into(),
                operation_id: "kill".into(),
                idempotency_key: "kill".into(),
            })
            .unwrap_err()
            .code,
    ] {
        assert_eq!(code, SandboxErrorCode::IdempotencyConflict);
    }
    // The journaled lease record's base restores every bind.
    runtime.bind_restore_base("sbx-1", &disk());
    runtime.stat_path(&stat(&request)).expect("bound again");
    // The autonomous fail-safe binding needs no hint (the host owns Incus).
    runtime.client().set_restore_base("sbx-1", None);
    runtime
        .client()
        .bind_owned_instance("wssp-sbx-sbx-1", "sbx-1")
        .expect("owned bind of a restored instance");
}

/// (base image, restore tag, daemon hint, dispatch bind ok, owned bind ok)
type BindCase<'a> = (&'a str, Option<&'a str>, Option<&'a str>, bool, bool);

#[test]
fn a_forged_restore_base_tag_never_binds() {
    let template = create_req().template_digest;
    let other = format!("sha256:{}", "2".repeat(64));
    // (base image, restore tag, daemon hint, expected dispatch bind, expected owned bind)
    let cases: [BindCase<'_>; 7] = [
        // Template lineage: the tag is never consulted.
        (&template[7..], None, None, true, true),
        (&template[7..], Some(&other), None, true, true),
        // A hint requires base == hint == tag.
        (&template[7..], Some(&other), Some(&other), false, true),
        (DISK, Some(&other), Some(&disk()), false, false),
        (DISK, None, Some(&disk()), false, false),
        // A restored base without the daemon's hint is not provable for a
        // dispatch; the host-owned arm accepts only a well-formed tag.
        (DISK, Some(&disk()), None, false, true),
        (DISK, Some("not-a-fingerprint"), None, false, false),
    ];
    for (base, tag, hint, dispatch, owned) in cases {
        // An existing instance whose config the test labels.
        let (runtime, log) = runtime_for("running");
        let dir = log.parent().unwrap().join("config");
        for (key, value) in [
            ("user.flycockpit.sandbox_id", "sbx-1"),
            ("user.flycockpit.create_idempotency_key", "create-1"),
            ("user.flycockpit.template_digest", template.as_str()),
            ("volatile.base_image", base),
        ] {
            fs::write(dir.join(key), value).unwrap();
        }
        if let Some(tag) = tag {
            fs::write(dir.join("user.flycockpit.restore_base"), tag).unwrap();
        }
        let identity = BindingIdentity {
            template_fingerprint: template.clone(),
            restore_base: hint.map(str::to_owned),
        };
        let client = runtime.client();
        assert_eq!(
            client
                .bind_instance_as("wssp-sbx-sbx-1", "sbx-1", &identity, None)
                .is_ok(),
            dispatch,
            "dispatch bind: base={base} tag={tag:?} hint={hint:?}"
        );
        assert_eq!(
            client
                .bind_owned_instance("wssp-sbx-sbx-1", "sbx-1")
                .is_ok(),
            owned,
            "owned bind: base={base} tag={tag:?}"
        );
    }
}

#[test]
fn a_refused_restore_before_init_is_not_issued() {
    // An invalid restore fingerprint is refused before any host IO: a
    // first attempt with the instance absent is a definite failure.
    let (runtime, log) = shim_runtime();
    fs::write(log.parent().unwrap().join("deleted-instance"), "").unwrap();
    let mut request = restore_req();
    request.restore.as_mut().unwrap().fingerprint = "not-a-fingerprint".into();
    let error = runtime.create_bound(&request).unwrap_err();
    assert!(
        matches!(error, crate::EffectError::NotIssued(_)),
        "{error:?}"
    );
    assert!(!fs::read_to_string(&log).unwrap().contains("init "));
}

/// Review (offload impl1, P2): a discard on a host with no lease record binds
/// a restored stale copy through the copy row's base, bound for the discard
/// only (`bind_restore_base` / `unbind_restore_base`). The same `base_bound`
/// hint arm decides: `volatile.base_image == hint == restore tag`, plus the
/// template tag and the create key. A forged tag (tag != base image), another
/// create key or template is refused; once unbound, nothing binds.
#[test]
fn a_discards_copy_row_hint_binds_only_the_exact_restored_instance() {
    let template = create_req().template_digest;
    let other = format!("sha256:{}", "2".repeat(64));
    // (restore tag, create key, template, binds)
    let cases: [(&str, &str, &str, bool); 4] = [
        (&disk(), "restore-key", &template, true),
        (&other, "restore-key", &template, false),
        (&disk(), "another-key", &template, false),
        (&disk(), "restore-key", &other, false),
    ];
    for (tag, key, fingerprint, binds) in cases {
        let (runtime, log) = runtime_for("running");
        let dir = log.parent().unwrap().join("config");
        for (k, v) in [
            ("user.flycockpit.sandbox_id", "sbx-1"),
            ("user.flycockpit.create_idempotency_key", "restore-key"),
            ("user.flycockpit.template_digest", template.as_str()),
            ("volatile.base_image", DISK),
            ("user.flycockpit.restore_base", tag),
        ] {
            fs::write(dir.join(k), v).unwrap();
        }
        let bind = || {
            runtime
                .client()
                .bind_instance("wssp-sbx-sbx-1", "sbx-1", fingerprint, Some(key))
        };
        assert!(bind().is_err(), "no hint: a restored copy never binds");
        runtime.bind_restore_base("sbx-1", &disk());
        assert_eq!(
            bind().is_ok(),
            binds,
            "tag={tag} key={key} template={fingerprint}"
        );
        runtime.unbind_restore_base("sbx-1");
        assert_eq!(
            bind().unwrap_err().code,
            SandboxErrorCode::IdempotencyConflict,
            "unbound again"
        );
    }
}
