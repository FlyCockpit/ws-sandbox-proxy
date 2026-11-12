//! Executable API/CLI shims only. No test talks to an Incus daemon.
use super::shim_tests::{DnsTestClock, install_executable, log_invoked, write_shim};
use super::{IncusClient, IncusKvmRuntime};
use crate::{CreateSandboxRequest, GIB_BYTES, RootDisk, SandboxRuntime, StorageDriver};
use serde_json::json;
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

fn fixture() -> (IncusKvmRuntime, PathBuf) {
    let (binary, log) = write_shim("c37_start_gated");
    let delegate = binary.with_file_name("delegate");
    let source = fs::read_to_string(&binary)
        .unwrap()
        .replace("incus.log", "delegate.log");
    install_executable(&delegate, &source, 0o755);
    install_executable(&binary, SCRIPT, 0o755);
    let mut client = IncusClient::new(binary.to_string_lossy().into_owned(), "default");
    client.set_host_state_dir(log.parent().unwrap().join("host-state"));
    client.agent_timeout = Duration::from_secs(5);
    let mut runtime = IncusKvmRuntime::from_test_client(client);
    runtime.override_network_test_state(log.parent().unwrap().join("host-state"), Vec::new());
    fs::write(log.parent().unwrap().join("allocation-list"), "").unwrap();
    let clock = DnsTestClock::install(runtime.client_mut());
    runtime.client_mut().cancelled =
        Some(std::sync::Arc::new(clock.permit(Duration::from_secs(600))));
    (runtime, log)
}
fn root(runtime: &IncusKvmRuntime, pool: &str) -> RootDisk {
    RootDisk {
        pool: runtime.initialize_storage_pool(pool, None).unwrap(),
        disk_gi_b: sandbox_protocol::vm_size_limits()
            .unwrap()
            .disk_gi_b_default,
    }
}
fn write_json(log: &Path, name: &str, value: serde_json::Value) {
    fs::write(
        log.parent().unwrap().join(name),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
}
fn reconnect(req: &CreateSandboxRequest) -> crate::ReconnectSandboxRequest {
    crate::ReconnectSandboxRequest {
        vm_size: req.vm_size,
        lease: req.lease.clone(),
        template_fingerprint: req.template_digest.clone(),
        architecture: req.architecture.clone(),
        guest: req.guest.clone(),
        sandbox_id: req.sandbox_id.clone(),
        instance_name: req.instance_name.clone(),
        operation_id: "resume".into(),
        idempotency_key: "resume".into(),
        egress_policy: req.egress_policy.clone(),
        egress_policy_hash: req.egress_policy_hash.clone(),
        egress_admission: crate::egress::EgressAdmission::PERMITTED,
        guest_sudo: false,
    }
}
fn no_mutation(log: &Path) {
    for line in fs::read_to_string(log).unwrap().lines() {
        assert!(
            ![
                "init ",
                "start ",
                "config ",
                "stop ",
                "delete ",
                "network create ",
                "network set ",
                "network edit ",
                "storage volume file push "
            ]
            .iter()
            .any(|s| line.starts_with(s)),
            "{line}"
        );
    }
}

#[test]
fn storage_resources_four_drivers_loop_backing_and_strict_bounds_without_writes() {
    let (runtime, log) = fixture();
    for (name, driver) in [
        ("dir", StorageDriver::Dir),
        ("lvm", StorageDriver::Lvm),
        ("zfs", StorageDriver::Zfs),
        ("btrfs", StorageDriver::Btrfs),
    ] {
        write_json(
            &log,
            "pool.json",
            json!({"driver":name,"status":"Created","config":{"source":"/operator/loop.img"}}),
        );
        let (observed, resources) = runtime.client().storage_resources("pool-a").unwrap();
        assert_eq!(observed, driver);
        assert_eq!(resources.free_bytes(), 200 * GIB_BYTES);
    }
    for value in [
        json!({}),
        json!({"space":{"total":0,"used":0}}),
        json!({"space":{"total":4,"used":5}}),
        json!({"space":{"total":4,"used":-1}}),
        json!({"space":{"total":4,"used":1.5}}),
        json!({"space":{"total":"4","used":1}}),
    ] {
        write_json(&log, "resources.json", value);
        assert!(runtime.client().storage_resources("pool-a").is_err());
    }
    fs::write(
        log.parent().unwrap().join("resources.json"),
        r#"{"space":{"total":18446744073709551616,"used":1}}"#,
    )
    .unwrap();
    assert!(runtime.client().storage_resources("pool-a").is_err());
    no_mutation(&log);
    assert!(!fs::read_to_string(log).unwrap().contains("project create"));
}

#[test]
fn storage_marker_create_once_bound_missing_never_restamps_and_inspection_never_creates() {
    let (runtime, log) = fixture();
    assert!(runtime.client().read_storage_marker("pool-a").is_err());
    assert!(!log_invoked(&log, "storage volume file push"));
    let root = root(&runtime, "pool-a");
    assert_eq!(
        runtime.initialize_storage_pool("pool-a", None).unwrap(),
        root.pool
    );
    assert_eq!(
        runtime
            .initialize_storage_pool("pool-a", Some(&root.pool))
            .unwrap(),
        root.pool
    );
    let text = fs::read_to_string(&log).unwrap();
    assert_eq!(text.matches("storage volume file push").count(), 1);
    assert_eq!(text.matches("-X POST").count(), 1);
    assert!(text.contains("\"size\":\"1GiB\""));
    assert!(!text.contains("-X PUT") && !text.contains("-X PATCH"));
    fs::remove_file(log.parent().unwrap().join("marker-pool-a.json")).unwrap();
    fs::write(&log, "").unwrap();
    assert!(
        runtime
            .initialize_storage_pool("pool-a", Some(&root.pool))
            .is_err()
    );
    assert!(!fs::read_to_string(log).unwrap().contains("POST"));
}

#[test]
fn storage_marker_conflict_waits_for_winner_never_writes_and_timeout_never_claims_creation() {
    for mode in [
        "conflict",
        "conflict-incomplete",
        "ambiguous",
        "denied",
        "push-denied",
    ] {
        let (runtime, log) = fixture();
        fs::write(log.parent().unwrap().join("create-mode"), mode).unwrap();
        let result = runtime.initialize_storage_pool("pool-a", None);
        assert_eq!(result.is_ok(), mode == "conflict", "{mode}: {result:?}");
        let text = fs::read_to_string(&log).unwrap();
        assert_eq!(
            text.matches("storage volume file push").count(),
            usize::from(mode == "push-denied"),
            "{mode}"
        );
        assert!(!text.contains("-X PUT") && !text.contains("-X PATCH"));
        if mode == "ambiguous" {
            fs::write(&log, "").unwrap();
            assert!(runtime.initialize_storage_pool("pool-a", None).is_err());
            assert!(!fs::read_to_string(&log).unwrap().contains("POST"));
        }
    }
}

#[test]
fn storage_marker_file_loss_swap_metadata_change_and_rights_are_pool_local_failures() {
    for mode in [
        "missing-file",
        "missing-file-751",
        "missing-volume",
        "malformed-file",
        "different-file",
        "metadata-swap",
        "file-denied",
        "file-flood",
        "pool-offline",
        "pool-missing",
        "volumes-denied",
    ] {
        let (runtime, log) = fixture();
        let a = root(&runtime, "pool-a");
        let b = root(&runtime, "pool-b");
        fs::write(log.parent().unwrap().join("fault-pool-a"), mode).unwrap();
        let err = runtime.observe_storage_pool(&a.pool).unwrap_err();
        assert_eq!(
            err.storage_reason(),
            ([
                "missing-file",
                "missing-file-751",
                "missing-volume",
                "pool-missing"
            ]
            .contains(&mode))
            .then_some(sandbox_protocol::capacity_v11::StorageReason::Missing),
            "{mode}"
        );
        runtime.observe_storage_pool(&b.pool).unwrap();
        fs::write(&log, "").unwrap();
        assert!(
            runtime
                .initialize_storage_pool("pool-a", Some(&a.pool))
                .is_err()
        );
        assert!(!fs::read_to_string(&log).unwrap().contains("POST"));
    }
}

#[test]
fn storage_project_owns_volumes_including_default_semantics_never_updates_sharing() {
    let (runtime, log) = fixture();
    runtime.client().ensure_project().unwrap();
    for config in [json!({"features.storage.volumes":"false"}), json!({})] {
        write_json(&log, "project.json", json!({"config": config}));
        let client = IncusClient::new(runtime.client().binary.clone(), "wssp");
        assert!(client.ensure_project().is_err());
    }
    write_json(
        &log,
        "project.json",
        json!({"config":{"features.profiles":"false","features.images":"false","features.storage.volumes":"true"}}),
    );
    let client = IncusClient::new(runtime.client().binary.clone(), "wssp");
    client.ensure_project().unwrap();
    assert!(!fs::read_to_string(log).unwrap().contains("project set"));
}

#[test]
fn storage_physical_credit_clamps_to_commitments_excludes_caches_and_falls_back_to_zero() {
    let (runtime, log) = fixture();
    let root = root(&runtime, "pool-a");
    for (driver, trusted) in [
        ("dir", false),
        ("lvm", true),
        ("zfs", true),
        ("btrfs", false),
    ] {
        write_json(
            &log,
            "pool.json",
            json!({"driver":driver,"status":"Created","config":{}}),
        );
        let usage = runtime
            .storage_physical_usage(
                &root.pool,
                &["wssp-sbx-a".into(), "wssp-sbx-b".into()],
                5 * GIB_BYTES,
            )
            .unwrap();
        assert_eq!(usage.trusted, trusted);
        assert_eq!(usage.charged_bytes, if trusted { 5 * GIB_BYTES } else { 0 });
    }
    write_json(
        &log,
        "pool.json",
        json!({"driver":"lvm","status":"Created","config":{"lvm.use_thinpool":"false"}}),
    );
    assert_eq!(
        runtime
            .storage_physical_usage(&root.pool, &["wssp-sbx-a".into()], u64::MAX)
            .unwrap()
            .charged_bytes,
        0
    );
    write_json(
        &log,
        "pool.json",
        json!({"driver":"zfs","status":"Created","config":{}}),
    );
    write_json(
        &log,
        "usage.json",
        json!({"usage":{"total":1000*GIB_BYTES}}),
    );
    assert_eq!(
        runtime
            .storage_physical_usage(&root.pool, &["wssp-sbx-a".into()], u64::MAX)
            .unwrap()
            .charged_bytes,
        0
    );
    let text = fs::read_to_string(log).unwrap();
    assert!(
        !text.contains("/volumes/custom/wssp-pool-marker/state")
            && !text.contains("/volumes/image/")
    );
}

#[test]
fn storage_census_ignores_marker_images_containers_snapshots_and_unrelated_volumes() {
    let (runtime, log) = fixture();
    let root = root(&runtime, "pool-a");
    write_json(
        &log,
        "volumes.json",
        json!([
            {"type":"custom","name":"wssp-pool-marker"},
            {"type":"custom","name":"wssp-sbx-custom"},
            {"type":"container","name":"wssp-sbx-container"},
            {"type":"image","name":"native-cache"},
            {"type":"virtual-machine","name":"unrelated"},
        {"type":"virtual-machine","name":"wssp-sbx-orphan/snapshot"},
            {"type":"virtual-machine","name":"wssp-sbx-orphan","config":{"size":"34359738368"}},
            {"type":"virtual-machine","name":"wssp-sbx-uncertain","config":{}}
        ]),
    );
    let census = runtime.storage_root_census(&root.pool).unwrap();
    assert_eq!(census.roots.len(), 2);
    assert_eq!(census.roots[0].instance_name, "wssp-sbx-orphan");
    assert_eq!(census.roots[0].size_bytes, Some(32 * GIB_BYTES));
    assert_eq!(census.roots[1].size_bytes, None);
    fs::write(log.parent().unwrap().join("lose-during-census"), "").unwrap();
    assert!(runtime.storage_root_census(&root.pool).is_err());
}

#[test]
fn storage_absence_requires_healthy_original_marker_vm_and_root_absence() {
    let (runtime, log) = fixture();
    let root = root(&runtime, "pool-a");
    let name = "wssp-sbx-sbx-1";
    let proof = runtime.prove_root_absent(&root, name).unwrap();
    assert_eq!(proof.pool(), &root.pool);
    assert_eq!(proof.instance_name(), name);
    write_json(
        &log,
        "volumes.json",
        json!([{"type":"virtual-machine","name":name,"config":{"size":"32GiB"}}]),
    );
    assert!(runtime.prove_root_absent(&root, name).is_err());
    write_json(&log, "volumes.json", json!([]));
    fs::write(log.parent().unwrap().join("fault-pool-a"), "pool-offline").unwrap();
    assert!(runtime.prove_root_absent(&root, name).is_err());
    fs::remove_file(log.parent().unwrap().join("fault-pool-a")).unwrap();
    fs::write(log.parent().unwrap().join("launched"), "").unwrap();
    assert!(runtime.prove_root_absent(&root, name).is_err());
}

#[test]
fn storage_final_pool_size_and_actual_root_name_are_pinned_before_native_init_and_start() {
    let (runtime, log) = fixture();
    let root = root(&runtime, "pool-a");
    fs::write(log.parent().unwrap().join("profile-root-name"), "rootfs").unwrap();
    // Explicit selection does not query resources/marker on the profile pool.
    fs::write(log.parent().unwrap().join("fault-default"), "pool-offline").unwrap();
    let req = CreateSandboxRequest::for_test("sbx-1", "create");
    runtime.create_sandbox_on_storage(&req, &root).unwrap();
    runtime.create_sandbox_on_storage(&req, &root).unwrap();
    runtime
        .reconnect_sandbox_on_storage(&reconnect(&req), &root)
        .unwrap();
    fs::write(log.parent().unwrap().join("stopped-instance"), "").unwrap();
    runtime
        .reconnect_sandbox_on_storage(&reconnect(&req), &root)
        .unwrap();
    let bound = runtime
        .client()
        .bind_instance(
            &req.instance_name,
            &req.sandbox_id,
            &req.template_digest,
            None,
        )
        .unwrap();
    runtime
        .client()
        .with_root_disk(&root)
        .unwrap()
        .start(&bound, req.vm_size, &root)
        .unwrap();
    let text = fs::read_to_string(&log).unwrap();
    let init = text.lines().find(|s| s.starts_with("init ")).unwrap();
    assert!(
        init.contains("--storage pool-a --device rootfs,size=32GiB -- "),
        "{init}"
    );
    assert!(!init.contains("--device eth0"));
    assert_eq!(text.lines().filter(|s| s.starts_with("init ")).count(), 1);
    assert!(!text.contains("/storage-pools/default"));
}

#[test]
fn storage_drift_refuses_create_adoption_warm_cold_and_direct_start_before_mutation() {
    for fault in [
        "effective-pool",
        "effective-size",
        "local-pool",
        "local-size",
        "local-missing",
        "volume-size",
        "state-size-missing",
        "root-source",
        "missing-file",
    ] {
        let (runtime, log) = fixture();
        let root = root(&runtime, "pool-a");
        let req = CreateSandboxRequest::for_test("sbx-1", "create");
        runtime.create_sandbox_on_storage(&req, &root).unwrap();
        for stopped in [false, true] {
            if stopped {
                fs::write(log.parent().unwrap().join("stopped-instance"), "").unwrap();
            }
            fs::write(log.parent().unwrap().join("root-fault"), fault).unwrap();
            for path in ["create", "reconnect", "direct"] {
                fs::write(&log, "").unwrap();
                let failed = match path {
                    "create" => runtime.create_sandbox_on_storage(&req, &root).map(|_| ()),
                    "reconnect" => runtime
                        .reconnect_sandbox_on_storage(&reconnect(&req), &root)
                        .map(|_| ()),
                    _ => {
                        let bound = runtime
                            .client()
                            .bind_instance(
                                &req.instance_name,
                                &req.sandbox_id,
                                &req.template_digest,
                                None,
                            )
                            .unwrap();
                        runtime
                            .client()
                            .with_root_disk(&root)
                            .unwrap()
                            .start(&bound, req.vm_size, &root)
                            .map(|_| ())
                    }
                };
                assert!(failed.is_err(), "{fault} {path} {stopped}");
                no_mutation(&log);
            }
        }
    }
}

#[test]
fn storage_native_copy_failure_retains_orphan_and_cancelled_reads_never_prove_absence() {
    let (runtime, log) = fixture();
    let root = root(&runtime, "pool-a");
    fs::write(log.parent().unwrap().join("native-failure"), "ENOSPC").unwrap();
    let req = CreateSandboxRequest::for_test("sbx-1", "create");
    let error = runtime.create_sandbox_on_storage(&req, &root).unwrap_err();
    assert_eq!(
        error.state(),
        sandbox_protocol::OperationState::UnknownOutcome
    );
    assert_eq!(
        runtime.storage_root_census(&root.pool).unwrap().roots.len(),
        1
    );
    assert!(
        runtime
            .prove_root_absent(&root, &req.instance_name)
            .is_err()
    );
    let permit = std::sync::Arc::new(crate::RuntimePermit::default());
    permit.revoke();
    assert!(
        runtime
            .with_cancellation(permit)
            .prove_root_absent(&root, &req.instance_name)
            .is_err()
    );
    assert!(!log_invoked(&log, "start"));
}

#[test]
fn storage_marker_reads_have_deadline_and_output_bounds() {
    let (runtime, log) = fixture();
    let root = root(&runtime, "pool-a");
    fs::write(log.parent().unwrap().join("fault-pool-a"), "file-timeout").unwrap();
    let mut client = runtime.client().clone();
    client.agent_timeout = Duration::from_millis(100);
    let started = Instant::now();
    assert!(client.observe_storage_pool(&root.pool).is_err());
    assert!(started.elapsed() < Duration::from_secs(2));
}

const SCRIPT: &str = r#"#!/usr/bin/python3
import sys, json, pathlib, subprocess, time, os
from urllib.parse import urlsplit, parse_qs
base = pathlib.Path(__file__).parent
args = sys.argv[1:]
project = 'default'
if args[:1] == ['--project']:
    project, args = args[1], args[2:]
with (base/'incus.log').open('a') as log:
    log.write(' '.join(args)+'\n')
def text(name, default=''):
    p=base/name
    return p.read_text() if p.exists() else default
def obj(name, default):
    return json.loads(text(name, json.dumps(default)))
def emit(metadata, code=200):
    print(json.dumps({'type':'sync' if code==200 else 'error','status_code':code,'error_code':0 if code==200 else code,'metadata':metadata}))
    sys.exit(0)
def marker(pool):
    return base/('marker-'+pool+'.json')
def fault(pool):
    return text('fault-'+pool)
def delegate(argv):
    # Its log is separate, leaving one deterministic record per external call.
    out=subprocess.run([str(base/'delegate'),'--project',project,*argv],capture_output=True)
    return out
if args[:2] == ['project','list']:
    print('[{"name":"default"},{"name":"wssp"}]'); sys.exit(0)
if args[:1]==['profile'] and (base/'profile-extra.json').exists():
    out=delegate(args); profiles=json.loads(out.stdout)
    rn=text('profile-root-name','root'); profiles[0]['devices'][rn].update(obj('profile-extra.json',{}))
    print(json.dumps(profiles)); sys.exit(out.returncode)
if args[:1] == ['query']:
    url=next(a for a in args if a.startswith('/1.0'))
    path=urlsplit(url).path
    if path.startswith('/1.0/projects/'):
        emit(obj('project.json',{'config':{'features.profiles':'false','features.images':'false','features.storage.volumes':'true'}}))
    if path.startswith('/1.0/storage-pools/'):
        parts=path.split('/'); pool=parts[3]; tail='/'.join(parts[4:]); f=fault(pool)
        if f=='pool-offline': emit({},500)
        if f=='pool-missing': emit({},404)
        if f=='volumes-denied' and 'volumes' in tail: emit({},403)
        if tail=='': emit(obj('pool.json',{'driver':'dir','status':'Created','config':{}}))
        if tail=='resources': emit(obj('resources.json',{'space':{'total':1000*(1<<30),'used':800*(1<<30)}}))
        if tail=='volumes/custom' and 'POST' in args:
            body=json.loads(args[args.index('-d')+1]); mode=text('create-mode')
            if mode=='denied': emit({},403)
            if marker(pool).exists(): emit({},409)
            volume={k:body[k] for k in ['name','type','content_type','config']}
            if mode.startswith('conflict'): volume['config']['user.wssp.storage-id']='a'*32
            marker(pool).write_text(json.dumps(volume))
            if mode=='conflict': (base/('file-'+pool)).write_text('wssp-storage-v1\n'+'a'*32+'\n')
            if mode=='ambiguous': sys.exit(1)
            emit({},409 if mode.startswith('conflict') else 200)
        if tail=='volumes/custom/wssp-pool-marker':
            if f=='missing-volume': emit({},404)
            if not marker(pool).exists(): emit({},404)
            emit(json.loads(marker(pool).read_text()))
        if tail=='volumes':
            roots=obj('volumes.json',[])
            if ((base/'launched').exists() and not (base/'deleted-instance').exists()) or (base/'orphan').exists(): roots.append({'type':'virtual-machine','name':'wssp-sbx-sbx-1','config':{'size':text('disk-size','32GiB')}})
            if (base/'lose-during-census').exists(): (base/('fault-'+pool)).write_text('pool-offline')
            emit(roots)
        if tail.endswith('/state'):
            usage=obj('usage.json',{'usage':{'used':3*(1<<30),'total':32*(1<<30)}})
            if text('root-fault')=='volume-size': usage['usage']['total']=64*(1<<30)
            if text('root-fault')=='state-size-missing': usage['usage'].pop('total',None)
            emit(usage)
        if tail.startswith('volumes/virtual-machine/'):
            size=text('disk-size','32GiB')
            if text('root-fault')=='volume-size': size='64GiB'
            emit({'name':parts[-1],'type':'virtual-machine','content_type':'block','config':{}})
    # Delegate the real binding/readiness/network shims, then supply root evidence.
    # Avoid --project for query, which Incus forbids.
    out=subprocess.run([str(base/'delegate'),*args],capture_output=True)
    try:
        envelope=json.loads(out.stdout)
        if path.startswith('/1.0/instances/') and '/state' not in path and envelope.get('type')=='sync' and (base/'disk-size').exists():
            m=envelope['metadata']; rn=text('profile-root-name','root'); pool=text('disk-pool'); size=text('disk-size')
            r={'type':'disk','path':'/','pool':pool,'size':size}
            m['devices'][rn]=dict(r); m['expanded_devices'][rn]=dict(r)
            f=text('root-fault')
            if f=='effective-pool': m['expanded_devices'][rn]['pool']='wrong'
            if f=='effective-size': m['expanded_devices'][rn]['size']='64GiB'
            if f=='local-pool': m['devices'][rn]['pool']='wrong'
            if f=='local-size': m['devices'][rn]['size']='64GiB'
            if f=='local-missing': del m['devices'][rn]
            if f=='root-source': m['expanded_devices'][rn]['source']='/host/path'
            print(json.dumps(envelope)); sys.exit(out.returncode)
    except (ValueError,KeyError): pass
    sys.stdout.buffer.write(out.stdout); sys.stderr.buffer.write(out.stderr); sys.exit(out.returncode)
if args[:4]==['storage','volume','file','pull']:
    pool=args[4]; f=fault(pool)
    if f=='missing-file-751':
        print('Error: file does not exist', file=sys.stderr); sys.exit(1)
    if text('root-fault')=='missing-file' or f=='missing-file':
        print('Error: open /storage-id: no such file or directory', file=sys.stderr); sys.exit(1)
    if f=='file-denied':
        print('Error: permission denied', file=sys.stderr); sys.exit(1)
    if f=='file-flood': print('x'*4096); sys.exit(0)
    if f=='file-timeout': time.sleep(30); sys.exit(1)
    content=text('file-'+pool)
    if f=='malformed-file': content='invalid'
    if f=='different-file': content='wssp-storage-v1\n'+'b'*32+'\n'
    if f=='metadata-swap':
        m=json.loads(marker(pool).read_text()); m['config']['user.changed']=str(int(m['config'].get('user.changed','0'))+1); marker(pool).write_text(json.dumps(m))
    if not content: sys.exit(1)
    sys.stdout.write(content); sys.exit(0)
if args[:4]==['storage','volume','file','push']:
    if text('create-mode')=='push-denied': sys.exit(1)
    assert args[4:7]==['--mode','0600','-']
    (base/('file-'+args[7])).write_bytes(sys.stdin.buffer.read()); sys.exit(0)
if args[:1]==['init'] and '--storage' in args:
    pool=args[args.index('--storage')+1]; spec=args[args.index('--device')+1]
    (base/'disk-pool').write_text(pool); (base/'disk-size').write_text(spec.split('size=')[1])
    if (base/'native-failure').exists(): (base/'orphan').write_text(''); sys.exit(1)
    args=args[:]; i=args.index('--storage'); del args[i:i+2]; i=args.index('--device'); del args[i:i+2]
# Preserve live helper stdin/stdout handshakes rather than buffering them.
os.execv(str(base/'delegate'), [str(base/'delegate'),'--project',project,*args])
"#;

#[test]
fn storage_profile_root_extras_fail_before_vm_or_network_effects() {
    for extra in [
        json!({"source":"/host"}),
        json!({"readonly":"true"}),
        json!({"recursive":"true"}),
        json!({"shift":"true"}),
    ] {
        let (runtime, log) = fixture();
        let root = root(&runtime, "pool-a");
        write_json(&log, "profile-extra.json", extra);
        fs::write(&log, "").unwrap();
        assert!(
            runtime
                .create_sandbox_on_storage(
                    &CreateSandboxRequest::for_test("sbx-1", "create"),
                    &root
                )
                .is_err()
        );
        no_mutation(&log);
        assert!(!log.parent().unwrap().join("launched").exists());
    }
}

#[test]
fn storage_late_drift_is_rechecked_at_locked_adoption_and_running_completion() {
    for phase in ["before_existing_adoption", "before_existing_start"] {
        let (mut runtime, log) = fixture();
        let root = root(&runtime, "pool-a");
        let request = CreateSandboxRequest::for_test("sbx-1", "create");
        runtime.create_sandbox_on_storage(&request, &root).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        runtime.client_mut().create_barrier = Some((phase, barrier.clone()));
        let worker = std::thread::spawn(move || runtime.create_sandbox_on_storage(&request, &root));
        barrier.wait();
        fs::write(log.parent().unwrap().join("root-fault"), "volume-size").unwrap();
        fs::write(&log, "").unwrap();
        barrier.wait();
        assert_eq!(
            worker.join().unwrap().unwrap_err().code,
            sandbox_protocol::SandboxErrorCode::VmSizeMismatch
        );
        no_mutation(&log);
    }
}

#[test]
fn storage_delete_remains_available_for_size_conflict_but_requires_root_and_network_absence() {
    for orphan in [false, true] {
        let (runtime, log) = fixture();
        let root = root(&runtime, "pool-a");
        let req = CreateSandboxRequest::for_test("sbx-1", "create");
        runtime.create_sandbox_on_storage(&req, &root).unwrap();
        fs::write(log.parent().unwrap().join("root-fault"), "volume-size").unwrap();
        if orphan {
            fs::write(log.parent().unwrap().join("orphan"), "").unwrap();
        }
        let kill = crate::KillSandboxRequest {
            template_fingerprint: req.template_digest,
            sandbox_id: req.sandbox_id,
            instance_name: req.instance_name.clone(),
            operation_id: "destroy".into(),
            idempotency_key: "destroy".into(),
        };
        let result = runtime.kill_sandbox_on_storage(&kill, &root);
        assert_eq!(result.is_err(), orphan, "{result:?}");
        assert_eq!(
            runtime.prove_root_absent(&root, &req.instance_name).is_ok(),
            !orphan
        );
    }
}
