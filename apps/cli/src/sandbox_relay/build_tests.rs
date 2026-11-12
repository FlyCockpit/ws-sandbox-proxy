//! Lane-B e2e (D1: root only inside build VMs). The real relay workers,
//! journal and build gate over `FakeRuntime`: a build-kind record runs a
//! root step and the COPY helper; a normal sandbox refuses both, and a build
//! record refuses reconnect, signals and file IO other than its context put.

use super::{BuildBinding, gate};
use crate::sandbox_relay::authority::HostAuthority;
use crate::sandbox_relay::images::{ImageService, ImageSettings};
use crate::sandbox_relay::journal::unrecorded_intent_from_dispatch;
use crate::sandbox_relay::journal::{HostJournal, TransportBindingV11, intent_from_dispatch};
use crate::sandbox_relay::supervisor::{FinishedOp, RelaySupervisor};
use sandbox_protocol::{OperationDispatch, OperationState, SandboxErrorCode};
use sandbox_runtime::FakeRuntime;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

const CONTEXT: &str = "/var/tmp/wssp-build/build-1/context.tar";

fn fingerprint() -> String {
    sandbox_runtime::CreateSandboxRequest::for_test("sbx", "key").template_digest
}

struct Fixture {
    relay: RelaySupervisor,
    journal: Arc<HostJournal>,
    authority: HostAuthority,
    binding: TransportBindingV11,
    fake: FakeRuntime,
    finished: HashMap<String, FinishedOp>,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new(builder: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let binding = TransportBindingV11 {
            server: "wss://example".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let journal = Arc::new(
            crate::sandbox_relay::test_support::open_journal(dir.path().join("journal"), &binding)
                .unwrap(),
        );
        let fake = FakeRuntime::new();
        fake.fixture_root().unwrap();
        let authority = HostAuthority::default();
        let relay = RelaySupervisor::start(
            Arc::new(fake.clone()),
            journal.clone(),
            authority.clone(),
            #[cfg(target_os = "linux")]
            None,
        );
        let images = ImageService::start(
            Arc::new(fake.clone()),
            dir.path(),
            ImageSettings {
                size: crate::config::ImageCacheSize::Gib(1),
                accept_foreign: false,
                foreign_grace: Duration::ZERO,
                builder,
                accept_foreign_builds: false,
            },
            ureq::Agent::new_with_defaults(),
            "http://127.0.0.1:9",
            "wssp_host_test-secret",
        )
        .unwrap()
        .unwrap();
        assert_eq!(images.capabilities().build, builder);
        relay.install_images(images);
        Self {
            relay,
            journal,
            authority,
            binding,
            fake,
            finished: HashMap::new(),
            _dir: dir,
        }
    }

    fn dispatch(id: &str, kind: &str, sandbox: &str, extra: Value) -> OperationDispatch {
        let mut value = json!({
            "sandboxOwnerId": "creator", "operationId": id, "sandboxId": sandbox,
            "kind": kind, "generation": 1, "attempt": 1, "idempotencyKey": id,
            "bodyHash": "a".repeat(64), "templateDigest": fingerprint(),
            "incusFingerprint": fingerprint(), "architecture": "x86_64",
            "guestUid": 1000, "guestGid": 1000, "guestHome": "/home/user",
            "guestShell": "/bin/bash",
        });
        if matches!(kind, "sandbox.create" | "sandbox.reconnect") {
            value["cpuCount"] = json!(1);
            value["memoryMiB"] = json!(1024);
            value["lease"] = json!(sandbox_protocol::HostLease::for_test());
            value["allocation"] =
                serde_json::to_value(crate::sandbox_relay::test_support::allocation()).unwrap();
        }
        for (key, field) in extra.as_object().unwrap() {
            value[key] = field.clone();
        }
        // Every frame is the strict wire shape first.
        value["type"] = json!("operation.dispatch");
        let value = crate::sandbox_relay::test_support::current_control_fixture(value);
        match sandbox_protocol::parse_server_control(&value.to_string()) {
            Ok(sandbox_protocol::ServerControlMessage::OperationDispatch(d)) => *d,
            other => panic!("{id}: {other:?}"),
        }
    }

    /// The production order before the relay: durable intent, authority
    /// admission, then submission.
    fn run(&mut self, d: OperationDispatch) -> FinishedOp {
        let id = d.operation_id.clone();
        self.journal
            .record_fixture_intent(&intent_from_dispatch(&self.journal, &self.binding, &d))
            .unwrap();
        assert!(
            self.authority
                .accept_dispatch(&id, &d.sandbox_id, &d.kind, d.generation, d.attempt)
                .unwrap()
        );
        let upload = (d.kind == "file.put")
            .then(|| sandbox_runtime::FileContent::from_bytes(b"context").unwrap());
        let instance = sandbox_runtime::default_incus_instance_name(&d.sandbox_id);
        self.relay.submit(d, instance, upload).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            for frame in self.relay.poll_output().expect("encode output") {
                self.relay.ack_output(
                    frame.metadata.operation_id.clone(),
                    frame.metadata.generation,
                    frame.metadata.attempt,
                    frame.metadata.sequence,
                    frame.metadata.offset.unwrap_or(0) + frame.body_len() as u64,
                );
            }
            for op in self.relay.poll_finished() {
                if !op.interim {
                    self.finished.insert(op.operation_id.clone(), op);
                }
            }
            if let Some(op) = self.finished.remove(&id) {
                return op;
            }
            assert!(Instant::now() < deadline, "no completion for {id}");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn succeeds(&mut self, d: OperationDispatch) {
        let id = d.operation_id.clone();
        let done = self.run(d);
        assert_eq!(
            done.state,
            OperationState::Succeeded,
            "{id}: {:?}",
            done.error
        );
    }

    fn refused(&mut self, d: OperationDispatch, code: SandboxErrorCode) {
        let id = d.operation_id.clone();
        let done = self.run(d);
        assert_eq!(done.state, OperationState::Failed, "{id}");
        assert_eq!(done.error.map(|e| e.code), Some(code.into()), "{id}");
        assert!(
            self.fake.command_stdout(&id).is_none(),
            "{id} reached the runtime"
        );
    }
}

fn copy_body(context: &str) -> Value {
    json!({"buildCopy": {"contextPath": context, "sha256": "c".repeat(64),
        "src": ["app"], "dest": "/srv/app/", "owner": "user"}})
}

#[test]
fn build_record_runs_root_steps_and_copy_while_a_normal_sandbox_refuses_them() {
    let mut f = Fixture::new(true);
    let build = json!({"build": {"buildId": "build-1"}});
    f.succeeds(Fixture::dispatch(
        "create-b",
        "sandbox.create",
        "sbx-b",
        build,
    ));
    f.succeeds(Fixture::dispatch(
        "create-n",
        "sandbox.create",
        "sbx-n",
        json!({}),
    ));
    // The create journaled the binding; the normal sandbox has none.
    assert_eq!(
        f.journal.lease("sbx-b").unwrap().build_id.as_deref(),
        Some("build-1")
    );
    assert_eq!(f.journal.lease("sbx-n").unwrap().build_id, None);
    // B12 (E1-A-05): only the build VM's create asks for blocked-name hints.
    assert!(f.fake.created_with_refused_dns_hints("sbx-b"));
    assert!(!f.fake.created_with_refused_dns_hints("sbx-n"));

    // Root step and COPY on the build record reach the runtime as root.
    let root = json!({"argv": ["id", "-u"], "runAs": "root"});
    f.succeeds(Fixture::dispatch(
        "root-b",
        "command.run",
        "sbx-b",
        root.clone(),
    ));
    assert_eq!(
        f.fake.command_stdout("root-b").as_deref(),
        Some("exec:[root] id -u\n")
    );
    f.succeeds(Fixture::dispatch(
        "copy-b",
        "command.run",
        "sbx-b",
        copy_body(CONTEXT),
    ));
    assert_eq!(
        f.fake.command_stdout("copy-b").unwrap(),
        format!(
            "exec:[root] build-copy {CONTEXT} {} /srv/app/ 1000 1000 - app\n",
            "c".repeat(64)
        )
    );
    // A plain step in the build VM still runs as the declared guest user.
    let user = json!({"argv": ["id", "-u"]});
    f.succeeds(Fixture::dispatch("user-b", "command.run", "sbx-b", user));
    assert_eq!(
        f.fake.command_stdout("user-b").as_deref(),
        Some("exec:id -u\n")
    );
    // COPY reads only this build's own context.
    let other = copy_body("/var/tmp/wssp-build/build-2/context.tar");
    f.refused(
        Fixture::dispatch("copy-other", "command.run", "sbx-b", other),
        SandboxErrorCode::ProtocolError,
    );

    // A normal sandbox refuses both root forms before any effect.
    f.refused(
        Fixture::dispatch("root-n", "command.run", "sbx-n", root),
        SandboxErrorCode::ProtocolError,
    );
    f.refused(
        Fixture::dispatch("copy-n", "command.run", "sbx-n", copy_body(CONTEXT)),
        SandboxErrorCode::ProtocolError,
    );

    // The build record accepts its context upload and nothing else.
    f.succeeds(Fixture::dispatch(
        "put-context",
        "file.put",
        "sbx-b",
        json!({"path": CONTEXT}),
    ));
    f.refused(
        Fixture::dispatch("put-other", "file.put", "sbx-b", json!({"path": "/tmp/x"})),
        SandboxErrorCode::UnsupportedCapability,
    );
    f.refused(
        Fixture::dispatch("stat-b", "file.stat", "sbx-b", json!({"path": CONTEXT})),
        SandboxErrorCode::UnsupportedCapability,
    );
    // Reconnect is refused before any effect. The VM's pinned root is still
    // retained, so allocation accounting reports the refusal as unknown.
    let done = f.run(Fixture::dispatch(
        "reconnect-b",
        "sandbox.reconnect",
        "sbx-b",
        json!({}),
    ));
    assert!(
        matches!(
            done.state,
            OperationState::Failed | OperationState::UnknownOutcome
        ),
        "{:?}",
        done.state
    );
    assert_eq!(
        done.error.map(|e| e.code),
        Some(SandboxErrorCode::UnsupportedCapability.into())
    );
    // The normal sandbox keeps ordinary file IO.
    f.succeeds(Fixture::dispatch(
        "put-n",
        "file.put",
        "sbx-n",
        json!({"path": "/tmp/x"}),
    ));
}

#[test]
fn builder_off_refuses_build_creates_and_root_steps() {
    let mut f = Fixture::new(false);
    f.refused(
        Fixture::dispatch(
            "create-b",
            "sandbox.create",
            "sbx-b",
            json!({"build": {"buildId": "build-1"}}),
        ),
        SandboxErrorCode::UnsupportedCapability,
    );
    assert!(f.journal.lease("sbx-b").is_none());
    // A build record journaled while builds were on cannot run root steps
    // once this node opted out.
    let create = Fixture::dispatch(
        "seed-b",
        "sandbox.create",
        "sbx-s",
        json!({"build": {"buildId": "build-1"}}),
    );
    f.journal
        .record_fixture_intent(&intent_from_dispatch(&f.journal, &f.binding, &create))
        .unwrap();
    f.journal.accept_fixture_lease(&create).unwrap();
    let root = Fixture::dispatch(
        "root-s",
        "command.run",
        "sbx-s",
        json!({"argv": ["true"], "runAs": "root"}),
    );
    assert_eq!(
        gate(&f.journal, false, &root).unwrap_err().code,
        SandboxErrorCode::UnsupportedCapability
    );
    assert_eq!(
        gate(&f.journal, true, &root)
            .unwrap()
            .root
            .as_ref()
            .map(BuildBinding::build_id),
        Some("build-1")
    );
}

#[test]
fn the_build_binding_is_immutable_and_survives_renewal() {
    let f = Fixture::new(true);
    let create = Fixture::dispatch(
        "create-b",
        "sandbox.create",
        "sbx-b",
        json!({"build": {"buildId": "build-1"}}),
    );
    f.journal
        .record_fixture_intent(&intent_from_dispatch(&f.journal, &f.binding, &create))
        .unwrap();
    f.journal.accept_fixture_lease(&create).unwrap();
    // A later create of the same sandbox may not rebind or drop the build.
    for (id, extra) in [
        ("create-2", json!({"build": {"buildId": "build-2"}})),
        ("create-3", json!({})),
    ] {
        let mut again = Fixture::dispatch(id, "sandbox.create", "sbx-b", extra);
        again.generation = 2;
        let mut lease = again.lease.clone().unwrap();
        lease.revision += 1;
        again.lease = Some(lease);
        f.journal
            .record_fixture_intent(&intent_from_dispatch(&f.journal, &f.binding, &again))
            .unwrap();
        let error = f
            .journal
            .accept_fixture_lease(&again)
            .unwrap_err()
            .to_string();
        assert!(error.contains("build binding differs"), "{id}: {error}");
    }
    // The receipt binds the build fields: the same operation id with a
    // different build is a different request.
    let mut changed = create.clone();
    changed.build = Some(sandbox_protocol::DispatchBuildV11 {
        build_id: "build-9".into(),
        bootstrap: false,
    });
    assert_ne!(
        unrecorded_intent_from_dispatch(&f.binding, &create).body_hash,
        unrecorded_intent_from_dispatch(&f.binding, &changed).body_hash
    );
    assert_eq!(
        f.journal.lease("sbx-b").unwrap().build_id.as_deref(),
        Some("build-1")
    );
}

/// A dispatch that skips the wire validation (the gate's own defence).
fn unchecked(extra: Value) -> OperationDispatch {
    let mut value = json!({
        "sandboxOwnerId": "creator", "operationId": "op-x", "sandboxId": "sbx-x",
        "kind": "sandbox.create", "generation": 1, "attempt": 1, "idempotencyKey": "op-x",
    });
    for (key, field) in extra.as_object().unwrap() {
        value[key] = field.clone();
    }
    serde_json::from_value(value).unwrap()
}

/// Community bases: `build.bootstrap` yields bootstrap readiness for the
/// create that carries it (builds enabled), and nothing else. An upstream
/// image plan without it, or bootstrap on any other kind, is refused.
#[test]
fn bootstrap_readiness_comes_only_from_a_bootstrap_build_create() {
    use sandbox_runtime::ReadinessMode;
    let f = Fixture::new(true);
    let bootstrap = json!({"build": {"buildId": "build-1", "bootstrap": true}});
    let create = Fixture::dispatch("c", "sandbox.create", "sbx-c", bootstrap.clone());
    let proof = gate(&f.journal, true, &create).unwrap();
    assert_eq!(proof.readiness, ReadinessMode::BuildBootstrap);
    assert!(proof.root.is_none(), "bootstrap grants no root step (D1)");
    let plain = Fixture::dispatch(
        "p",
        "sandbox.create",
        "sbx-p",
        json!({"build": {"buildId": "build-1"}}),
    );
    assert_eq!(
        gate(&f.journal, true, &plain).unwrap().readiness,
        ReadinessMode::Standard
    );
    // Builds disabled: the bootstrap create is refused like any build create.
    assert_eq!(
        gate(&f.journal, false, &create).unwrap_err().code,
        SandboxErrorCode::UnsupportedCapability
    );
    // Bootstrap on a reconnect (never valid on the wire) is refused here too.
    let mut reconnect = unchecked(bootstrap);
    reconnect.kind = "sandbox.reconnect".into();
    assert_eq!(
        gate(&f.journal, true, &reconnect).unwrap_err().code,
        SandboxErrorCode::ProtocolError
    );
    // An upstream image plan without bootstrap (defence in depth).
    let upstream = json!({"image": {
        "fingerprint": format!("sha256:{}", "3".repeat(64)),
        "sizeBytes": 2048, "format": "split", "source": "upstream",
        "upstream": {
            "metaPath": "images/u/incus.tar.xz", "metaSha256": "1".repeat(64), "metaSize": 1024,
            "diskPath": "images/u/disk.qcow2", "diskSha256": "2".repeat(64), "diskSize": 1024,
        },
    }});
    for build in [json!(null), json!({"buildId": "build-1"})] {
        let mut extra = upstream.clone();
        if !build.is_null() {
            extra["build"] = build;
        }
        assert_eq!(
            gate(&f.journal, true, &unchecked(extra)).unwrap_err().code,
            SandboxErrorCode::ProtocolError
        );
    }
}

/// End to end on the fake: a raw upstream guest (1000:1001, no /home/user)
/// becomes READY only through a bootstrap build create; a non-bootstrap
/// build create of the same image is GuestUnavailable (I12 backstop).
#[test]
fn a_raw_upstream_guest_is_ready_only_in_its_bootstrap_build_vm() {
    let mut f = Fixture::new(true);
    f.fake.set_image_guest(
        &fingerprint(),
        sandbox_runtime::raw_upstream_identity(),
        true,
    );
    let done = f.run(Fixture::dispatch(
        "plain",
        "sandbox.create",
        "sbx-plain",
        json!({"build": {"buildId": "build-1"}}),
    ));
    assert_eq!(done.state, OperationState::Failed);
    assert_eq!(
        done.error.map(|e| e.code),
        Some(SandboxErrorCode::GuestUnavailable.into())
    );
    f.succeeds(Fixture::dispatch(
        "boot",
        "sandbox.create",
        "sbx-boot",
        json!({"build": {"buildId": "build-2", "bootstrap": true}}),
    ));
}
