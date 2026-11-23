//! C8a daemon-level e2e through the real connect loop with FakeRuntime: a
//! create carrying `credentialSpec` fetches the spec before any VM effect,
//! installs the bundle after readiness, and sends `credential.installed`
//! before its READY result; after a daemon restart the census is followed by
//! `bundle.request{restore_env}`, and a command then sees the env again.
//! A sentinel check proves no credential plaintext is at rest.

use super::*;
use crate::sandbox_relay::credentials::transfer::{definition_for, digest_bytes};
use login_definition::{Bundle, BundleEnv, BundleFile, BundleFileKind, encode_bundle};
use sandbox_protocol::{
    BundleRequestReason, CREDENTIAL_CHUNK_RAW_BYTES, CredentialDelivery, CredentialLeaseKind,
    CredentialRotates, CredentialSpecV11, SpecFilesV11, SpecLeaseAction, SpecLeaseV11,
    encode_chunk_data, parse_daemon_control,
};
use std::net::{TcpListener, TcpStream};

type Wire = tungstenite::WebSocket<TcpStream>;

const SANDBOX: &str = "sbx-cred";
const FILE: &str = ".config/tool/hosts.yml";
const SENTINEL: &str = "SENTINEL-CREDENTIAL-VALUE-e2e9";
const FILE_SENTINEL: &[u8] = b"token: SENTINEL-FILE-e2e9";
const FP: &str = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

fn lease() -> SpecLeaseV11 {
    SpecLeaseV11 {
        lease_id: "lease-1".into(),
        binding_id: None,
        credential_id: "cred-1".into(),
        instance_id: "inst-1".into(),
        definition_digest: "ab".repeat(32),
        max_bytes: 4096,
        delivery: CredentialDelivery::Guest,
        exclusive: true,
        copy_back: true,
        rotates: CredentialRotates::Unknown,
        kind: CredentialLeaseKind::Workload,
        action: SpecLeaseAction::Inject,
        files: SpecFilesV11 {
            required: vec![".config/tool".into()],
            optional: vec![],
            exclude: vec![],
        },
        env: vec!["TOOL_TOKEN".into()],
        proxy: vec![],
        checkpoint_interval_min: None,
    }
}

fn spec_bytes() -> Vec<u8> {
    let spec = CredentialSpecV11 {
        version: 1,
        sandbox_id: SANDBOX.into(),
        sandbox_owner_id: "owner-1".into(),
        host_owner_id: "owner-1".into(),
        leases: vec![lease()],
        residue: vec![],
    };
    json!(spec).to_string().into_bytes()
}

fn bundle(files: bool) -> Vec<u8> {
    let lease = lease();
    let def = definition_for(&lease).unwrap();
    let mut entries = Vec::new();
    if files {
        entries.push(BundleFile {
            kind: BundleFileKind::Dir,
            path: ".config/tool",
            mode: 0o700,
            data: b"",
        });
        entries.push(BundleFile {
            kind: BundleFileKind::File,
            path: FILE,
            mode: 0o600,
            data: FILE_SENTINEL,
        });
    }
    let bundle = Bundle {
        definition_digest: digest_bytes(&lease.definition_digest).unwrap(),
        files: entries,
        env: vec![BundleEnv {
            name: "TOOL_TOKEN",
            value: SENTINEL.as_bytes(),
        }],
    };
    encode_bundle(&bundle, &def).unwrap().as_bytes().to_vec()
}

fn options(dir: &std::path::Path, address: std::net::SocketAddr) -> ConnectOptions {
    ConnectOptions {
        host_terminal: None,
        server_url: format!("ws://{address}"),
        host_token: "test-only-token".into(),
        host_id: "host-1".into(),
        label: "test".into(),
        runtime: HostRuntimeKind::Fake,
        incus_project: None,
        state_dir: Some(dir.into()),
        heartbeat: Duration::from_secs(30),
        sandbox_memory_mib: None,
        max_sandbox_cpu_count: None,
        sandbox_vcpu_budget: Some(4),
        max_concurrent_commands: 16,
        shutdown: Default::default(),
    }
}

fn send(wire: &mut Wire, value: serde_json::Value) {
    wire.send(Message::Text(value.to_string().into()))
        .expect("send");
}

/// Accepts the daemon, checks the hello advertises credentials, registers it
/// and answers the reconciliation and credential census.
fn register(listener: &TcpListener, address: std::net::SocketAddr) -> Wire {
    let (tcp, _) = listener.accept().expect("accept");
    register_stream(tcp, address)
}

fn register_stream(tcp: TcpStream, address: std::net::SocketAddr) -> Wire {
    tcp.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    let mut wire = tungstenite::accept_hdr(tcp, super::tests::RelayHandshake).expect("handshake");
    let hello = wire.read().expect("hello");
    match parse_daemon_control(hello.to_text().expect("text")).expect("parse") {
        DaemonControlMessage::Hello { daemon, .. } => {
            let caps = daemon
                .capabilities
                .credentials
                .expect("credential capability");
            assert!(caps.files && caps.env && caps.spec_transfer && caps.sealed_return);
        }
        other => panic!("expected hello, got {other:?}"),
    }
    crate::sandbox_relay::test_support::send_sized_hello(
        &mut wire,
        &TransportBindingV11 {
            server: format!("ws://{address}/ws/sandbox-host"),
            host_owner_id: "owner-1".into(),
            host_id: "host-1".into(),
        },
    );
    wire
}

/// Plays the server until `done` says stop; returns every credential frame
/// kind seen, in order, with `operation.result`s interleaved.
fn serve(wire: &mut Wire, done: impl FnMut(&DaemonControlMessage) -> bool) -> Vec<String> {
    serve_acking(wire, &json!({"outcome":"committed"}), done)
}

/// [`serve`], answering every uploaded capture with `ack` (`outcome` and
/// optional `reason`) once its last chunk arrives.
fn serve_acking(
    wire: &mut Wire,
    ack: &serde_json::Value,
    mut done: impl FnMut(&DaemonControlMessage) -> bool,
) -> Vec<String> {
    let mut seen = Vec::new();
    let mut captures: std::collections::HashMap<String, u32> = Default::default();
    loop {
        let frame = wire.read().expect("frame");
        let Ok(text) = frame.to_text() else { continue };
        let message = parse_daemon_control(text).expect("control");
        match &message {
            DaemonControlMessage::SandboxInventory { page, entries, .. } => send(
                wire,
                json!({"type":"inventory.ack","page":page,"entryResults": entries.iter().map(|entry| json!({"sandboxId":entry.sandbox_id,"outcome":"converged"})).collect::<Vec<_>>()}),
            ),
            DaemonControlMessage::OperationReceipt { operation_id, .. }
            | DaemonControlMessage::OperationReceiptPruned { operation_id, .. } => send(
                wire,
                json!({"type":"receipt.ack","operationId":operation_id}),
            ),
            DaemonControlMessage::DispatchAuditRequest { page } => send(
                wire,
                json!({"type":"dispatch.audit.page","page":page,"complete":true,"entries":[]}),
            ),
            DaemonControlMessage::CredentialCensus(page) => {
                seen.push("census".into());
                send(
                    wire,
                    json!({"type":"credential.census.ack","page":page.page}),
                );
            }
            DaemonControlMessage::CredentialSpecRequest(request) => {
                seen.push("spec.request".into());
                for (seq, chunk) in spec_bytes().chunks(CREDENTIAL_CHUNK_RAW_BYTES).enumerate() {
                    send(
                        wire,
                        json!({"type":"credential.spec.chunk","operationId":request.operation_id,
                            "seq":seq,"data":encode_chunk_data(chunk)}),
                    );
                }
            }
            DaemonControlMessage::CredentialBundleRequest(request) => {
                let install = request.reason == BundleRequestReason::Install;
                seen.push(if install {
                    "bundle.install".into()
                } else {
                    "bundle.restore_env".into()
                });
                assert_eq!(request.lease_id, "lease-1");
                let bytes = bundle(install);
                let chunks: Vec<&[u8]> = bytes.chunks(CREDENTIAL_CHUNK_RAW_BYTES).collect();
                send(
                    wire,
                    json!({"type":"credential.bundle.begin","requestId":request.request_id,
                        "bindingId":"bind-1","storageSeq":1,"fileCount":if install {2} else {0},
                        "envCount":1,"bundleLen":bytes.len(),"chunkCount":chunks.len()}),
                );
                for (seq, chunk) in chunks.into_iter().enumerate() {
                    send(
                        wire,
                        json!({"type":"credential.bundle.chunk","requestId":request.request_id,
                            "seq":seq,"data":encode_chunk_data(chunk)}),
                    );
                }
            }
            DaemonControlMessage::CredentialCaptureBegin(begin) => {
                seen.push("capture.begin".into());
                captures.insert(begin.capture_id.clone(), begin.chunk_count);
            }
            DaemonControlMessage::CredentialCaptureChunk(chunk) => {
                if captures.get(&chunk.capture_id) == Some(&(chunk.seq + 1)) {
                    let mut frame = ack.clone();
                    frame["type"] = json!("credential.capture.ack");
                    frame["captureId"] = json!(chunk.capture_id);
                    send(wire, frame);
                }
            }
            DaemonControlMessage::CredentialScrubbed(scrubbed) => {
                assert!(scrubbed.verified_absent);
                seen.push("scrubbed".into());
            }
            DaemonControlMessage::CredentialReturnKeyAck(_) => seen.push("return.key.ack".into()),
            DaemonControlMessage::CredentialInstalled(installed) => {
                assert_eq!(
                    (installed.binding_id.as_str(), installed.storage_seq),
                    ("bind-1", 1)
                );
                seen.push("installed".into());
            }
            DaemonControlMessage::OperationResult {
                operation_id,
                state,
                ..
            } => seen.push(format!("result:{operation_id}:{state:?}")),
            _ => {}
        }
        if done(&message) {
            return seen;
        }
    }
}

fn create_dispatch() -> serde_json::Value {
    let spec = spec_bytes();
    crate::sandbox_relay::test_support::current_control_fixture(
        json!({"sandboxOwnerId":"owner-1", "type":"operation.dispatch", "operationId":"create",
        "sandboxId":SANDBOX, "kind":"sandbox.create", "idempotencyKey":"create",
        "bodyHash":"a".repeat(64), "lease":sandbox_protocol::HostLease::for_test(),
        "generation":1, "attempt":1, "templateDigest":FP, "incusFingerprint":FP,
        "architecture":"x86_64", "cpuCount":1, "memoryMiB":1024,
        "allocation": crate::sandbox_relay::test_support::allocation(),
        "credentialSpec": {"digest": crate::sandbox_relay::journal::sha256_hex(&spec),
            "bytes": spec.len()}}),
    )
}

fn every_file_under(dir: &std::path::Path) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let Ok(items) = std::fs::read_dir(dir) else {
        return out;
    };
    for item in items {
        let path = item.unwrap().path();
        if path.is_dir() {
            out.extend(every_file_under(&path));
        } else if let Ok(bytes) = std::fs::read(path) {
            out.push(bytes);
        }
    }
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn create_with_login_installs_before_ready_and_restart_reinstalls_env() {
    let _staging = crate::sandbox_relay::test_support::staging_quota();
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let address = listener.local_addr().expect("address");
    let fake = sandbox_runtime::FakeRuntime::new();
    fake.fixture_root().unwrap();

    // --- first daemon: create with a login ---------------------------------
    let opts = options(dir.path(), address);
    let shutdown = opts.shutdown.clone();
    let daemon_fake = fake.clone();
    let client = thread::spawn(move || {
        run_connect_with_credentials(&opts, |_| Ok((Box::new(daemon_fake), None)))
    });
    let mut wire = register(&listener, address);
    serve(
        &mut wire,
        |m| matches!(m, DaemonControlMessage::CredentialCensus(p) if p.complete),
    );
    send(&mut wire, create_dispatch());
    let (seen, result) = result_of(&mut wire, &json!({"outcome":"committed"}), "create");
    assert_eq!(
        seen,
        vec![
            "spec.request",
            "bundle.install",
            "installed",
            "result:create:Succeeded"
        ],
        "install happens before READY and its frame precedes the result"
    );
    // The journaled READY receipt repeats the report, so a replay after the
    // frame was lost with its socket still proves the install.
    let DaemonControlMessage::OperationResult { result, .. } = result else {
        unreachable!()
    };
    let installed = &result.expect("result payload")["credentialInstalled"];
    assert_eq!(
        (&installed[0]["bindingId"], &installed[0]["storageSeq"]),
        (&json!("bind-1"), &json!(1))
    );
    assert_eq!(
        fake.guest_file(SANDBOX, FILE).as_deref(),
        Some(FILE_SENTINEL)
    );

    // A command sees the credential env (memory only).
    send(
        &mut wire,
        crate::sandbox_relay::test_support::current_control_fixture(
            json!({"sandboxOwnerId":"owner-1", "type":"operation.dispatch", "operationId":"cmd-1",
            "sandboxId":SANDBOX, "kind":"command.run", "resultVersion":1, "processId":"proc-cmd-1", "incusFingerprint":FP, "generation":1,
            "attempt":1, "idempotencyKey":"cmd-1", "bodyHash":"a".repeat(64), "argv":["env"]}),
        ),
    );
    let output = command_output(&mut wire, "cmd-1");
    assert!(
        output.contains(&format!("TOOL_TOKEN={SENTINEL}")),
        "{output}"
    );

    shutdown.request();
    while wire.read().is_ok_and(|f| !matches!(f, Message::Close(_))) {}
    drop(wire);
    client.join().unwrap().unwrap();
    for bytes in every_file_under(dir.path()) {
        assert!(!contains(&bytes, SENTINEL.as_bytes()), "env value at rest");
        assert!(!contains(&bytes, FILE_SENTINEL), "file value at rest");
    }

    // --- daemon restart: census, then restore_env -----------------------------
    // Restart the daemon, not the fake daemon: the old runtime's lifecycle
    // authority (which owns the journal lock) is discarded as process exit
    // would discard it; guest state and the running VM survive.
    let daemon = fake.restart_policy_reconciler().unwrap();
    drop(fake);
    let fake = daemon;
    // A forked child may still share the lock for a moment: retry briefly.
    let deadline = Instant::now() + Duration::from_secs(60);
    listener.set_nonblocking(true).unwrap();
    let (shutdown, client, tcp) = 'restart: loop {
        let opts = options(dir.path(), address);
        let shutdown = opts.shutdown.clone();
        let daemon_fake = fake.clone();
        let client = thread::spawn(move || {
            run_connect_with_credentials(&opts, |_| Ok((Box::new(daemon_fake), None)))
        });
        loop {
            match listener.accept() {
                Ok((tcp, _)) => break 'restart (shutdown, client, tcp),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("accept: {e}"),
            }
            if client.is_finished() {
                let outcome = client.join().unwrap();
                assert!(
                    Instant::now() < deadline,
                    "restarted daemon could not start: {outcome:?}"
                );
                thread::sleep(Duration::from_millis(200));
                continue 'restart;
            }
            thread::sleep(Duration::from_millis(20));
        }
    };
    tcp.set_nonblocking(false).unwrap();
    let mut wire = register_stream(tcp, address);
    let seen = serve(&mut wire, |m| {
        matches!(m, DaemonControlMessage::CredentialBundleRequest(r)
            if r.reason == BundleRequestReason::RestoreEnv)
    });
    assert_eq!(seen.last().map(String::as_str), Some("bundle.restore_env"));
    assert!(seen.contains(&"census".to_owned()));
    send(
        &mut wire,
        crate::sandbox_relay::test_support::current_control_fixture(
            json!({"sandboxOwnerId":"owner-1", "type":"operation.dispatch", "operationId":"cmd-2",
            "sandboxId":SANDBOX, "kind":"command.run", "resultVersion":1, "processId":"proc-cmd-2", "incusFingerprint":FP, "generation":1,
            "attempt":1, "idempotencyKey":"cmd-2", "bodyHash":"a".repeat(64), "argv":["env"]}),
        ),
    );
    let output = command_output(&mut wire, "cmd-2");
    assert!(
        output.contains(&format!("TOOL_TOKEN={SENTINEL}")),
        "{output}"
    );
    // The restore never rewrote guest files.
    assert_eq!(
        fake.credential_calls()
            .iter()
            .filter(|(op, _)| op == "restore")
            .count(),
        1
    );
    shutdown.request();
    while wire.read().is_ok_and(|f| !matches!(f, Message::Close(_))) {}
    drop(wire);
    client.join().unwrap().unwrap();
    for bytes in every_file_under(dir.path()) {
        assert!(!contains(&bytes, SENTINEL.as_bytes()), "env value at rest");
        assert!(!contains(&bytes, FILE_SENTINEL), "file value at rest");
    }
}

/// Collects a command's stdout until its result.
fn command_output(wire: &mut Wire, id: &str) -> String {
    let mut out = Vec::new();
    loop {
        match wire.read().expect("frame") {
            Message::Binary(bytes) => {
                if let Ok((meta, body)) = parse_binary_frame(&bytes)
                    && meta.operation_id == id
                {
                    out.extend_from_slice(&body);
                }
            }
            Message::Text(text) => match parse_daemon_control(&text).expect("control") {
                DaemonControlMessage::OperationResult {
                    operation_id,
                    state,
                    error,
                    ..
                } if operation_id == id => {
                    assert_eq!(state, OperationState::Succeeded, "{error:?}");
                    return String::from_utf8_lossy(&out).into_owned();
                }
                DaemonControlMessage::OperationReceipt { operation_id, .. } => send(
                    wire,
                    json!({"type":"receipt.ack","operationId":operation_id}),
                ),
                DaemonControlMessage::CredentialCensus(page) => send(
                    wire,
                    json!({"type":"credential.census.ack","page":page.page}),
                ),
                _ => {}
            },
            _ => {}
        }
    }
}

fn dispatch(id: &str, kind: &str, generation: u64) -> serde_json::Value {
    crate::sandbox_relay::test_support::current_control_fixture(
        json!({"sandboxOwnerId":"owner-1", "type":"operation.dispatch", "operationId":id,
        "sandboxId":SANDBOX, "kind":kind, "idempotencyKey":id, "bodyHash":"a".repeat(64),
        "generation":generation, "attempt":1, "incusFingerprint":FP,
        "allocation": crate::sandbox_relay::test_support::allocation()}),
    )
}

/// A fresh X25519 return key frame (public material only).
fn return_key() -> serde_json::Value {
    let rng = ring::rand::SystemRandom::new();
    let private =
        ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::X25519, &rng).unwrap();
    let bytes: [u8; 32] = private
        .compute_public_key()
        .unwrap()
        .as_ref()
        .try_into()
        .unwrap();
    let public =
        crate::sandbox_relay::credentials::seal::ReturnPublicKey::from_bytes(bytes).unwrap();
    json!({"type":"credential.return.key","kidR":public.kid_r(),"epoch":1,
        "publicKey":public.to_base64url(),"serverOrigin":"https://wssp.example.com"})
}

/// Waits for `id`'s result and returns it.
fn result_of(
    wire: &mut Wire,
    ack: &serde_json::Value,
    id: &str,
) -> (Vec<String>, DaemonControlMessage) {
    let mut last = None;
    let seen = serve_acking(wire, ack, |m| {
        let hit = matches!(m, DaemonControlMessage::OperationResult { operation_id, .. } if operation_id == id);
        if hit {
            last = Some(m.clone());
        }
        hit
    });
    (seen, last.unwrap())
}

/// C8b-daemon lane e2e through the real connect loop: create with a login →
/// the guest rotates its token → a user stop whose capture is REJECTED is
/// refused (`credential_capture_failed`) after the host lease row is
/// re-bound, so a `command.run` at the stop's generation runs with the
/// login env; the next stop captures again, commits, scrubs and succeeds
/// with `credentialOutcomes` on its result. No plaintext at rest.
#[test]
fn stop_captures_and_a_refused_stop_keeps_the_sandbox_usable() {
    let _staging = crate::sandbox_relay::test_support::staging_quota();
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let address = listener.local_addr().expect("address");
    let fake = sandbox_runtime::FakeRuntime::new();
    fake.fixture_root().unwrap();
    let opts = options(dir.path(), address);
    let shutdown = opts.shutdown.clone();
    let daemon_fake = fake.clone();
    let client = thread::spawn(move || {
        run_connect_with_credentials(&opts, |_| Ok((Box::new(daemon_fake), None)))
    });
    let mut wire = register(&listener, address);
    serve(
        &mut wire,
        |m| matches!(m, DaemonControlMessage::CredentialCensus(p) if p.complete),
    );
    send(&mut wire, create_dispatch());
    serve(
        &mut wire,
        |m| matches!(m, DaemonControlMessage::OperationResult { operation_id, .. } if operation_id == "create"),
    );
    send(&mut wire, return_key());
    let seen = serve(
        &mut wire,
        |m| matches!(m, DaemonControlMessage::CredentialCensus(p) if p.complete),
    );
    assert_eq!(seen.first().map(String::as_str), Some("return.key.ack"));
    const ROTATED: &[u8] = b"token: ROTATED-IN-THE-GUEST-e2e9";
    fake.set_guest_file(SANDBOX, FILE, ROTATED);

    // A REJECTED capture refuses the user stop; the VM keeps running.
    send(&mut wire, dispatch("stop-1", "sandbox.stop", 2));
    let rejected = json!({"outcome":"rejected","reason":"context_mismatch"});
    let (seen, result) = result_of(&mut wire, &rejected, "stop-1");
    assert_eq!(seen, vec!["capture.begin", "result:stop-1:Failed"]);
    let DaemonControlMessage::OperationResult { error, .. } = result else {
        unreachable!()
    };
    assert_eq!(
        error.and_then(|e| e.code.known()),
        Some(sandbox_protocol::SandboxErrorCode::CredentialCaptureFailed)
    );
    assert_eq!(fake.guest_file(SANDBOX, FILE).as_deref(), Some(ROTATED));
    // The server returns the sandbox to READY at generation 2; ordinary work
    // at that generation is admitted and still sees the login env.
    send(
        &mut wire,
        crate::sandbox_relay::test_support::current_control_fixture(
            json!({"sandboxOwnerId":"owner-1", "type":"operation.dispatch", "operationId":"cmd-2",
            "sandboxId":SANDBOX, "kind":"command.run", "resultVersion":1, "processId":"proc-cmd-2", "incusFingerprint":FP, "generation":2,
            "attempt":1, "idempotencyKey":"cmd-2", "bodyHash":"a".repeat(64), "argv":["env"]}),
        ),
    );
    let output = command_output(&mut wire, "cmd-2");
    assert!(
        output.contains(&format!("TOOL_TOKEN={SENTINEL}")),
        "{output}"
    );

    // The next stop opens a new attempt, captures, commits, scrubs, stops.
    send(&mut wire, dispatch("stop-2", "sandbox.stop", 3));
    let (seen, result) = result_of(&mut wire, &json!({"outcome":"committed"}), "stop-2");
    assert_eq!(
        seen,
        vec!["capture.begin", "scrubbed", "result:stop-2:Succeeded"]
    );
    let DaemonControlMessage::OperationResult { result, .. } = result else {
        unreachable!()
    };
    let outcomes = &result.expect("result payload")["credentialOutcomes"];
    assert_eq!(outcomes[0]["bindingId"], "bind-1");
    assert_eq!(outcomes[0]["capture"]["status"], "acked");
    assert_eq!(outcomes[0]["capture"]["outcome"], "committed");
    assert_eq!(outcomes[0]["scrub"], "verified");
    assert!(fake.guest_file(SANDBOX, FILE).is_none());

    shutdown.request();
    while wire.read().is_ok_and(|f| !matches!(f, Message::Close(_))) {}
    drop(wire);
    client.join().unwrap().unwrap();
    for bytes in every_file_under(dir.path()) {
        assert!(!contains(&bytes, SENTINEL.as_bytes()), "env value at rest");
        assert!(!contains(&bytes, FILE_SENTINEL), "file value at rest");
        assert!(!contains(&bytes, ROTATED), "rotated value at rest");
    }
}

/// Live attach through the real connect loop: the attach result repeats the
/// `installed` report as `credentialInstalled`, so a result replayed after
/// the frame was lost with its socket still proves the install.
#[test]
fn live_attach_result_repeats_the_installed_report() {
    let _staging = crate::sandbox_relay::test_support::staging_quota();
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let address = listener.local_addr().expect("address");
    let fake = sandbox_runtime::FakeRuntime::new();
    fake.fixture_root().unwrap();
    let opts = options(dir.path(), address);
    let shutdown = opts.shutdown.clone();
    let daemon_fake = fake.clone();
    let client = thread::spawn(move || {
        run_connect_with_credentials(&opts, |_| Ok((Box::new(daemon_fake), None)))
    });
    let mut wire = register(&listener, address);
    serve(
        &mut wire,
        |m| matches!(m, DaemonControlMessage::CredentialCensus(p) if p.complete),
    );
    // A create without a login, then a live attach of one.
    let mut create = create_dispatch();
    create.as_object_mut().unwrap().remove("credentialSpec");
    send(&mut wire, create);
    let (seen, _) = result_of(&mut wire, &json!({"outcome":"committed"}), "create");
    assert_eq!(seen, vec!["result:create:Succeeded"]);
    let spec = spec_bytes();
    let mut attach = dispatch("attach", "credential.attach", 1);
    attach.as_object_mut().unwrap().remove("allocation");
    attach["credentialSpec"] = json!({"digest": crate::sandbox_relay::journal::sha256_hex(&spec),
        "bytes": spec.len()});
    send(&mut wire, attach);
    let (seen, result) = result_of(&mut wire, &json!({"outcome":"committed"}), "attach");
    assert_eq!(
        seen,
        vec![
            "spec.request",
            "bundle.install",
            "installed",
            "result:attach:Succeeded"
        ],
        "{result:?}"
    );
    let DaemonControlMessage::OperationResult { result, .. } = result else {
        unreachable!()
    };
    let result = result.expect("result payload");
    assert_eq!(result["state"], "attached");
    let installed = &result["credentialInstalled"];
    assert_eq!(
        (
            &installed[0]["leaseId"],
            &installed[0]["bindingId"],
            &installed[0]["storageSeq"]
        ),
        (&json!("lease-1"), &json!("bind-1"), &json!(1))
    );

    shutdown.request();
    while wire.read().is_ok_and(|f| !matches!(f, Message::Close(_))) {}
    drop(wire);
    client.join().unwrap().unwrap();
}
