//! Helpers shared by tests that run concurrently in one libtest process.

use std::sync::{Mutex, MutexGuard};

/// `sandbox_runtime` charges every transfer capture against one process-wide
/// quota of four active slots, and libtest runs tests on parallel threads. A
/// test that creates charged captures (directly, or by driving uploads and
/// guest reads through the relay) holds this guard for its whole body so
/// concurrent tests cannot exhaust its slots.
pub(crate) fn staging_quota() -> MutexGuard<'static, ()> {
    static QUOTA: Mutex<()> = Mutex::new(());
    QUOTA.lock().unwrap_or_else(|err| err.into_inner())
}

/// Plays the server side of the post-hello census: acknowledges every
/// `sandbox.inventory` page, returns the entries once `reconcile.complete`
/// arrives. Receipts and heartbeats are acknowledged or ignored.
pub(crate) fn ack_reconciliation<S: std::io::Read + std::io::Write>(
    wire: &mut tungstenite::WebSocket<S>,
) -> Vec<sandbox_protocol::InventoryEntry> {
    use sandbox_protocol::{DaemonControlMessage, parse_daemon_control};
    let mut census = Vec::new();
    loop {
        let frame = wire.read().expect("reconciliation frame");
        let Ok(text) = frame.to_text() else { continue };
        match parse_daemon_control(text).expect("parse") {
            DaemonControlMessage::SandboxInventory { page, entries, .. } => {
                let entry_results: Vec<_> = entries.iter().map(|entry| serde_json::json!({"sandboxId":entry.sandbox_id,"outcome":"converged"})).collect();
                census.extend(entries);
                wire.send(tungstenite::Message::Text(
                    serde_json::json!({"type": "inventory.ack", "page": page, "entryResults": entry_results})
                        .to_string()
                        .into(),
                ))
                .expect("inventory ack");
            }
            DaemonControlMessage::OperationReceipt { operation_id, .. }
            | DaemonControlMessage::OperationReceiptPruned { operation_id, .. } => {
                wire.send(tungstenite::Message::Text(
                    serde_json::json!({"type": "receipt.ack", "operationId": operation_id})
                        .to_string()
                        .into(),
                ))
                .expect("receipt ack");
            }
            // Nothing was lost in transit in these fixtures.
            DaemonControlMessage::DispatchAuditRequest { page } => {
                wire.send(tungstenite::Message::Text(
                    serde_json::json!({"type": "dispatch.audit.page", "page": page,
                        "complete": true, "entries": []})
                    .to_string()
                    .into(),
                ))
                .expect("audit page");
            }
            DaemonControlMessage::ReconcileComplete { .. } => return census,
            _ => {}
        }
    }
}

/// Complete connect-loop registration includes a host-terminal policy report.
/// Reconciliation-only fixtures continue to use `ack_reconciliation` above.
/// The server's ACK for one stored command output frame. A finished
/// command's result waits for its output to drain (or `DRAIN_IDLE`), so fake
/// servers that expect a prompt result acknowledge output like the real one.
pub(crate) fn command_output_ack(data: &[u8]) -> tungstenite::Message {
    let (metadata, body) = sandbox_protocol::parse_binary_frame(data).expect("output frame");
    tungstenite::Message::Text(
        serde_json::json!({"type":"command.output.ack", "operationId":metadata.operation_id, "generation":metadata.generation, "attempt":metadata.attempt, "sequence":metadata.sequence, "offset":metadata.offset.unwrap_or(0) + body.len() as u64})
            .to_string()
            .into(),
    )
}

pub(crate) fn ack_registration<S: std::io::Read + std::io::Write>(
    wire: &mut tungstenite::WebSocket<S>,
) -> Vec<sandbox_protocol::InventoryEntry> {
    let (census, terminal) = ack_reconciliation_with_policy(wire);
    loop {
        let frame = wire.read().expect("initial agent policy");
        let Ok(text) = frame.to_text() else {
            continue;
        };
        match sandbox_protocol::parse_daemon_control(text).expect("agent policy control") {
            sandbox_protocol::DaemonControlMessage::HostAgentPolicy(policy) => {
                assert_eq!(policy.connection_epoch, terminal.connection_epoch);
                assert_eq!(policy.sequence, 1, "initial agent policy sequence");
                assert!(policy.is_valid());
                return census;
            }
            sandbox_protocol::DaemonControlMessage::Heartbeat { .. } => {}
            other => panic!("unexpected {other:?} before initial agent policy"),
        }
    }
}

pub(crate) fn ack_reconciliation_with_policy<S: std::io::Read + std::io::Write>(
    wire: &mut tungstenite::WebSocket<S>,
) -> (
    Vec<sandbox_protocol::InventoryEntry>,
    sandbox_protocol::HostTerminalPolicyV11,
) {
    let census = ack_reconciliation(wire);
    loop {
        let frame = wire.read().expect("initial host policy");
        let Ok(text) = frame.to_text() else { continue };
        match sandbox_protocol::parse_daemon_control(text).expect("policy control") {
            sandbox_protocol::DaemonControlMessage::HostTerminalPolicy(policy) => {
                assert!(policy.connection_epoch > 0, "registered policy epoch");
                assert_eq!(policy.sequence, 1, "initial policy sequence");
                return (census, policy);
            }
            sandbox_protocol::DaemonControlMessage::Heartbeat { .. } => {}
            other => panic!("unexpected {other:?} before initial host policy"),
        }
    }
}

/// Creates an executable script without this process ever holding a writable
/// descriptor to it. A fork on any other test thread inherits every open
/// descriptor (O_CLOEXEC only closes it at the child's exec), so writing the
/// script in-process lets a concurrent fork keep it open for writing and our
/// own exec of it fails with ETXTBSY. Only the `cp` child opens the target for
/// writing; the in-process write goes to a sibling file that is never executed.
#[cfg(unix)]
pub(crate) fn install_executable(path: &std::path::Path, contents: impl AsRef<[u8]>, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    let mut staged = path.as_os_str().to_owned();
    staged.push(".src");
    let staged = PathBuf::from(staged);
    std::fs::write(&staged, contents).expect("write executable source");
    let status = std::process::Command::new("cp")
        .arg(&staged)
        .arg(path)
        .status()
        .expect("spawn cp");
    assert!(status.success(), "cp {staged:?} -> {path:?}: {status}");
    std::fs::remove_file(&staged).expect("remove executable source");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

/// Capacity tests deliberately fsync thousands of real receipt files. Prefer
/// Linux's memory filesystem so fixture construction does not spend minutes
/// flushing the host's shared disk; keep all journal IO/reopen paths intact.
/// Each directory is still private and unique. Other platforms (or hosts
/// without a writable /dev/shm) use the ordinary temporary filesystem.
pub(crate) fn journal_capacity_dir() -> tempfile::TempDir {
    #[cfg(target_os = "linux")]
    if let Ok(dir) = tempfile::tempdir_in("/dev/shm") {
        return dir;
    }
    tempfile::tempdir().expect("journal capacity directory")
}

/// Real Incus adapter driven by an executable shim. The log proves image
/// refusal happens before any instance effect, without contacting a daemon.
#[cfg(target_os = "linux")]
pub(crate) fn image_lookup_runtime(
    mode: &str,
) -> (tempfile::TempDir, sandbox_runtime::IncusKvmRuntime) {
    let dir = tempfile::tempdir().unwrap();
    let shim = dir.path().join("incus");
    install_executable(
        &shim,
        format!(
            r#"#!/bin/sh
root=$(dirname "$0")
printf '%s\n' "$*" >> "$root/calls"
if [ "$1" = "--project" ]; then shift 2; fi
if [ "$1" = "--quiet" ]; then shift; fi
case "$1" in
  version) exit 0 ;;
  profile) printf '[{{"name":"default","devices":{{"root":{{"type":"disk","path":"/","pool":"test"}},"eth0":{{"type":"nic","network":"test"}}}}}}]'; exit 0 ;;
  query)
    case "$3" in
      /1.0/projects/default?project=default) printf '{{"type":"sync","metadata":{{"name":"default","config":{{}}}}}}'; exit 0 ;;
      /1.0/images/*)
        case '{mode}' in
          json) printf '{{"type":"error","status":"Failure","status_code":404,"error":"Image \\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\" not found","error_code":404}}'; exit 1 ;;
          cli) printf 'Error: Image "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not found\n' >&2; exit 1 ;;
          denied) printf '{{"type":"error","error":"Forbidden","error_code":403}}'; exit 1 ;;
          unknown) printf 'Error: Connection reset by peer\n' >&2; exit 1 ;;
        esac ;;
    esac ;;
esac
exit 1
"#
        ),
        0o700,
    );
    let mut runtime = sandbox_runtime::IncusKvmRuntime::new(sandbox_runtime::IncusConfig {
        binary: shim.to_string_lossy().into_owned(),
        project: "default".into(),
    })
    .unwrap();
    // Shim host: a synthetic healthy egress guard for the start fence.
    runtime.set_guard_probe(std::sync::Arc::new(
        sandbox_runtime::guard_probe::FakeGuardProbe::healthy(),
    ));
    (dir, runtime)
}

/// Establishes the strict sized test session from the shared hello fixture.
#[cfg(test)]
pub(crate) fn send_sized_hello<S: std::io::Read + std::io::Write>(
    wire: &mut tungstenite::WebSocket<S>,
    binding: &super::journal::TransportBindingV11,
) {
    send_sized_hello_for_version(
        wire,
        binding,
        sandbox_protocol::SANDBOX_RELAY_PROTOCOL_VERSION,
    );
}

#[cfg(test)]
pub(crate) fn send_sized_hello_for_version<S: std::io::Read + std::io::Write>(
    wire: &mut tungstenite::WebSocket<S>,
    binding: &super::journal::TransportBindingV11,
    version: &str,
) {
    use sandbox_protocol::SANDBOX_RELAY_PROTOCOL_VERSION;
    let mut hello: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
    ))
    .expect("hello fixture");
    hello["protocolVersion"] = version.into();
    hello["supportedProtocolVersions"] =
        serde_json::Value::Array(if version == SANDBOX_RELAY_PROTOCOL_VERSION {
            vec![version.into()]
        } else {
            vec![version.into(), SANDBOX_RELAY_PROTOCOL_VERSION.into()]
        });
    hello["capabilities"]["protocolVersion"] = version.into();
    hello["connectionEpoch"] = 1.into();
    wire.send(tungstenite::Message::Text(hello.to_string().into()))
        .expect("hello ok");
    wire.send(tungstenite::Message::Text(
        serde_json::json!({
            "type": "journal.key.install", "connectionEpoch": 1,
            "keyVersion": 1, "keyId": "d".repeat(32), "keyHex": "ab".repeat(32),
            "server": binding.server, "hostOwnerId": binding.host_owner_id, "hostId": binding.host_id,
        })
        .to_string()
        .into(),
    ))
    .expect("key install");
}

pub(crate) trait FixtureRuntime {
    fn create_fixture(
        &self,
        r: &sandbox_runtime::CreateSandboxRequest,
    ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::CreateSandboxResponse>;
    fn reconnect_fixture(
        &self,
        r: &sandbox_runtime::ReconnectSandboxRequest,
    ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::ReconnectSandboxResponse>;
    fn kill_fixture(
        &self,
        r: &sandbox_runtime::KillSandboxRequest,
    ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::KillSandboxResponse>;
}
impl FixtureRuntime for dyn sandbox_runtime::SandboxRuntime {
    fn create_fixture(
        &self,
        r: &sandbox_runtime::CreateSandboxRequest,
    ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::CreateSandboxResponse> {
        self.create_sandbox_on_storage(r, &fixture_root(self)?)
    }
    fn reconnect_fixture(
        &self,
        r: &sandbox_runtime::ReconnectSandboxRequest,
    ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::ReconnectSandboxResponse> {
        self.reconnect_sandbox_on_storage(r, &fixture_root(self)?)
    }
    fn kill_fixture(
        &self,
        r: &sandbox_runtime::KillSandboxRequest,
    ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::KillSandboxResponse> {
        self.kill_sandbox_on_storage(r, &fixture_root(self)?)
    }
}
fn fixture_root(
    runtime: &dyn sandbox_runtime::SandboxRuntime,
) -> Result<sandbox_runtime::RootDisk, sandbox_runtime::RuntimeError> {
    Ok(sandbox_runtime::RootDisk {
        pool: runtime.initialize_storage_pool("default", None)?,
        disk_gi_b: sandbox_protocol::vm_size_limits()
            .map_err(|_| {
                sandbox_runtime::RuntimeError::new(
                    sandbox_protocol::SandboxErrorCode::Internal,
                    "invalid policy",
                )
            })?
            .disk_gi_b_default,
    })
}

/// Exact default root used by lifecycle doubles; production initialization stays random.
pub(crate) fn allocation() -> sandbox_protocol::capacity_v11::PinnedAllocationV11 {
    sandbox_protocol::capacity_v11::PinnedAllocationV11 {
        cpu_count: 1,
        memory_mi_b: 1024,
        disk_gi_b: 32,
        storage_pool_name: "default".into(),
        storage_marker: "a".repeat(32),
        charged_memory_mi_b: sandbox_protocol::vm_live_memory_charge_mi_b(1024).unwrap(),
        charged_vcpu: 1,
        root_charge_gi_b: 33,
    }
}

/// A fixture journal carries the same frozen pool lineage as a strict hello.
pub(crate) fn open_journal(
    path: impl AsRef<std::path::Path>,
    binding: &super::journal::TransportBindingV11,
) -> anyhow::Result<super::journal::HostJournal> {
    let journal = super::journal::HostJournal::open(path, binding)?;
    // Journal-capacity fixtures flood one sandbox with command receipts; the
    // per-sandbox cap (DG-10) has its own test, which lowers this again.
    journal.set_max_concurrent_commands(8192);
    if journal.pool_lineages().is_empty() {
        let hello: sandbox_protocol::capacity_v11::HostHelloV11 = serde_json::from_str(
            include_str!("../../../../crates/sandbox-protocol/fixtures/control_hello_daemon.json"),
        )?;
        let mut pool = hello.storage_pools[0].clone();
        pool.name = "default".into();
        pool.marker = "a".repeat(32);
        journal.freeze_pool(&mut pool, 8192, true)?;
    }
    Ok(journal)
}

pub(crate) fn pinned_dispatch(
    d: &sandbox_protocol::OperationDispatch,
) -> sandbox_protocol::OperationDispatch {
    let mut d = current_fixture_dispatch(d);
    if matches!(
        d.kind.as_str(),
        "sandbox.create" | "sandbox.reconnect" | "sandbox.stop" | "sandbox.kill"
    ) {
        let mut a = d.allocation.clone().unwrap_or_else(allocation);
        if matches!(d.kind.as_str(), "sandbox.create" | "sandbox.reconnect") {
            if let Some(cpu) = d.cpu_count {
                a.cpu_count = cpu;
                a.charged_vcpu = cpu;
            }
            if let Some(memory) = d.memory_mi_b {
                a.memory_mi_b = memory;
                a.charged_memory_mi_b =
                    sandbox_protocol::vm_live_memory_charge_mi_b(memory).unwrap();
            }
        }
        d.allocation = Some(a);
    }
    d
}
pub(crate) fn admission(
    vcpu: u32,
    capacity: sandbox_protocol::VmCapacity,
) -> super::live_admission::LiveSandboxAdmission {
    let mut admission = super::live_admission::LiveSandboxAdmission::new(vcpu, capacity);
    let hello: sandbox_protocol::capacity_v11::HostHelloV11 = serde_json::from_str(include_str!(
        "../../../../crates/sandbox-protocol/fixtures/control_hello_daemon.json"
    ))
    .unwrap();
    let mut pool = hello.storage_pools[0].clone();
    pool.marker = "a".repeat(32);
    pool.capacity_gi_b = 8192;
    admission.set_pools(vec![pool]);
    admission
}
pub(crate) fn run_fixture_connect(options: &super::connect::ConnectOptions) -> anyhow::Result<()> {
    if matches!(options.runtime, sandbox_runtime::HostRuntimeKind::Fake) {
        let runtime = sandbox_runtime::FakeRuntime::new();
        runtime.fixture_root()?;
        super::connect::run_connect_with(options, |_| Ok((Box::new(runtime), None)))
    } else {
        super::connect::run_connect(options)
    }
}

impl FixtureRuntime for sandbox_runtime::FakeRuntime {
    fn create_fixture(
        &self,
        r: &sandbox_runtime::CreateSandboxRequest,
    ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::CreateSandboxResponse> {
        sandbox_runtime::SandboxRuntime::create_sandbox_on_storage(self, r, &self.fixture_root()?)
    }
    fn reconnect_fixture(
        &self,
        r: &sandbox_runtime::ReconnectSandboxRequest,
    ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::ReconnectSandboxResponse> {
        sandbox_runtime::SandboxRuntime::reconnect_sandbox_on_storage(
            self,
            r,
            &self.fixture_root()?,
        )
    }
    fn kill_fixture(
        &self,
        r: &sandbox_runtime::KillSandboxRequest,
    ) -> sandbox_runtime::EffectOutcome<sandbox_runtime::KillSandboxResponse> {
        sandbox_runtime::SandboxRuntime::kill_sandbox_on_storage(self, r, &self.fixture_root()?)
    }
}

/// A fake root egress guard on a temporary Unix socket, speaking the real
/// G1 protocol (`serve_connection`). Its status follows the machine's own
/// boot id and CLOCK_BOOTTIME, so the daemon's real `SocketGuardProbe`
/// judges it with the production lease rule. Tests flip its health and
/// restart it as a new instance (deployment source back to `unknown`).
#[cfg(unix)]
pub(crate) struct FakeGuardServer {
    pub path: std::path::PathBuf,
    state: std::sync::Arc<std::sync::Mutex<FakeGuardServerState>>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    _dir: tempfile::TempDir,
}

#[cfg(unix)]
#[derive(Debug)]
struct FakeGuardServerState {
    instance_id: String,
    generation: u64,
    healthy: bool,
    /// `None`: no push since this instance started (`unknown`).
    deployment: Option<bool>,
    pushes: Vec<(String, bool)>,
}

#[cfg(unix)]
struct FakeGuardHandler(std::sync::Arc<std::sync::Mutex<FakeGuardServerState>>);

#[cfg(unix)]
impl sandbox_runtime::guard::protocol::Handler for FakeGuardHandler {
    fn handle(
        &self,
        request: sandbox_runtime::guard::protocol::Request,
    ) -> sandbox_runtime::guard::protocol::Reply {
        use sandbox_runtime::guard::protocol::{Reply, Request, SourcePolicy};
        use sandbox_runtime::guard::sources::SourceState;
        use sandbox_runtime::guard_probe::{GuardSourceState, GuardSourceStatus};
        let mut state = self.0.lock().unwrap();
        match request {
            Request::Status {} => {
                state.generation += 1;
                let now = sandbox_runtime::guard_probe::boottime_now_ns().unwrap();
                let mut status = sandbox_runtime::guard_probe::FakeGuardProbe::healthy_status(&[]);
                status.instance_id = state.instance_id.clone();
                status.generation = state.generation;
                status.boot_id = sandbox_runtime::guard_probe::read_boot_id().unwrap();
                status.verified_boottime_ns = now;
                status.lease_until_boottime_ns = now + 15_000_000_000;
                status.ok = state.healthy;
                if !state.healthy {
                    status.reasons = vec!["guard_stopped".into()];
                }
                status.sources.deployment = GuardSourceStatus {
                    state: match state.deployment {
                        None => GuardSourceState::Unknown,
                        Some(false) => GuardSourceState::NotConfigured,
                        Some(true) => GuardSourceState::Valid,
                    },
                    digest: state.deployment.map(|_| "sha256:deployment".into()),
                };
                Reply::Status {
                    status: Box::new(status),
                }
            }
            // The fake guard publishes no egress ceiling: proxied
            // connections fail closed against it.
            Request::Ceiling {} => Reply::error(
                sandbox_runtime::guard::protocol::ErrorCode::Internal,
                "no ceiling",
            ),
            Request::PushDeployment { configured, .. } => {
                state.deployment = Some(configured);
                let instance = state.instance_id.clone();
                state.pushes.push((instance, configured));
                Reply::Pushed {
                    digest: "sha256:deployment".into(),
                    state: if configured {
                        SourceState::Valid {
                            digest: "sha256:deployment".into(),
                            cidrs: 0,
                            domains: 0,
                        }
                    } else {
                        SourceState::NotConfigured {
                            digest: "sha256:deployment".into(),
                        }
                    },
                }
            }
            Request::Policy {} => {
                let empty = |digest: &str| SourcePolicy {
                    state: SourceState::NotConfigured {
                        digest: digest.into(),
                    },
                    digest: Some(digest.into()),
                    domains: Vec::new(),
                    cidrs: 0,
                };
                Reply::Policy {
                    policy: sandbox_runtime::guard::protocol::PolicyAnswer {
                        root: empty("sha256:root"),
                        deployment: empty("sha256:deployment"),
                    },
                }
            }
        }
    }
}

#[cfg(unix)]
impl FakeGuardServer {
    pub(crate) fn start() -> Self {
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("guard.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let state = std::sync::Arc::new(std::sync::Mutex::new(FakeGuardServerState {
            instance_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            generation: 0,
            healthy: true,
            deployment: None,
            pushes: Vec::new(),
        }));
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handle = {
            let handler = FakeGuardHandler(state.clone());
            let stop = stop.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            sandbox_runtime::guard::protocol::serve_connection(
                                stream,
                                Some(1000),
                                sandbox_runtime::guard::protocol::ServerConfig::new(1000),
                                &handler,
                            );
                        }
                        Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
                    }
                }
            })
        };
        Self {
            path,
            state,
            stop,
            handle: Some(handle),
            _dir: dir,
        }
    }
    pub(crate) fn probe(&self) -> std::sync::Arc<dyn sandbox_runtime::guard_probe::GuardProbe> {
        std::sync::Arc::new(sandbox_runtime::guard::client::SocketGuardProbe::new(
            &self.path,
        ))
    }
    pub(crate) fn set_healthy(&self, healthy: bool) {
        self.state.lock().unwrap().healthy = healthy;
    }
    /// A guard restart: new instance, generation and deployment reset.
    pub(crate) fn restart_as(&self, instance_id: &str) {
        let mut state = self.state.lock().unwrap();
        state.instance_id = instance_id.into();
        state.generation = 0;
        state.deployment = None;
    }
    /// `(instance, configured)` of every push, in order.
    pub(crate) fn pushes(&self) -> Vec<(String, bool)> {
        self.state.lock().unwrap().pushes.clone()
    }
}

#[cfg(unix)]
impl Drop for FakeGuardServer {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Put synthetic dispatches on the same digest path as current relay frames.
pub(crate) fn current_fixture_dispatch(
    d: &sandbox_protocol::OperationDispatch,
) -> sandbox_protocol::OperationDispatch {
    let mut d = d.clone();
    if d.digest_scheme.is_none() {
        if sandbox_protocol::KEY_FREE_CLEANUP_KINDS.contains(&d.kind.as_str()) {
            d.digest_scheme = Some("sha256-env-free-v1".into());
        } else {
            d.digest_scheme = Some("hmac-sha256-v1".into());
            d.digest_key_id = Some("d".repeat(32));
        }
    }
    d
}

pub(crate) fn install_fixture_key(
    journal: &super::journal::HostJournal,
    binding: &super::journal::TransportBindingV11,
) {
    journal
        .install_key(
            &sandbox_protocol::JournalKeyInstall {
                connection_epoch: 1,
                key_version: 1,
                key_id: "d".repeat(32),
                key_hex: "ab".repeat(32),
                server: binding.server.clone(),
                host_owner_id: binding.host_owner_id.clone(),
                host_id: binding.host_id.clone(),
            },
            binding,
            1,
        )
        .expect("fixture key");
}

/// Build a current dispatch fixture while leaving malformed-frame tests intact.
pub(crate) fn current_control_fixture(mut value: serde_json::Value) -> serde_json::Value {
    if value["type"] != "operation.dispatch" || value.get("digestScheme").is_some() {
        return value;
    }
    let mut body = value.clone();
    body.as_object_mut()
        .expect("dispatch object")
        .remove("type");
    if let Ok(dispatch) = serde_json::from_value::<sandbox_protocol::OperationDispatch>(body) {
        let tagged = current_fixture_dispatch(&dispatch);
        let object = value.as_object_mut().expect("dispatch object");
        object.insert(
            "digestScheme".into(),
            serde_json::json!(tagged.digest_scheme),
        );
        if let Some(key_id) = tagged.digest_key_id {
            object.insert("digestKeyId".into(), serde_json::json!(key_id));
        }
    }
    value
}

/// A positive unit-test fixture whose simulated server has installed its key.
pub(crate) fn open_ready_journal(
    path: impl AsRef<std::path::Path>,
    binding: &super::journal::TransportBindingV11,
) -> anyhow::Result<super::journal::HostJournal> {
    let journal = open_journal(path, binding)?;
    install_fixture_key(&journal, binding);
    Ok(journal)
}

/// A fixture server accepts hello and installs the current scoped journal key.
pub(crate) fn send_ready_hello_value(
    wire: &mut tungstenite::WebSocket<std::net::TcpStream>,
    hello: serde_json::Value,
    host_id: &str,
) {
    let epoch = hello["connectionEpoch"].as_u64().expect("fixture epoch");
    let address = wire.get_ref().local_addr().expect("fixture address");
    wire.send(tungstenite::Message::Text(hello.to_string().into()))
        .expect("hello ok");
    wire.send(tungstenite::Message::Text(serde_json::json!({
        "type":"journal.key.install", "connectionEpoch":epoch, "keyVersion":1,
        "keyId":"d".repeat(32), "keyHex":"ab".repeat(32),
        "server":format!("ws://{address}/ws/sandbox-host"), "hostOwnerId":"owner-1", "hostId":host_id
    }).to_string().into())).expect("fixture key install");
}
