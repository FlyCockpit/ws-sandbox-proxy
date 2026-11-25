//! Outbound sandbox host relay client (`wssp host run`).
#[cfg(test)]
use crate::sandbox_relay::test_support::FixtureRuntime;
#[cfg(test)]
use sandbox_protocol::StreamChunkFlags;

use std::collections::HashMap;
use std::io::ErrorKind;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use sandbox_protocol::SandboxErrorCode;
use sandbox_protocol::{
    DaemonCapabilities, DaemonControlMessage, DaemonHello, HostInventorySnapshot,
    OperationDispatch, OperationState, ProtocolErrorDetail, SANDBOX_BINARY_CHUNK_MAX_BYTES,
    SANDBOX_RELAY_PROTOCOL_VERSION, SANDBOX_RELAY_SUBPROTOCOL, ServerControlMessage,
    StreamBinaryMetadata, StreamKind, WireCodes, parse_binary_frame_ref,
};
#[cfg(test)]
use sandbox_protocol::{encode_binary_frame, parse_binary_frame};
#[cfg(target_os = "linux")]
use sandbox_runtime::{ExecSupervisor, IncusConfig, IncusKvmRuntime};
use sandbox_runtime::{HostRuntimeKind, SandboxRuntime, resolve_managed_instance_name};

use super::authority::HostAuthority;
#[cfg(test)]
use super::journal::intent_from_dispatch;
use super::journal::{Decision, HostJournal, HostReceipt, TransportBindingV11};
use super::live_admission::{LiveSandboxAdmission, confirmed_release};
use super::reconcile::reconcile_after_hello;

#[cfg(all(test, target_os = "linux"))]
use super::supervisor::command_result_json;
#[cfg(test)]
use super::supervisor::reject_unsupported_dispatch;
use super::supervisor::{
    DispatchError, FinishedOp, RelaySupervisor, persist_finished, runtime_err,
};
use crate::exit::{CodedError, ExitCode};
#[cfg(all(test, unix))]
use serde_json::json;
use tungstenite::Message;
use tungstenite::client::IntoClientRequest;
use url::Url;

#[derive(Debug, Clone)]
pub struct ConnectOptions {
    pub host_terminal: Option<bool>,
    pub server_url: String,
    pub host_token: String,
    pub host_id: String,
    pub label: String,
    pub runtime: HostRuntimeKind,
    pub incus_project: Option<String>,
    pub state_dir: Option<PathBuf>,
    pub heartbeat: Duration,
    pub sandbox_vcpu_budget: Option<u32>,
    pub sandbox_memory_mib: Option<u32>,
    pub max_sandbox_cpu_count: Option<u32>,
    /// Host-wide command concurrency (1 to 256; default 16).
    pub max_concurrent_commands: u32,
    /// Graceful daemon shutdown request (C55, C52-TB-3).
    pub shutdown: ShutdownSignal,
}

/// A graceful shutdown request for `wssp host run` (C55, C52-TB-3). Once
/// requested, the relay loop closes every terminal of the connection with
/// intent `shutdown` (each PTY's supervised shell group is killed and reaped
/// on its pump thread, and each exit reaches the server), waits at most
/// `TERMINAL_SHUTDOWN_DRAIN` for those exits, closes the socket normally
/// and returns; no reconnect follows. Bounded end to end: the drain, then
/// `shutdown_terminals`' 20 s reap wait, then the expiry worker's join when
/// the service drops (an in-flight expiry attempt: a graceful stop of up to
/// 16 s and its forced stop of up to 5 s); the lease wait is skipped.
/// SIGTERM/SIGINT raise it (`crate::shutdown`), under an outer 60 s deadline.
/// WP7: SIGUSR1 raises only the graceful [`quiesce`](Self::quiesce) that
/// precedes it (`super::quiesce`).
#[derive(Debug, Clone, Default)]
pub struct ShutdownSignal {
    requested: Arc<std::sync::atomic::AtomicBool>,
    /// fu-d3: when the first request arrived. The shutdown flush bound
    /// counts from it, and each session's [`FlushDeadline`] watches it, so
    /// the bound holds even while the session loop is stuck in socket IO.
    requested_at: FlushClock,
    quiesce: Arc<super::quiesce::QuiesceState>,
}

impl ShutdownSignal {
    pub fn request(&self) {
        {
            let (at, changed) = &*self.requested_at;
            let mut at = at.lock().unwrap_or_else(|e| e.into_inner());
            at.get_or_insert_with(Instant::now);
            changed.notify_all();
        }
        self.requested
            .store(true, std::sync::atomic::Ordering::Release);
        self.quiesce.wake();
    }
    /// fu-d3: when the shutdown was first requested.
    fn requested_at(&self) -> Option<Instant> {
        *self
            .requested_at
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }
    pub fn requested(&self) -> bool {
        self.requested.load(std::sync::atomic::Ordering::Acquire)
    }
    /// WP7: the graceful quiesce request (`wssp host daemon quiesce`).
    pub fn quiesce(&self) -> &super::quiesce::QuiesceState {
        &self.quiesce
    }
    pub(super) fn quiesce_handle(&self) -> Arc<super::quiesce::QuiesceState> {
        self.quiesce.clone()
    }
}

/// How long a graceful shutdown waits for terminal exits to reach the server.
pub(super) fn exact_probe_absent(
    runtime: &dyn SandboxRuntime,
    sandbox_id: &str,
    allocation: &sandbox_protocol::capacity_v11::PinnedAllocationV11,
) -> bool {
    let root = sandbox_runtime::RootDisk {
        pool: sandbox_runtime::StoragePoolIdentity {
            name: allocation.storage_pool_name.clone(),
            storage_id: allocation.storage_marker.clone(),
        },
        disk_gi_b: allocation.disk_gi_b,
    };
    runtime
        .prove_root_absent(
            &root,
            &sandbox_runtime::default_incus_instance_name(sandbox_id),
        )
        .is_ok()
}

#[cfg(test)]
#[test]
fn targeted_probe_requires_original_healthy_root() {
    let runtime = sandbox_runtime::FakeRuntime::new();
    let pool = runtime.initialize_storage_pool("primary", None).unwrap();
    let mut a = sandbox_protocol::capacity_v11::PinnedAllocationV11 {
        cpu_count: 1,
        memory_mi_b: 1024,
        disk_gi_b: 32,
        storage_pool_name: pool.name.clone(),
        storage_marker: pool.storage_id.clone(),
        charged_memory_mi_b: 1280,
        charged_vcpu: 1,
        root_charge_gi_b: 33,
    };
    assert!(exact_probe_absent(&runtime, "probe", &a));
    a.storage_marker = "b".repeat(32);
    assert!(!exact_probe_absent(&runtime, "probe", &a));
    a.storage_marker = pool.storage_id;
    runtime.set_storage_pool_available("primary", false);
    assert!(!exact_probe_absent(&runtime, "probe", &a));
}

const TERMINAL_SHUTDOWN_DRAIN: Duration = Duration::from_secs(5);
/// fu-a: after a shutdown request, how long a registered session stays open
/// to publish finished commands' output and results and read the server's
/// ACKs and `receipt.confirmed` before it closes. Only while something is
/// pending; well inside the 60 s shutdown deadline, and a second signal
/// still ends the process at once (`crate::shutdown`).
pub(super) const SHUTDOWN_FLUSH: Duration = Duration::from_secs(5);
/// fu-a: the IO bound of the close that follows a flush that ran out of time.
const SHUTDOWN_FLUSH_CLOSE: Duration = Duration::from_secs(1);

/// fu-a: the only server frames a shutdown flush acts on, judged on the raw
/// `type` before any parser with side effects (key and private-config
/// installs act inside the parse). Everything else (new dispatches, config
/// installs, terminal opens, uploads) is left unread in effect, as it was
/// when the socket closed at once: the next daemon reconciles it.
fn shutdown_flush_frame(text: &str) -> bool {
    #[derive(serde::Deserialize)]
    struct Kind<'a> {
        #[serde(borrow, rename = "type")]
        kind: std::borrow::Cow<'a, str>,
    }
    serde_json::from_str::<Kind<'_>>(text).is_ok_and(|frame| {
        matches!(
            frame.kind.as_ref(),
            "command.output.ack"
                | "receipt.confirmed"
                | "receipt.ack"
                | "receipt.pruned.ack"
                | "heartbeat.pong"
        )
    })
}

/// fu-d3: the instant a [`FlushDeadline`] counts from, `None` until it is
/// known (the shutdown request's own clock), with the condvar that announces
/// it.
type FlushClock = Arc<(std::sync::Mutex<Option<Instant>>, std::sync::Condvar)>;

/// fu-a: holds the shutdown flush to its bound on the socket IO itself. A
/// peer that trickles an incomplete frame keeps one `read` busy past any
/// per-call timeout, and a write may block for its own 30 s: at the
/// deadline this shuts the TCP stream down, which ends any blocked read or
/// write at once. Disarmed (and joined) when dropped, so the normal close
/// that follows a flush in time is never cut short.
///
/// fu-d3: armed for the whole session on the shutdown request's clock
/// ([`Self::after_shutdown`]), not when the loop first observes the request:
/// a frame already trickling when SIGTERM lands keeps the loop in `read`
/// and would otherwise leave only the 60 s outer bound.
struct FlushDeadline {
    clock: FlushClock,
    disarmed: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl FlushDeadline {
    /// The socket IO ends at `at`.
    fn arm(
        socket: &tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
        at: Instant,
    ) -> Option<Self> {
        let clock = Arc::new((std::sync::Mutex::new(Some(at)), std::sync::Condvar::new()));
        Self::watch(socket, clock, Duration::ZERO)
    }

    /// fu-d3: the socket IO ends `after` the shutdown request, whenever it
    /// arrives (at once if it is already older than that).
    fn after_shutdown(
        socket: &tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
        shutdown: &ShutdownSignal,
        after: Duration,
    ) -> Option<Self> {
        Self::watch(socket, shutdown.requested_at.clone(), after)
    }

    fn watch(
        socket: &tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
        clock: FlushClock,
        after: Duration,
    ) -> Option<Self> {
        let tcp = match socket.get_ref() {
            tungstenite::stream::MaybeTlsStream::Plain(stream) => stream.try_clone().ok(),
            tungstenite::stream::MaybeTlsStream::Rustls(stream) => {
                stream.get_ref().try_clone().ok()
            }
            _ => None,
        }?;
        let disarmed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handle = thread::Builder::new()
            .name("wssp-flush-deadline".into())
            .spawn({
                let clock = clock.clone();
                let disarmed = disarmed.clone();
                move || {
                    let (lock, changed) = &*clock;
                    let mut from = lock.lock().unwrap_or_else(|e| e.into_inner());
                    while !disarmed.load(std::sync::atomic::Ordering::Acquire) {
                        let Some(at) = from.map(|from| from + after) else {
                            from = changed.wait(from).unwrap_or_else(|e| e.into_inner());
                            continue;
                        };
                        let now = Instant::now();
                        if now >= at {
                            tracing::warn!(
                                "the relay socket is stuck past the shutdown flush; closing it"
                            );
                            let _ = tcp.shutdown(std::net::Shutdown::Both);
                            return;
                        }
                        from = changed
                            .wait_timeout(from, at - now)
                            .unwrap_or_else(|e| e.into_inner())
                            .0;
                    }
                }
            })
            .ok()?;
        Some(Self {
            clock,
            disarmed,
            handle: Some(handle),
        })
    }
}

impl Drop for FlushDeadline {
    fn drop(&mut self) {
        {
            // Under the clock's lock, so the watcher cannot miss the wake.
            let (lock, changed) = &*self.clock;
            let _held = lock.lock().unwrap_or_else(|e| e.into_inner());
            self.disarmed
                .store(true, std::sync::atomic::Ordering::Release);
            changed.notify_all();
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

type RuntimeSetup = (Box<dyn SandboxRuntime>, Option<CommandSupervisor>);

/// Disk offload is offered when its service and image fetching are available.
pub(super) const DISK_OFFLOAD_SUPPORTED: bool = true;

/// The runtime proves egress enforcement before the daemon advertises it.
fn daemon_capabilities(
    runtime_kind: sandbox_protocol::RuntimeKind,
    egress_policy: bool,
) -> DaemonCapabilities {
    DaemonCapabilities {
        protocol_version: SANDBOX_RELAY_PROTOCOL_VERSION.to_string(),
        binary_frames: true,
        cancellation: true,
        operation_wal: true,
        host_inventory: true,
        max_binary_chunk_bytes: sandbox_protocol::SANDBOX_BINARY_CHUNK_MAX_BYTES,
        stream_window_chunks: sandbox_protocol::SANDBOX_STREAM_WINDOW_CHUNKS,
        egress_policy,
        terminal: false,
        host_terminal: false,
        host_commands: false,
        host_files: false,
        host_command_max_ms: None,
        agent_policy_revision: 0,
        require_host_terminal_totp: true,
        policy_revision: 0,
        host_managed_sandbox_ceiling: sandbox_protocol::vm_size_limits()
            .map(|l| l.host_managed_sandbox_ceiling)
            .unwrap_or(250),
        // Placeholder only: the hello literal always sets the live ceiling
        // from `host_policy` (the static capabilities never carry it).
        max_lease_ms: Some(sandbox_protocol::DEFAULT_MAX_LEASE_MS),
        image: None,
        egress_refused_hints: false,
        // B9: every runtime that runs guest commands runs start/ready; the
        // same runtimes grant or revoke the guest sudo drop-in and retire
        // guestRoot receipts on host proof only.
        template_startup: !matches!(runtime_kind, sandbox_protocol::RuntimeKind::Unsupported),
        guest_sudo: !matches!(runtime_kind, sandbox_protocol::RuntimeKind::Unsupported),
        runtime_kind,
        // Set in the hello literal from the credential service (C8a).
        credentials: None,
        // Placeholder only: the hello sets the measured guard and open bits.
        egress: sandbox_protocol::EgressCapabilitiesV11 {
            open: false,
            guard: false,
        },
        // D3b: offer 64 KiB output chunks; the server answers in `hello.ok`.
        max_output_chunk_bytes: u32::try_from(sandbox_protocol::SANDBOX_OUTPUT_CHUNK_OFFER_BYTES)
            .ok(),
        // Per-entry census results; the server answers in `hello.ok`.
        census_entry_results: true,
        // WP7: set in the hello literal when this daemon can quiesce.
        quiesce: false,
        // WP8: set in the hello literal from the node's terminal grace.
        terminal_resume: None,
        // WP2 (D11): `reconcile.complete` may name receipts still resolving.
        pending_receipts: true,
        // WP2 section 9, with its observation fence (see the constant).
        expiry_status_results: true,
        observation_fence: true,
        // UNKNOWN `command.run` receipts retire on per-command proof.
        command_retire: true,
        // Set in the hello literal (needs the image cache's `fetch`).
        disk_offload: false,
        // Set in the hello literal from the tunnel manager.
        tunnel: None,
        // Set in the hello literal from the runtime kind.
        tunnel_ports: false,
        // Interactive channels are not offered yet.
        channels: None,
    }
}

/// The guest a running sandbox's checkpoint packs from (its lease record's
/// declared guest identity, else the dispatch defaults); none once expired.
fn checkpoint_target(
    journal: &HostJournal,
    sandbox_id: &str,
) -> Option<super::credentials::service::CheckpointTarget> {
    let row = journal.lease(sandbox_id).filter(|row| !row.expired)?;
    let guest = row.guest.as_ref().map_or_else(
        || sandbox_runtime::CredentialGuest {
            sandbox_id: row.sandbox_id.clone(),
            uid: 1000,
            gid: 1000,
            home: "/home/user".into(),
        },
        |g| sandbox_runtime::CredentialGuest {
            sandbox_id: row.sandbox_id.clone(),
            uid: g.guest_uid,
            gid: g.guest_gid,
            home: g.guest_home.clone(),
        },
    );
    Some(super::credentials::service::CheckpointTarget {
        guest,
        sandbox_owner_id: row.sandbox_owner_id.clone(),
    })
}

pub fn run_connect(options: &ConnectOptions) -> Result<()> {
    run_connect_with_trust(options, &crate::tls::Trust::default())
}
pub fn run_connect_with_trust(options: &ConnectOptions, trust: &crate::tls::Trust) -> Result<()> {
    run_connect_with_config(options, trust, &crate::config::Config::default())
}
pub fn run_connect_with_config(
    options: &ConnectOptions,
    trust: &crate::tls::Trust,
    config: &crate::config::Config,
) -> Result<()> {
    // Only the per-command host supervisors are subreapers. Adopting
    // runtime/PTY orphans here would take them from their existing reapers.
    // WP1 chaos knob: read once, debug builds only (release: always None).
    install_relay_test_timing(super::test_timing::relay_test_timing()?);
    // Widen-only runtime waits for test daemons on an Incus double; debug
    // builds only (release: always None).
    install_runtime_test_timing(super::test_timing::runtime_test_timing(
        &options.server_url,
    )?);
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut lease = LeaseSlot::default();
    let result = run_connect_service_with_tls(
        options,
        |state_dir| init_runtime(options, state_dir, &mut lease),
        Arc::new(super::clock::LeaseClock::default()),
        trust.client_config(),
        config,
        true,
    );
    // Every relay thread has been joined: mark this daemon's Incus server
    // marker released, so another daemon may start at once.
    #[cfg(target_os = "linux")]
    if let Some(lease) = lease.take() {
        lease.release();
    }
    result
}
#[cfg(test)]
pub(super) fn run_connect_with(
    options: &ConnectOptions,
    init: impl FnOnce(&std::path::Path) -> Result<RuntimeSetup>,
) -> Result<()> {
    run_connect_service(options, init, Arc::new(super::clock::LeaseClock::default()))
}
#[cfg(test)]
fn run_connect_service(
    options: &ConnectOptions,
    init: impl FnOnce(&std::path::Path) -> Result<RuntimeSetup>,
    clock: Arc<super::clock::LeaseClock>,
) -> Result<()> {
    // Fixture daemons disable image capabilities and frames by default.
    // unless a test opts in; the image cache has its own tests.
    run_connect_service_with_tls(
        options,
        init,
        clock,
        None,
        &crate::config::Config {
            image_cache_gib: crate::config::ImageCacheSize::Gib(0),
            ..crate::config::Config::default()
        },
        // Likewise no credential capability or census frames.
        false,
    )
}
/// A fixture daemon with the CLI-login credential service (C8a tests).
#[cfg(test)]
pub(super) fn run_connect_with_credentials(
    options: &ConnectOptions,
    init: impl FnOnce(&std::path::Path) -> Result<RuntimeSetup>,
) -> Result<()> {
    run_connect_service_with_tls(
        options,
        init,
        Arc::new(super::clock::LeaseClock::default()),
        None,
        &crate::config::Config {
            image_cache_gib: crate::config::ImageCacheSize::Gib(0),
            ..crate::config::Config::default()
        },
        true,
    )
}
fn run_connect_service_with_tls(
    options: &ConnectOptions,
    init: impl FnOnce(&std::path::Path) -> Result<RuntimeSetup>,
    clock: Arc<super::clock::LeaseClock>,
    tls: Option<Arc<rustls::ClientConfig>>,
    config: &crate::config::Config,
    credentials: bool,
) -> Result<()> {
    let ws_url = crate::auth::relay_url(&options.server_url)?;
    // Resolved before any state opens: a malformed debug timing knob fails the start.
    let carry = carry_policy(config)?;

    let mut request = ws_url.as_str().into_client_request()?;
    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {}", options.host_token).parse()?,
    );
    request
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", SANDBOX_RELAY_SUBPROTOCOL.parse()?);

    let mut binding = TransportBindingV11 {
        server: canonical_server_binding(&ws_url),
        host_owner_id: String::new(),
        host_id: options.host_id.clone(),
    };
    let state_dir = match &options.state_dir {
        Some(dir) => dir.clone(),
        None => crate::paths::data_dir()?
            .join("relay")
            .join(super::journal::sha256_hex(options.host_id.as_bytes())),
    };
    let mut journal = HostJournal::open(&state_dir, &binding)?;
    journal.clock = clock;
    let journal = Arc::new(journal);
    // Preview tunnels: an earlier daemon's clients go before any runtime
    // cleanup can release their sandboxes' networks.
    super::tunnel::sweep_leftovers(&state_dir)?;
    let (runtime, exec_supervisor) = init(&state_dir)?;
    let runtime: Arc<dyn SandboxRuntime> = Arc::from(runtime);
    // Preview tunnels: runtime port changes (any runtime that records
    // tunnel plans; independent of an installed client).
    super::tunnel_ports::install(runtime.clone());
    // Preview tunnels: off unless `[tunnel]` names a client that verifies.
    // A client runs only for a sandbox this host holds a live lease for
    // (another user's only with the node owner's consent).
    let holder_journal = journal.clone();
    super::tunnel::install(
        config.tunnel_settings(),
        runtime.clone(),
        &state_dir,
        Arc::new(move |sandbox_id: &str| {
            let Some(row) = holder_journal.lease(sandbox_id) else {
                return super::tunnel::LeaseHere::Unknown;
            };
            // Live: the lease's own generation is allowed ordinary work now
            // (not expired, deadline not passed, clock and journal sound).
            if !holder_journal.work_allowed(sandbox_id, row.generation, "tunnel") {
                return super::tunnel::LeaseHere::Lapsed;
            }
            super::tunnel::LeaseHere::Live {
                own: !row.binding.host_owner_id.is_empty()
                    && row.binding.host_owner_id == row.sandbox_owner_id,
            }
        }),
    );
    let authority = HostAuthority::with_journal(journal.clone());
    // CLI-login credentials: None when its state directory is
    // unusable, in which case the capability is not advertised. Started
    // before expiry so a lease already due captures, and a refused
    // teardown's owed lease re-bind is replayed before any admission.
    let credential_service = if credentials {
        match super::credentials::service::CredentialService::start(&state_dir, &options.host_id) {
            Ok(service) => {
                service.replay_rebinds(&|sandbox_id, generation| {
                    journal
                        .rebind_after_refused_teardown(sandbox_id, generation)
                        .map(|_| ())
                });
                // Proxy mode (§9) only where the runtime gives each sandbox a
                // bridge gateway the guest can reach on the proxy port.
                if runtime.supports_credential_proxy() {
                    let trust = tls
                        .as_deref()
                        .cloned()
                        .or_else(super::credentials::proxy::upstream::webpki_client_config);
                    let settings = trust.and_then(|trust| {
                        let endpoints = runtime.clone();
                        // Proxy upstreams obey the node's egress ceiling,
                        // read from the runtime's own guard probe (fail
                        // closed without one).
                        let ceiling = super::credentials::proxy::upstream::guard_ceiling(
                            runtime.egress_guard_probe(),
                        );
                        super::credentials::proxy::ProxySettings::production(
                            config.credential_proxy_port(),
                            &trust,
                            Arc::new(move |sandbox_id: &str| {
                                endpoints.credential_proxy_endpoint(sandbox_id)
                            }),
                            ceiling,
                        )
                    });
                    match settings {
                        Some(settings) => service.enable_proxy(settings),
                        None => tracing::warn!(
                            "credential proxy disabled: its upstream trust or resolver is unavailable"
                        ),
                    }
                }
                Some(service)
            }
            Err(error) => {
                tracing::warn!(reason = %format!("{error:#}"),
                    "credential delivery disabled: its state directory is unusable");
                None
            }
        }
    } else {
        None
    };
    let expiry = super::expiry::ExpiryService::start_with_credentials(
        runtime.clone(),
        journal.clone(),
        authority.clone(),
        carry,
        credential_service.clone(),
    );
    // Periodic login checkpoints: stopped and joined with this
    // function, before the expiry service.
    let _checkpoints = credential_service.as_ref().map(|service| {
        let journal = journal.clone();
        service.start_checkpoints(
            runtime.clone(),
            Arc::new(move |sandbox_id: &str| checkpoint_target(&journal, sandbox_id)),
            super::credentials::service::CHECKPOINT_TICK,
        )
    });
    // Process-scoped execution state: work in flight survives a relay
    // transport drop (detached, bounded by the grace) and is adopted by the
    // reconnect. Every other exit revokes it, exactly as a session end did.
    let relay = RelaySupervisor::start_with_command_limit(
        runtime.clone(),
        journal.clone(),
        authority.clone(),
        #[cfg(target_os = "linux")]
        exec_supervisor.clone(),
        options.max_concurrent_commands,
    );
    journal.set_max_concurrent_commands(options.max_concurrent_commands);
    // Managed image cache: None when `image_cache_gib = 0` (no capability).
    let images = super::images::ImageService::start(
        runtime.clone(),
        &state_dir,
        super::images::ImageSettings {
            size: config.image_cache_gib,
            accept_foreign: config.accept_foreign_images,
            foreign_grace: config.foreign_grace(),
            // The service exists only with the cache (and capture) enabled.
            builder: config.builder_enabled(true),
            accept_foreign_builds: config.accept_foreign_builds,
        },
        crate::tls::Trust::http_agent_from(
            tls.clone(),
            super::images::upstream_agent_config(),
            super::images::HTTP_IDLE,
        ),
        &options.server_url,
        &options.host_token,
    )
    .unwrap_or_else(|error| {
        tracing::warn!(reason = %format!("{error:#}"), "image cache disabled: its state directory is unusable");
        None
    });
    if let Some(images) = images {
        // Disk offload rides on the image cache's staging and
        // upload loop; without the cache the hello omits `diskOffload`.
        let lookup_journal = journal.clone();
        let lookup: super::offload::SandboxLookup = Arc::new(move |sandbox_id: &str| {
            let lease = lookup_journal.lease(sandbox_id)?;
            if lease.instance_absent || lease.root_deleted {
                return None;
            }
            Some(super::offload::LocalSandbox {
                disk_gib: lease
                    .allocation
                    .as_ref()
                    .map(|allocation| allocation.disk_gi_b)
                    .unwrap_or_else(|| {
                        sandbox_protocol::vm_size_limits()
                            .map(|limits| limits.disk_gi_b_default)
                            .unwrap_or(20)
                    }),
                build: lease.build_id.is_some(),
            })
        });
        match super::offload::OffloadService::start(
            images.clone(),
            runtime.clone(),
            lookup,
            super::offload::OffloadSettings {
                upload_bytes_per_sec: config.offload_upload_bytes_per_sec(),
                fetch_bytes_per_sec: config.offload_fetch_bytes_per_sec(),
                host_id: options.host_id.clone(),
            },
        ) {
            Ok(offload) => {
                // Eviction and discard (§7) delete through the journal's
                // pinned allocations; local pressure is checked every
                // five minutes.
                offload.install_local_disks(Arc::new(super::offload::JournalDisks::new(
                    journal.clone(),
                    runtime.clone(),
                )));
                let pressure = offload.clone();
                let _ = std::thread::Builder::new()
                    .name("wssp-offload-pressure".into())
                    .spawn(move || {
                        loop {
                            std::thread::sleep(Duration::from_secs(300));
                            pressure.pressure_evict();
                        }
                    });
                expiry.install_offload(offload.clone());
                relay.install_offload(offload);
            }
            Err(error) => tracing::warn!(
                reason = %format!("{error:#}"),
                "disk offload disabled: its journal is unusable"
            ),
        }
        relay.install_images(images);
    }
    if let Some(service) = credential_service {
        relay.install_credentials(service);
    }
    // WP7: graceful quiesce (worker, then the control file advertising it);
    // the control file is removed when this function returns.
    let _quiesce = super::quiesce::start(
        &options.shutdown,
        &state_dir,
        config,
        relay.quiesce_outstanding(),
    )?;
    // Node egress state (docs/guide/network.md#other-users-hosts): the
    // runtime's own guard probe (the start fence trusts the same one), the
    // live consent and settings, and the guard monitor that renews the
    // server's lease and re-pushes the deployment list to every new guard.
    let node_egress = Arc::new(
        super::egress_state::NodeEgress::new(runtime.egress_guard_probe(), config)
            .with_deployment_store(state_dir.join(super::egress_state::DEPLOYMENT_BLOCKLIST_FILE)),
    );
    relay.install_egress(node_egress.clone());
    let _guard_monitor = super::egress_state::GuardMonitor::start(
        node_egress,
        super::egress_state::GUARD_POLL_INTERVAL,
    );
    if config.allow_open_egress_for_others.is_none() {
        tracing::info!(
            "open internet for other users' sandboxes is off until you choose: `wssp host config set-open-egress-for-others on|off`"
        );
    }
    let mut workers = RelayWorkers {
        authority: authority.clone(),
        handles: Vec::new(),
        supervisor: exec_supervisor.clone(),
    };
    // PTY capacity survives reconnects: a closing PTY stays charged until its
    // pump confirms the reap, whichever connection opened it.
    // WP8: it also keeps detached sandbox PTYs for `terminal_resume_grace`.
    let terminal_slots = Arc::new(super::terminal::TerminalSlots::with_resume_grace(
        super::terminal::resume_grace(config)?,
    ));
    // CLI channels: capacity survives reconnects like PTY slots; the durable
    // registry's scopes from a previous process are killed now.
    let channel_slots = Arc::new(super::channel::ChannelSlots::default());
    if runtime.channel_capability() {
        super::channel::sweep_registry(
            runtime.clone(),
            Arc::new(super::channel::ChannelRegistry::new(journal.clone())),
        );
    }
    let policy_path = match &options.state_dir {
        Some(dir) => Some(dir.join("config.toml")),
        None => Some(crate::paths::config_file()?),
    };
    let mut host_policy =
        super::host_policy::HostPolicy::new(config, options.host_terminal, policy_path);
    // M5: the configured ceiling is in force before the first dispatch.
    journal.set_lease_ceiling(host_policy.lease_ceiling());
    // A recorded authority revocation survives restarts: re-apply the stop
    // before serving anything (idempotent; never destroys). What a few
    // bounded cycles cannot confirm stays an obligation: a registered session
    // lifts it, every other exit retries it in `wait_idle`.
    if super::revocation::is_revoked(&journal) {
        let shutdown = options.shutdown.clone();
        super::revocation::enforce(
            &journal,
            runtime.as_ref(),
            super::revocation::StopBudgets::DEFAULT,
            &|| shutdown.requested(),
            super::revocation::STARTUP_CYCLES,
        );
    }
    // A transient relay drop must not strand the host until every accepted
    // lease settles: the expiry service and the journal lock stay held while
    // the session reconnects with backoff. Only credential failures (upgrade
    // 401/403, close 4003) and a local shutdown end the process: no other
    // server close does, whatever its code.
    let mut backoff = ReconnectBackoff::default();
    const STABLE_SESSION: Duration = Duration::from_secs(60);
    // The first connect is the operator's command line: redirects, refusals,
    // and other connect failures fail fast. Only once a session existed does
    // a dropped server earn reconnects (it may still be restarting).
    let mut reconnect = false;
    let mut observed = HostObservations::default();
    // Receipt resolutions outlive sessions: a stalled one is deferred, then
    // delivered by a later session (WP2).
    let resolutions = Arc::new(super::resolutions::InFlightResolutions::with_wait(
        resolution_wait(),
    ));
    let result = loop {
        let session_started = Instant::now();
        authority.begin_session();
        let mut pre_hello = false;
        let result = relay_session(
            tls.clone(),
            options,
            request.clone(),
            options.runtime.protocol_runtime_kind(),
            &mut binding,
            runtime.clone(),
            exec_supervisor.clone(),
            journal.clone(),
            authority.clone(),
            &expiry,
            &relay,
            &terminal_slots,
            &channel_slots,
            &mut host_policy,
            reconnect,
            config,
            &mut observed,
            &mut pre_hello,
            &resolutions,
        )
        .map_err(|error| {
            // Once a session existed, a transient census/recovery refusal is
            // part of reconnect too. Falling through here used to enter
            // wait_idle and silently stop dialing until every lease expired.
            if reconnect
                && error.downcast_ref::<CodedError>().is_none()
                && error.downcast_ref::<CleanShutdown>().is_none()
                && error.downcast_ref::<TerminalHelloRefusal>().is_none()
            {
                error.context(RetryableSession)
            } else {
                error
            }
        });
        match result {
            // A local shutdown observed in any phase ends the process.
            Err(error) if error.downcast_ref::<CleanShutdown>().is_some() => break Ok(()),
            // fu-a: a credential close (4003) that arrives during the shutdown
            // flush keeps its meaning: the credential failure ends the process
            // and a revocation verdict is latched (and its VMs stopped).
            Err(error)
                if options.shutdown.requested()
                    && crate::exit::code_for(&error) == ExitCode::CredentialInactive =>
            {
                break Err(error);
            }
            // A daemon shutdown never reconnects (C55).
            _ if options.shutdown.requested() => break Ok(()),
            Err(error)
                if error.downcast_ref::<RetryableSession>().is_some()
                    && crate::exit::code_for(&error) != ExitCode::CredentialInactive
                    && error.downcast_ref::<TerminalHelloRefusal>().is_none() =>
            {
                reconnect = true;
                if session_started.elapsed() >= STABLE_SESSION {
                    backoff.stable_session();
                }
                // WP2: revoke only on a server verdict or the journal IO
                // latch; a pre-hello failure (census, capacity, dial) is
                // local or network, never a verdict.
                if session_end(&error, pre_hello, journal.io_failed()) == SessionEnd::Detach {
                    let outage_started = authority.detached_since().is_none();
                    let carried = authority.detach(Instant::now());
                    // Once per outage: retries of a failed reconnect are not
                    // new detach events (live finding B-6).
                    if carried > 0 && outage_started {
                        tracing::info!(
                            carried,
                            "relay transport lost; detached in-flight work for adoption"
                        );
                    } else if carried > 0 {
                        tracing::debug!(carried, "reconnect attempt failed; work still detached");
                    }
                } else {
                    // A server verdict or a failed journal write: revoke at
                    // once, and the carried work's journal key goes with it.
                    let revoked = workers.revoke();
                    journal.clear_key();
                    relay.quiesce(Duration::from_secs(5));
                    if revoked > 0 {
                        tracing::warn!(revoked, "relay session failed; in-flight work revoked");
                    }
                }
                // Carried work is adopted promptly, then backs off (WP2).
                let wait = reconnect_wait(
                    backoff.next(
                        !authority.carried().is_empty(),
                        authority
                            .detached_since()
                            .map(|since| Instant::now().saturating_duration_since(since)),
                    ),
                    &error,
                );
                tracing::warn!(
                    "sandbox relay connection lost ({error:#}); reconnecting in {}ms",
                    wait.as_millis()
                );
                // Sliced so a shutdown request ends the backoff promptly.
                let resume = Instant::now() + wait;
                while Instant::now() < resume && !options.shutdown.requested() {
                    thread::sleep((resume - Instant::now()).min(Duration::from_millis(50)));
                }
                if options.shutdown.requested() {
                    break Ok(());
                }
            }
            result => break result,
        }
    };
    // Every exit revokes all work at once (P4/P5): credential failure, a clean
    // close, a shutdown request. Dropped before the terminal and lease waits.
    drop(workers);
    drop(relay);
    journal.clear_key();
    // Debug-build test hold: lets the signal tests keep a graceful shutdown
    // in progress (release builds compile it to nothing).
    if options.shutdown.requested() {
        crate::state::test_barrier("graceful_shutdown");
    }
    // This runs on EVERY relay exit, including upgrade 401/403 and close 4003:
    // every PTY is closed (on its own threads) before the process ends.
    super::terminal::shutdown_terminals(&runtime, &terminal_slots, Duration::from_secs(20));
    // Channel pumps kill-close on their own threads (relay loss/shutdown);
    // wait a bounded time for them to settle. Unsettled scopes stay in the
    // durable registry for the next start's sweep.
    channel_slots.wait_idle(Duration::from_secs(20));
    // Preview tunnels never outlive the daemon that supervises them.
    if let Some(tunnels) = super::tunnel::installed() {
        tunnels.stop_all();
    }
    // A requested shutdown is the operator's: bounded, so it never waits for
    // accepted leases to settle (they stay durable for the next start). Every
    // other exit keeps the journal lock until they settle.
    // A definitive revocation (close 4003, upgrade 401/403) removes the
    // server's way to stop anything here: stop every VM locally, durably.
    // The verdict is latched in memory: the obligation survives a failed
    // marker write.
    // fu-a: a revocation that ends a requested shutdown (a 4003 during its
    // flush) still stops every guest: the request that started the shutdown
    // must not cancel it. The outer shutdown deadline bounds it (and a
    // second signal still ends the process at once).
    let revoked_in_shutdown = options.shutdown.requested()
        && matches!(&result, Err(error) if super::revocation::is_authority_revocation(error));
    let mut obligation = match &result {
        Err(_) if revoked_in_shutdown => {
            super::revocation::revoke_and_stop(&journal, runtime.as_ref(), &|| false)
        }
        Err(error) if super::revocation::is_authority_revocation(error) => {
            let shutdown = options.shutdown.clone();
            super::revocation::revoke_and_stop(&journal, runtime.as_ref(), &|| shutdown.requested())
        }
        _ => super::revocation::StopObligation::new(super::revocation::StopBudgets::DEFAULT),
    };
    // `wait_idle` also keeps retrying the revocation stop obligation until
    // every managed VM is confirmed stopped or absent (and, when latched,
    // the marker is durable).
    if !options.shutdown.requested() {
        expiry.wait_idle_with(&options.shutdown, obligation);
    } else if revoked_in_shutdown {
        while obligation.poll(&journal, runtime.as_ref(), &|| false) {
            thread::sleep(Duration::from_millis(50));
        }
    }
    let shutdown_result = runtime
        .shutdown_local_children()
        .map_err(anyhow::Error::from);
    drop(expiry);
    result.and(shutdown_result)
}

fn send_terminal_frame(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    wire: WireCodes,
    frame: super::terminal::Outgoing,
) -> Result<()> {
    write_terminal_frame(socket, wire, frame)?;
    socket.flush()?;
    Ok(())
}

/// Write the next image frames and flush the socket (W1, a#1): a frame
/// counts as sent only once it was written AND flushed. A write or flush
/// error drops the batch unsent: its upload progress and terminal frames go
/// back to the front of the outbox for the next connection, after the
/// jobs' resumes; its other frames are dropped
/// (`images::replayed_after_failed_write`).
pub(super) fn send_image_batch<S: std::io::Read + std::io::Write>(
    socket: &mut tungstenite::WebSocket<S>,
    wire: WireCodes,
    images: &super::images::ImageService,
) -> Result<()> {
    let batch = images.take_batch();
    if batch.frames().is_empty() {
        return Ok(());
    }
    for message in batch.frames() {
        match super::spell(wire, message, None) {
            Ok(text) => socket.write(Message::Text(text.into()))?,
            // Never encodable: dropped with the batch once it is sent, not
            // retried on every reconnect.
            Err(error) => tracing::warn!(error = %error, "image frame not encodable; dropped"),
        }
    }
    socket.flush()?;
    batch.sent();
    Ok(())
}

/// Queues a terminal frame without flushing; the caller flushes the batch.
fn write_terminal_frame(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    wire: WireCodes,
    frame: super::terminal::Outgoing,
) -> Result<()> {
    match frame {
        super::terminal::Outgoing::Text(message) => {
            socket.write(Message::Text(super::spell(wire, &message, None)?.into()))?
        }
        super::terminal::Outgoing::Binary(bytes) => socket.write(Message::Binary(bytes.into()))?,
    }
    Ok(())
}

fn relay_dial_error(error: tungstenite::Error, server_url: &str, reconnect: bool) -> anyhow::Error {
    if let Some(hint) = crate::tls::certificate_hint(server_url, &error) {
        let error = anyhow::Error::new(error).context(hint);
        if reconnect {
            error.context(RetryableSession)
        } else {
            error
        }
    } else if let tungstenite::Error::Http(response) = &error
        && matches!(response.status().as_u16(), 401 | 403)
    {
        let refused = anyhow::anyhow!(
            "host credential is inactive; check account access or run `wssp host enroll` again"
        )
        .context(CodedError::new(ExitCode::CredentialInactive));
        // Only the server's explicit verdict about THIS credential (sent after
        // the full secret verified) stops VMs; a plain 401/403 never does.
        if super::revocation::upgrade_refusal_code(response.headers(), response.body().as_deref())
            .is_some_and(|code| super::revocation::is_revocation_verdict(&code))
        {
            refused.context(super::revocation::AuthorityRevoked)
        } else {
            refused
        }
    } else if reconnect
        || matches!(&error, tungstenite::Error::Http(response) if response.status().as_u16() == 429)
        // A 503 that names a retry time is the server's own admission control
        // (e.g. its rate-limit store is briefly unavailable), not an outage.
        || (matches!(&error, tungstenite::Error::Http(response) if response.status().as_u16() == 503)
            && upgrade_retry_after(&error).is_some())
    {
        let failed = anyhow::anyhow!("websocket connect failed");
        // A 429/503 refusal may say when to come back (`Retry-After`).
        match upgrade_retry_after(&error) {
            Some(after) => failed.context(RetryAfter(after)),
            None => failed,
        }
        .context(RetryableSession)
    } else if matches!(&error, tungstenite::Error::Http(response) if response.status().as_u16() == 503)
    {
        anyhow::anyhow!(
            "websocket connect failed: the server answered 503 Service Unavailable; \
                     the server is temporarily unavailable"
        )
    } else {
        // First connect: fail fast, exactly like before reconnects existed.
        anyhow::anyhow!("websocket connect failed")
    }
}

fn startup_census_error(error: sandbox_runtime::RuntimeError) -> anyhow::Error {
    let retryable = matches!(
        error.code,
        SandboxErrorCode::Internal
            | SandboxErrorCode::Timeout
            | SandboxErrorCode::UnknownOutcome
            | SandboxErrorCode::Transport
            | SandboxErrorCode::Disconnected
    );
    let error = anyhow::Error::from(error).context("host startup census failed");
    if retryable {
        error.context(RetryableSession)
    } else {
        error
    }
}

/// Marks a transient census or relay failure for a fresh reconnect attempt.
/// Inventory identity fencing and first-connect network refusals stay terminal.
#[derive(Debug, Clone, Copy)]
pub(super) struct RetryableSession;
impl std::fmt::Display for RetryableSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("relay session dropped")
    }
}
impl std::error::Error for RetryableSession {}

/// The server asked for a longer pause before the next connect: close 1013
/// (try again later) or the `rate_limited` refusal that precedes it.
#[derive(Debug, Clone, Copy)]
pub(super) struct ServerBusy;
impl std::fmt::Display for ServerBusy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("relay server busy")
    }
}
impl std::error::Error for ServerBusy {}

/// A server-provided reconnect hint (`Retry-After` on a refused upgrade).
#[derive(Debug, Clone, Copy)]
pub(super) struct RetryAfter(pub(super) Duration);
impl std::fmt::Display for RetryAfter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "server asked to retry after {}s", self.0.as_secs())
    }
}
impl std::error::Error for RetryAfter {}

/// The least wait after a 1013 / `rate_limited` refusal.
const SERVER_BUSY_BACKOFF: Duration = Duration::from_secs(5);
/// Upper bound on exponential reconnect backoff.
const MAX_RECONNECT_WAIT: Duration = Duration::from_secs(30);

/// `Retry-After` (delta-seconds) on a 429/503 upgrade refusal.
fn upgrade_retry_after(error: &tungstenite::Error) -> Option<Duration> {
    let tungstenite::Error::Http(response) = error else {
        return None;
    };
    if !matches!(response.status().as_u16(), 429 | 503) {
        return None;
    }
    let seconds: u64 = response
        .headers()
        .get(tungstenite::http::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()?;
    Some(Duration::from_secs(seconds.min(300)))
}

/// The next reconnect wait: `base` with jitter (in `[base/2, base]`, so a
/// fleet dropped by one server restart does not redial in lockstep), raised
/// to a 1013 floor or the server's `Retry-After`, capped at five minutes.
fn reconnect_wait(base: Duration, error: &anyhow::Error) -> Duration {
    fn jitter(base: Duration) -> Duration {
        use ring::rand::SecureRandom;
        let mut byte = [0u8; 2];
        let fraction = match ring::rand::SystemRandom::new().fill(&mut byte) {
            Ok(()) => f64::from(u16::from_le_bytes(byte)) / f64::from(u16::MAX),
            Err(_) => 1.0,
        };
        base.mul_f64(0.5 + fraction / 2.0)
    }
    let mut wait = jitter(base);
    if error.downcast_ref::<ServerBusy>().is_some() {
        wait = wait.max(jitter(SERVER_BUSY_BACKOFF));
    }
    if let Some(RetryAfter(after)) = error.downcast_ref::<RetryAfter>() {
        wait = wait.max(*after);
    }
    wait.min(Duration::from_secs(300))
}

/// Marks a local shutdown request observed by the session (SIGTERM / ctrl-c).
/// The process exits without reconnecting. A server close never carries it.
#[derive(Debug, Clone, Copy)]
pub(super) struct CleanShutdown;
impl std::fmt::Display for CleanShutdown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("relay session closed cleanly")
    }
}
impl std::error::Error for CleanShutdown {}

/// Marks a positive loss of the relay transport (any server close but 4003,
/// a reconciliation acknowledgement timeout, or the server-silence deadline).
/// In-flight host work is detached, not revoked, for the reconnect to adopt.
#[derive(Debug, Clone, Copy)]
pub(super) struct TransportLost;
impl std::fmt::Display for TransportLost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("relay transport lost")
    }
}
impl std::error::Error for TransportLost {}

/// A server verdict that revokes carried work for this session.
#[derive(Debug, Clone, Copy)]
pub(super) struct ServerVerdict;
impl std::fmt::Display for ServerVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("relay server refused the session")
    }
}
impl std::error::Error for ServerVerdict {}

/// A refused hello ends the daemon without a reduced capability retry.
#[derive(Debug, Clone, Copy)]
pub(super) struct TerminalHelloRefusal;
impl std::fmt::Display for TerminalHelloRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("relay hello refused")
    }
}
impl std::error::Error for TerminalHelloRefusal {}

/// Rate limits before registration retry; other hello refusals end the daemon.
/// Verdicts after registration retain the normal revoke-and-reconnect behavior.
pub(super) fn protocol_error_end(
    registered: bool,
    failure: SandboxErrorCode,
    message: &str,
) -> anyhow::Error {
    match failure {
        SandboxErrorCode::RateLimited if !registered => {
            anyhow::anyhow!("relay refused the connection: {message}")
                .context(ServerBusy)
                .context(TransportLost)
                .context(RetryableSession)
        }
        _ if !registered => anyhow::anyhow!("relay protocol error: {message}")
            .context(ServerVerdict)
            .context(TerminalHelloRefusal),
        _ => anyhow::anyhow!("relay protocol error: {message}").context(ServerVerdict),
    }
}

/// What a failed session does with carried work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SessionEnd {
    /// Keep it running, detached, for the reconnect to adopt.
    Detach,
    /// Revoke it at once (and drop the journal key).
    Revoke,
}

/// WP2: carried work is revoked only on a server verdict (`protocol.error`,
/// close 1002; close 4003 never reaches this) or the journal IO latch.
/// Everything else, a transport loss, a local protocol or runtime failure, a
/// census or capacity failure before hello, detaches and reconnects: the
/// daemon cannot tell those from a network fault, and the latch keeps
/// integrity failures fail-closed.
pub(super) fn session_end(
    error: &anyhow::Error,
    pre_hello: bool,
    journal_io_failed: bool,
) -> SessionEnd {
    let verdict = !pre_hello && error.downcast_ref::<ServerVerdict>().is_some();
    if journal_io_failed || verdict {
        SessionEnd::Revoke
    } else {
        SessionEnd::Detach
    }
}

/// The first reconnect wait; doubles per failed attempt up to
/// [`MAX_RECONNECT_WAIT`] and resets after a stable session.
const RECONNECT_BACKOFF_FLOOR: Duration = Duration::from_millis(250);
/// While work is carried, reconnect at least this often...
const CARRY_RECONNECT_FLOOR: Duration = Duration::from_secs(1);
/// ...for this long into the outage; then back off from the floor.
const CARRY_FAST_WINDOW: Duration = Duration::from_secs(60);

/// WP2: reconnect backoff. The session counter doubles from 250 ms to 30 s.
/// While work is carried the wait is held at most 1 s for the first 60 s of
/// the outage (adopt it promptly); after that a separate counter backs off
/// exponentially from 1 s to 30 s, so a long carry never redials every second
/// for its whole life. A new outage, or no carried work, resets that counter.
#[derive(Debug, Clone, Copy)]
pub(super) struct ReconnectBackoff {
    session: Duration,
    carry: Duration,
}

impl Default for ReconnectBackoff {
    fn default() -> Self {
        Self {
            session: RECONNECT_BACKOFF_FLOOR,
            carry: CARRY_RECONNECT_FLOOR,
        }
    }
}

impl ReconnectBackoff {
    /// A session that stayed up long enough starts over from the floor.
    pub(super) fn stable_session(&mut self) {
        self.session = RECONNECT_BACKOFF_FLOOR;
    }

    /// The next wait (before jitter and server hints), advancing the counters.
    /// `detached_for` is how long the current outage has carried work.
    pub(super) fn next(&mut self, carrying: bool, detached_for: Option<Duration>) -> Duration {
        let session = self.session;
        self.session = (self.session * 2).min(MAX_RECONNECT_WAIT);
        if !carrying {
            self.carry = CARRY_RECONNECT_FLOOR;
            return session;
        }
        match detached_for {
            Some(outage) if outage >= CARRY_FAST_WINDOW => {
                let wait = self.carry;
                self.carry = (self.carry * 2).min(MAX_RECONNECT_WAIT);
                wait
            }
            _ => {
                self.carry = CARRY_RECONNECT_FLOOR;
                session.min(CARRY_RECONNECT_FLOOR)
            }
        }
    }
}

/// A blocked write longer than this ends the session as a lost transport.
const RELAY_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// No frame of any kind (heartbeat pongs included) for this long, counted
/// only over idle read time, ends the session as a lost transport. The
/// deadline is the larger of this and six heartbeat intervals.
const SERVER_SILENCE_MIN: Duration = Duration::from_secs(30);

#[cfg(test)]
thread_local! {
    /// Test override of (carry intent window, silence floor), read on the
    /// daemon's thread.
    pub(super) static RELAY_TIMING_OVERRIDE: std::cell::Cell<Option<(Duration, Duration)>> =
        const { std::cell::Cell::new(None) };
}
#[cfg(test)]
thread_local! {
    /// Test override of the host-report cadence clock (`host_reports`), read
    /// on the daemon's thread: a stepped clock makes "a reconnect outlasting
    /// the server TTLs" deterministic without waiting.
    pub(super) static REPORT_CLOCK_OVERRIDE:
        std::cell::RefCell<Option<Arc<super::clock::LeaseClock>>> =
        const { std::cell::RefCell::new(None) };
}
#[cfg(test)]
thread_local! {
    /// Test override of the receipt-resolution wait, read on the daemon's thread.
    pub(super) static RESOLUTION_WAIT_OVERRIDE: std::cell::Cell<Option<Duration>> =
        const { std::cell::Cell::new(None) };
}
fn resolution_wait() -> Duration {
    #[cfg(test)]
    if let Some(wait) = RESOLUTION_WAIT_OVERRIDE.with(std::cell::Cell::get) {
        return wait;
    }
    super::resolutions::RESOLUTION_WAIT
}
/// The host-report cadence follows real elapsed time (the server's TTLs),
/// not the journal's lease clock.
fn report_clock() -> Arc<super::clock::LeaseClock> {
    #[cfg(test)]
    if let Some(clock) = REPORT_CLOCK_OVERRIDE.with(|cell| cell.borrow().clone()) {
        return clock;
    }
    Arc::new(super::clock::LeaseClock::default())
}
/// How long carried work survives a transport loss (WP3, `carry.rs`).
fn carry_policy(config: &crate::config::Config) -> Result<super::carry::CarryPolicy> {
    let policy = super::carry::CarryPolicy::for_daemon(config)?;
    #[cfg(test)]
    if let Some((window, _)) = RELAY_TIMING_OVERRIDE.with(std::cell::Cell::get) {
        return Ok(super::carry::CarryPolicy::new(window, policy.max_carry()));
    }
    Ok(policy)
}
/// The process's `WSSP_TEST_RELAY_TIMING` override (WP1), set once by
/// [`run_connect_with_config`]; always `None` in release builds.
static RELAY_TEST_TIMING: std::sync::OnceLock<Option<super::test_timing::RelayTestTiming>> =
    std::sync::OnceLock::new();

fn install_relay_test_timing(timing: Option<super::test_timing::RelayTestTiming>) {
    #[cfg(debug_assertions)]
    if let Some(timing) = &timing {
        tracing::warn!(
            ?timing,
            "relay test timing override in effect (debug build)"
        );
    }
    let _ = RELAY_TEST_TIMING.set(timing);
}

/// How often the connect loop runs the disk offload periodic pass
/// (`OffloadService::tick`).
pub(super) const DISK_TICK_EVERY: Duration = Duration::from_secs(60);

/// `DISK_TICK_EVERY`, or a debug test daemon's shorter period
/// (`WSSP_TEST_DISK_TIMING`).
fn disk_tick_every() -> Duration {
    super::test_timing::disk_test_timing().map_or(DISK_TICK_EVERY, |t| t.tick)
}

/// The process's `WSSP_TEST_RUNTIME_TIMING` widening, set once by
/// [`run_connect_with_config`]; always `None` in release builds.
static RUNTIME_TEST_TIMING: std::sync::OnceLock<Option<super::test_timing::RuntimeTestTiming>> =
    std::sync::OnceLock::new();

fn install_runtime_test_timing(timing: Option<super::test_timing::RuntimeTestTiming>) {
    #[cfg(debug_assertions)]
    if let Some(timing) = &timing {
        tracing::warn!(
            ?timing,
            "TEST-ONLY OVERRIDE `{}`: this daemon waits longer than production for the guest \
             terminate helper and the connected expiry observation, and may poll storage \
             less often; never set it in production",
            super::test_timing::RUNTIME_TIMING_ENV
        );
    }
    let _ = RUNTIME_TEST_TIMING.set(timing);
}

#[cfg(debug_assertions)]
pub(super) fn installed_runtime_test_timing() -> Option<super::test_timing::RuntimeTestTiming> {
    RUNTIME_TEST_TIMING.get().copied().flatten()
}

/// Permit of one connected expiry observation (host census of expiring
/// sandboxes). Debug test daemons may widen it (`WSSP_TEST_RUNTIME_TIMING`).
pub(super) const EXPIRY_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(4);

fn expiry_observation_timeout() -> Duration {
    #[cfg(debug_assertions)]
    if let Some(timeout) =
        installed_runtime_test_timing().and_then(|timing| timing.expiry_observation)
    {
        return timeout;
    }
    EXPIRY_OBSERVATION_TIMEOUT
}

/// The override [`run_connect_with_config`] read once at start; WP3 carry,
/// WP7 quiesce and WP8 terminal grace take their fields from here, never
/// from the environment again. `None` in release builds and fixture daemons.
pub(super) fn installed_relay_test_timing() -> Option<super::test_timing::RelayTestTiming> {
    RELAY_TEST_TIMING.get().copied().flatten()
}

pub(super) fn server_silence_deadline(heartbeat: Duration) -> Duration {
    #[cfg(test)]
    if let Some((_, floor)) = RELAY_TIMING_OVERRIDE.with(std::cell::Cell::get) {
        return floor.max(heartbeat.saturating_mul(6));
    }
    #[cfg(debug_assertions)]
    if let Some(floor) = installed_relay_test_timing().and_then(|timing| timing.silence) {
        return floor.max(session_heartbeat(heartbeat).saturating_mul(6));
    }
    SERVER_SILENCE_MIN.max(heartbeat.saturating_mul(6))
}

/// The dispatch loop's heartbeat interval. A debug build's
/// `WSSP_TEST_RELAY_TIMING` silence floor below six heartbeats shortens the
/// heartbeat with it, so the floor is the deadline: otherwise six 5 s
/// heartbeats (30 s) always outvote the override and the knob could never
/// name a shorter silence (WP1 chaos cell C11). Production timing is
/// unchanged.
pub(super) fn session_heartbeat(heartbeat: Duration) -> Duration {
    #[cfg(debug_assertions)]
    if let Some(floor) = installed_relay_test_timing().and_then(|timing| timing.silence) {
        return heartbeat_within_silence(heartbeat, floor);
    }
    heartbeat
}

/// Six heartbeats fit in `floor` (at least 1 ms apart).
#[cfg(debug_assertions)]
fn heartbeat_within_silence(heartbeat: Duration, floor: Duration) -> Duration {
    heartbeat.min(floor / 6).max(Duration::from_millis(1))
}

/// A positive loss of the relay transport (tests classify errors with it;
/// carried work follows [`session_end`]). Within a session a
/// `tungstenite::Error` comes only from socket read/send/flush; a journal
/// `io::Error` never becomes one.
#[cfg(test)]
pub(super) fn transport_lost(error: &anyhow::Error) -> bool {
    use tungstenite::error::ProtocolError;
    if error.downcast_ref::<TransportLost>().is_some() {
        return true;
    }
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<tungstenite::Error>(),
            Some(
                tungstenite::Error::Io(_)
                    | tungstenite::Error::ConnectionClosed
                    | tungstenite::Error::AlreadyClosed
                    | tungstenite::Error::Tls(_)
                    | tungstenite::Error::Protocol(
                        ProtocolError::ResetWithoutClosingHandshake
                            | ProtocolError::SendAfterClosing
                    )
            )
        )
    })
}

/// Classification of a websocket close frame, shared by every socket reader
/// (the dispatch loop and the reconciliation phases) so a server close means
/// the same thing wherever it arrives.
///
/// Only 4003 is final: the server refuses this credential. Every other close
/// (1000, none, 1001, 1002, 1008, 1011, 1013, unknown) is a transport loss:
/// carried work is detached for adoption and the daemon reconnects with
/// backoff. A server verdict about the session itself arrives as a typed
/// `protocol.error` frame before its close, and that frame revokes.
pub(super) fn close_during_read(code: Option<u16>, reason: Option<&str>) -> anyhow::Error {
    match code {
        // 4003 always revokes the relay; only an explicit server verdict that
        // this enrolled credential is revoked or its owner banned/deleting
        // also makes the daemon stop its VMs (it can no longer receive stops).
        Some(4003) => {
            let error = anyhow::anyhow!(
                "host credential is inactive; check account access or run `wssp host enroll` again"
            )
            .context(CodedError::new(ExitCode::CredentialInactive));
            if reason.is_some_and(super::revocation::is_revocation_verdict) {
                error.context(super::revocation::AuthorityRevoked)
            } else {
                error
            }
        }
        Some(1011) => anyhow::anyhow!("sandbox relay internal error; retry the connection")
            .context(CodedError::new(ExitCode::RelayUnavailable))
            .context(TransportLost)
            .context(RetryableSession),
        // Try again later: the same reconnect, after a longer pause.
        Some(1013) => anyhow::anyhow!("sandbox relay is busy; reconnecting later")
            .context(ServerBusy)
            .context(TransportLost)
            .context(RetryableSession),
        // 1002: the server refused this session's protocol (WP2): a verdict,
        // so carried work is revoked; the daemon still reconnects.
        Some(1002) => anyhow::anyhow!(
            "sandbox relay closed the session for a protocol violation (code 1002, reason {}); reconnecting",
            reason.filter(|reason| !reason.is_empty()).unwrap_or("none")
        )
        .context(ServerVerdict)
        .context(TransportLost)
        .context(RetryableSession),
        code => {
            let reason = reason.filter(|reason| !reason.is_empty()).unwrap_or("none");
            let code = code.map_or_else(|| "none".to_owned(), |code| code.to_string());
            anyhow::anyhow!(
                "sandbox relay closed the session (code {code}, reason {reason}); reconnecting"
            )
            .context(TransportLost)
            .context(RetryableSession)
        }
    }
}

/// C55-L11: the whole relay connect (name resolution, TCP connect, TLS and
/// the WebSocket upgrade) must finish within this bound, so a stalled or
/// trickling server can never hold the daemon past it; a shutdown request
/// ends it sooner, within one poll slice.
const RELAY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Revoke the startup runtime scope on timeout or SIGTERM, including while
/// the main thread is waiting on an Incus child. Dropping joins the watchdog.
pub(super) struct RuntimeIoGuard {
    pub(super) permit: Arc<sandbox_runtime::RuntimePermit>,
    cancel: Option<mpsc::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}
impl RuntimeIoGuard {
    pub(super) fn arm(shutdown: &ShutdownSignal, budget: Duration) -> Result<Self> {
        Self::watch(
            shutdown,
            sandbox_runtime::RuntimePermit::with_timeout(budget),
        )
    }

    /// Census cost grows with inventory and ACL contention. Bound each runtime
    /// call/lock/settlement instead of discarding all progress after 30 seconds.
    /// DNS lease watchers remain active and retain their absolute deadlines.
    fn census(shutdown: &ShutdownSignal) -> Result<Self> {
        Self::over(
            shutdown,
            Arc::new(sandbox_runtime::RuntimePermit::default()),
        )
    }

    fn watch(shutdown: &ShutdownSignal, permit: sandbox_runtime::RuntimePermit) -> Result<Self> {
        Self::over(shutdown, Arc::new(permit))
    }

    /// Watches an existing permit (a fenced reconciliation worker's).
    fn over(
        shutdown: &ShutdownSignal,
        permit: Arc<sandbox_runtime::RuntimePermit>,
    ) -> Result<Self> {
        let worker_permit = permit.clone();
        let shutdown = shutdown.clone();
        let (cancel, cancelled) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("wssp-startup-io".into())
            .spawn(move || {
                loop {
                    if shutdown.requested() || worker_permit.is_cancelled() {
                        worker_permit.revoke();
                        return;
                    }
                    match cancelled.recv_timeout(Duration::from_millis(50)) {
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        _ => return,
                    }
                }
            })?;
        Ok(Self {
            permit,
            cancel: Some(cancel),
            thread: Some(thread),
        })
    }
}
impl Drop for RuntimeIoGuard {
    fn drop(&mut self) {
        self.permit.revoke();
        drop(self.cancel.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// How often a pending connect or handshake checks the shutdown request.
const RELAY_HANDSHAKE_POLL: Duration = Duration::from_millis(100);

type RelaySocket = tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>;

/// Why a bounded connect step must give up now: a shutdown request wins over
/// the deadline.
fn relay_connect_stop(shutdown: &ShutdownSignal, deadline: Instant) -> Option<&'static str> {
    if shutdown.requested() {
        Some("stopped by daemon shutdown")
    } else if Instant::now() >= deadline {
        Some("timed out")
    } else {
        None
    }
}

/// A bounded connect step that gave up, as the I/O error callers already
/// treat like any other connect failure.
fn relay_connect_stopped(step: &str, cause: &str) -> Box<tungstenite::Error> {
    Box::new(tungstenite::Error::Io(std::io::Error::new(
        ErrorKind::TimedOut,
        format!("relay websocket {step} {cause}"),
    )))
}

/// Open the relay socket with a bounded, shutdown-aware connect and
/// handshake. Same request, TLS roots and frame limits as
/// `tungstenite::connect` without redirects; only the waiting changes. A
/// timeout or shutdown surfaces as an I/O error, which callers treat like any
/// other connect failure.
#[cfg(test)]
fn connect_relay_socket(
    request: tungstenite::http::Request<()>,
    config: tungstenite::protocol::WebSocketConfig,
    shutdown: &ShutdownSignal,
    timeout: Duration,
) -> Result<(RelaySocket, tungstenite::handshake::client::Response), Box<tungstenite::Error>> {
    connect_relay_socket_with_tls(request, config, shutdown, timeout, None)
}
fn connect_relay_socket_with_tls(
    request: tungstenite::http::Request<()>,
    config: tungstenite::protocol::WebSocketConfig,
    shutdown: &ShutdownSignal,
    timeout: Duration,
    tls: Option<Arc<rustls::ClientConfig>>,
) -> Result<(RelaySocket, tungstenite::handshake::client::Response), Box<tungstenite::Error>> {
    use tungstenite::HandshakeError;
    use tungstenite::error::UrlError;
    let io = |error: std::io::Error| Box::new(tungstenite::Error::Io(error));
    let deadline = Instant::now() + timeout;
    let uri = request.uri();
    let needs_tls = match uri.scheme_str() {
        Some("wss") => true,
        Some("ws") => false,
        _ => {
            return Err(Box::new(tungstenite::Error::Url(
                UrlError::UnsupportedUrlScheme,
            )));
        }
    };
    let host = uri
        .host()
        .ok_or_else(|| Box::new(tungstenite::Error::Url(UrlError::NoHostName)))?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let port = uri.port_u16().unwrap_or(if needs_tls { 443 } else { 80 });
    // The SIGTERM/SIGINT handlers are SA_RESTART, so a blocking socket call
    // they interrupt normally restarts by itself. Should one still fail with
    // EINTR, which the handshake cannot resume, the attempt restarts from the
    // dial, which observes the shutdown request and the deadline.
    loop {
        let stream = dial_relay(&uri.to_string(), host, port, shutdown, deadline)?;
        stream.set_nodelay(true).map_err(io)?;
        // The socket stays blocking: a peer that trickles bytes would never
        // trip a read timeout, so the watchdog bounds the handshake instead.
        let watchdog = HandshakeWatchdog::arm(&stream, shutdown, deadline).map_err(io)?;
        let attempt = tungstenite::client_tls_with_config(
            request.clone(),
            stream,
            Some(config),
            tls.clone().map(tungstenite::Connector::Rustls),
        );
        // Joined before the result is used: once the watchdog has fired the
        // socket is shut down, so even a handshake that just completed fails.
        if let Some(cause) = watchdog.disarm() {
            return Err(relay_connect_stopped("handshake", cause));
        }
        match attempt {
            Ok(connected) => return Ok(connected),
            Err(HandshakeError::Failure(tungstenite::Error::Io(error)))
                if error.kind() == ErrorKind::Interrupted => {}
            Err(HandshakeError::Failure(error)) => return Err(Box::new(error)),
            // Only a non-blocking or timed socket yields WouldBlock.
            Err(HandshakeError::Interrupted(_)) => {
                return Err(io(std::io::Error::from(ErrorKind::WouldBlock)));
            }
        }
    }
}

/// Resolve `host` and connect to its first reachable address, waiting until
/// `deadline` at most and returning within a poll slice of a shutdown
/// request. Neither name resolution (getaddrinfo) nor `connect_timeout` can
/// be interrupted, so both run on a short-lived dial thread and only the
/// waiting happens here. A dial this gives up on ends by itself: it checks
/// the shutdown request and the deadline between addresses, each connect is
/// capped at the time remaining, and resolution at the system resolver's own
/// timeouts (which this cannot shorten without a resolver dependency). A
/// socket it opens after that is closed when its result is dropped.
fn dial_relay(
    uri: &str,
    host: &str,
    port: u16,
    shutdown: &ShutdownSignal,
    deadline: Instant,
) -> Result<std::net::TcpStream, Box<tungstenite::Error>> {
    use std::net::ToSocketAddrs;
    let (dialed_tx, dialed) = mpsc::sync_channel(1);
    let target = host.to_owned();
    let signal = shutdown.clone();
    thread::Builder::new()
        .name("wssp-relay-dial".into())
        .spawn(move || {
            let result = (target.as_str(), port).to_socket_addrs().map(|addrs| {
                for addr in addrs {
                    if relay_connect_stop(&signal, deadline).is_some() {
                        break;
                    }
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if let Ok(tcp) = std::net::TcpStream::connect_timeout(&addr, remaining) {
                        return Some(tcp);
                    }
                }
                None
            });
            // The waiter may have given up; the socket then closes here.
            let _ = dialed_tx.send(result);
        })
        .map_err(|error| Box::new(tungstenite::Error::Io(error)))?;
    loop {
        if let Some(cause) = relay_connect_stop(shutdown, deadline) {
            return Err(relay_connect_stopped("connect", cause));
        }
        let slice = deadline
            .saturating_duration_since(Instant::now())
            .min(RELAY_HANDSHAKE_POLL);
        match dialed.recv_timeout(slice) {
            Ok(Ok(Some(tcp))) => return Ok(tcp),
            Ok(Ok(None)) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(dial_failure(uri, shutdown, deadline));
            }
            Ok(Err(error)) => return Err(Box::new(tungstenite::Error::Io(error))),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}

/// The error for a dial that produced no socket. The dial caps each connect
/// at the time remaining, so a connect that hangs to the deadline gives up
/// at the same instant the waiter's last poll slice ends; whichever thread
/// runs first must not decide the cause. A dial that ends at or after the
/// deadline (or after a shutdown request) timed out (or was stopped); only
/// one that failed before it found the relay unreachable.
fn dial_failure(
    uri: &str,
    shutdown: &ShutdownSignal,
    deadline: Instant,
) -> Box<tungstenite::Error> {
    match relay_connect_stop(shutdown, deadline) {
        Some(cause) => relay_connect_stopped("connect", cause),
        None => Box::new(tungstenite::Error::Url(
            tungstenite::error::UrlError::UnableToConnect(uri.to_owned()),
        )),
    }
}

/// C55-L11 (G8-R1): the hard bound on one relay handshake. A peer that
/// trickles bytes keeps the TLS and upgrade reads busy, so no read timeout
/// or WouldBlock ever hands control back; this thread holds a clone of the
/// socket and shuts it down in both directions at the deadline or on a
/// shutdown request, which ends the blocked read or write at once.
/// [`HandshakeWatchdog::disarm`] (or dropping it) cancels and joins the
/// thread, so neither the thread nor its socket clone outlives the handshake.
struct HandshakeWatchdog {
    cancel: Option<mpsc::Sender<()>>,
    thread: Option<thread::JoinHandle<Option<&'static str>>>,
}

impl HandshakeWatchdog {
    fn arm(
        tcp: &std::net::TcpStream,
        shutdown: &ShutdownSignal,
        deadline: Instant,
    ) -> std::io::Result<Self> {
        let tcp = tcp.try_clone()?;
        let shutdown = shutdown.clone();
        let (cancel, cancelled) = mpsc::channel::<()>();
        let thread = thread::Builder::new()
            .name("wssp-relay-handshake".into())
            .spawn(move || {
                loop {
                    if let Some(cause) = relay_connect_stop(&shutdown, deadline) {
                        let _ = tcp.shutdown(std::net::Shutdown::Both);
                        return Some(cause);
                    }
                    let slice = deadline
                        .saturating_duration_since(Instant::now())
                        .min(RELAY_HANDSHAKE_POLL);
                    match cancelled.recv_timeout(slice) {
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return None,
                    }
                }
            })?;
        Ok(Self {
            cancel: Some(cancel),
            thread: Some(thread),
        })
    }

    /// Cancel and join the watchdog. `Some(cause)` when it fired: the socket
    /// is then shut down, even if the handshake had just completed.
    fn disarm(mut self) -> Option<&'static str> {
        self.stop()
    }

    fn stop(&mut self) -> Option<&'static str> {
        drop(self.cancel.take());
        match self.thread.take().map(thread::JoinHandle::join) {
            None | Some(Ok(None)) => None,
            Some(Ok(Some(cause))) => Some(cause),
            // It cannot panic; if it somehow did, the socket's state is
            // unknown, so the handshake fails.
            Some(Err(_)) => Some("watchdog failed"),
        }
    }
}

impl Drop for HandshakeWatchdog {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[allow(clippy::too_many_arguments)]
fn relay_session(
    tls: Option<Arc<rustls::ClientConfig>>,
    options: &ConnectOptions,
    request: tungstenite::http::Request<()>,
    protocol_runtime: sandbox_protocol::RuntimeKind,
    binding: &mut TransportBindingV11,
    runtime: Arc<dyn SandboxRuntime>,
    exec_supervisor: Option<CommandSupervisor>,
    journal: Arc<HostJournal>,
    authority: HostAuthority,
    expiry: &super::expiry::ExpiryService,
    relay: &RelaySupervisor,
    terminal_slots: &Arc<super::terminal::TerminalSlots>,
    channel_slots: &Arc<super::channel::ChannelSlots>,
    host_policy: &mut super::host_policy::HostPolicy,
    reconnect: bool,
    config: &crate::config::Config,
    observed: &mut HostObservations,
    pre_hello: &mut bool,
    resolutions: &Arc<super::resolutions::InFlightResolutions>,
) -> Result<()> {
    // Every failure before the socket carries a session (census, capacity,
    // dial) is local or network, never a server verdict: carried work stays
    // detached for the next attempt (still bounded by the grace).
    let (mut socket, advertised, observe_after_hello) = relay_session_prepare(
        tls,
        options,
        request,
        &runtime,
        &journal,
        &authority,
        expiry,
        relay,
        reconnect,
        config,
        observed,
        pre_hello,
        resolutions,
    )?;
    relay_session_active(
        advertised,
        observe_after_hello.then_some((config, observed)),
        protocol_runtime,
        binding,
        runtime,
        exec_supervisor,
        journal,
        authority,
        expiry,
        relay,
        terminal_slots,
        channel_slots,
        host_policy,
        &mut socket,
        resolutions,
    )
    // Every phase classifies close frames itself: terminal credential errors
    // stay terminal and a local shutdown stays clean. Only unclassified
    // failures are transient session drops.
    .map_err(|error| {
        if error.downcast_ref::<RetryableSession>().is_some()
            || error.downcast_ref::<CleanShutdown>().is_some()
            || error.downcast_ref::<CodedError>().is_some()
        {
            error
        } else {
            error.context(RetryableSession)
        }
    })
}

/// What a session advertises in hello and repeats in `host.admission`: the
/// result of one host observation (census, capacity, storage ceilings).
#[derive(Clone)]
struct HostObservation {
    session_options: ConnectOptions,
    vm_capacity: sandbox_protocol::VmCapacity,
    static_capacity: sandbox_protocol::capacity_v11::HostStaticCapacityV11,
    sandbox_count: u32,
}

impl HostObservation {
    /// Whether this observation admits exactly the static tuple `advertised`
    /// froze for its epoch (hello binds it; `host.admission` must repeat it
    /// verbatim). Usage and derivation bytes are live observations, reported
    /// by storage updates, so only they may differ.
    fn same_static_tuple(&self, advertised: &Self) -> bool {
        type Key<'a> = (
            &'a str,
            &'a str,
            &'a sandbox_protocol::capacity_v11::StorageHealth,
            &'a Option<sandbox_protocol::capacity_v11::StorageReason>,
            u32,
            Option<u64>,
            &'a sandbox_protocol::capacity_v11::CapacitySource,
            Option<u64>,
            bool,
        );
        fn key(p: &sandbox_protocol::capacity_v11::StoragePoolV11) -> Key<'_> {
            (
                &p.name,
                &p.marker,
                &p.health,
                &p.reason,
                p.capacity_gi_b,
                p.total_based_capacity_gi_b,
                &p.capacity_source,
                p.implicit_ceiling_gi_b,
                p.draining,
            )
        }
        let (a, b) = (&self.static_capacity, &advertised.static_capacity);
        self.vm_capacity == advertised.vm_capacity
            && a.vm_capacity == b.vm_capacity
            && a.storage_pools.len() == b.storage_pools.len()
            && a.storage_pools
                .iter()
                .zip(&b.storage_pools)
                .all(|(a, b)| key(a) == key(b))
    }
}

/// Host observations that outlive one session: the last good capacity
/// inspection, and the last completed observation, which a reconnect
/// advertises so it can dial at once.
#[derive(Default)]
struct HostObservations {
    last_capacity: Option<crate::vm_capacity::CapacityInspection>,
    advertised: Option<HostObservation>,
}

/// The socket, what its hello advertises, and whether the host observation
/// still has to run after `hello.ok` (a reconnect that dialed at once).
type PreparedSession = (RelaySocket, HostObservation, bool);

#[allow(clippy::too_many_arguments)]
fn relay_session_prepare(
    tls: Option<Arc<rustls::ClientConfig>>,
    options: &ConnectOptions,
    request: tungstenite::http::Request<()>,
    runtime: &Arc<dyn SandboxRuntime>,
    journal: &Arc<HostJournal>,
    authority: &HostAuthority,
    expiry: &super::expiry::ExpiryService,
    relay: &RelaySupervisor,
    reconnect: bool,
    config: &crate::config::Config,
    observed: &mut HostObservations,
    pre_hello: &mut bool,
    resolutions: &super::resolutions::InFlightResolutions,
) -> Result<PreparedSession> {
    // Only network and runtime-observation failures (census reads, host
    // resource reads, dial and handshake) are pre-hello transport losses that
    // keep carried work detached. Journal and storage-ledger persistence
    // failures (check_inventory, expiry reconcile, retained-root
    // reconstruction, pool ceilings) leave `pre_hello` unset: they revoke.
    *pre_hello = false;
    let mut transport = |error| {
        *pre_hello = true;
        error
    };
    // C55-L11: a shutdown requested during the census returns between its
    // steps (each step is itself bounded) instead of starting the next one;
    // the reconnect loop maps any result to a clean exit once requested.
    let stop_requested = || {
        anyhow::ensure!(!options.shutdown.requested(), "daemon shutdown requested");
        Ok(())
    };
    stop_requested()?;
    // Policy sync never waits for inventory across a transport
    // loss. A reconnect dials at once and advertises the last completed
    // observation; the census it skips runs after `hello.ok`, fenced, while
    // the socket is read (so `egress.blocklist` applies meanwhile), and still
    // gates admission. The first connect has nothing to advertise yet.
    let cached = observed.advertised.clone().filter(|_| reconnect);
    let observe_after_hello = cached.is_some();
    let advertised = match cached {
        Some(cached) => cached,
        None => {
            let refresh_pause = expiry.pause_dns_refresh(&options.shutdown)?;
            let startup = RuntimeIoGuard::census(&options.shutdown)?;
            let startup_runtime = runtime.with_cancellation(startup.permit.clone());
            // R-1: the reconnect census never waits on a sandbox whose carried or
            // in-flight lifecycle work may hold its lock; a later census covers it.
            let mut census_busy = authority.pending_lifecycle_sandboxes();
            census_busy.extend(relay.lifecycle_busy());
            census_busy.extend(resolutions.busy_sandboxes());
            let observation = observe_host(
                options,
                startup_runtime.as_ref(),
                &|| options.shutdown.requested() || startup.permit.is_cancelled(),
                &|| false,
                journal,
                &expiry.handle(),
                &census_busy,
                &|| {
                    let mut busy = authority.pending_sandboxes();
                    busy.extend(relay.lifecycle_busy());
                    busy.extend(resolutions.busy_sandboxes());
                    busy
                },
                config,
                &mut observed.last_capacity,
                &mut transport,
            )?;
            drop(startup_runtime);
            drop(startup);
            drop(refresh_pause);
            observed.advertised = Some(observation.clone());
            observation
        }
    };
    stop_requested()?;
    let (socket, _response) = connect_relay_socket_with_tls(
        request,
        tungstenite::protocol::WebSocketConfig::default()
            .max_message_size(Some(
                sandbox_protocol::HOST_CONTROL_MAX_BYTES
                    .max(4 + 65536 + SANDBOX_BINARY_CHUNK_MAX_BYTES),
            ))
            .max_frame_size(Some(
                sandbox_protocol::HOST_CONTROL_MAX_BYTES
                    .max(4 + 65536 + SANDBOX_BINARY_CHUNK_MAX_BYTES),
            )),
        &options.shutdown,
        RELAY_HANDSHAKE_TIMEOUT,
        tls,
    )
    .map_err(|error| transport(relay_dial_error(*error, &options.server_url, reconnect)))?;
    Ok((socket, advertised, observe_after_hello))
}

/// One host observation: census (and the expiry pass it may need), host
/// capacity, retained-root reconstruction and storage ceilings. `runtime` is
/// already scoped to the caller's cancellation; `interrupted` ends the pool
/// census, `fenced` the expiry wait. Runtime-observation failures go through
/// `transport` (they keep carried work detached); journal and ledger
/// failures do not (they revoke).
#[allow(clippy::too_many_arguments)]
fn observe_host(
    options: &ConnectOptions,
    runtime: &dyn SandboxRuntime,
    interrupted: &dyn Fn() -> bool,
    fenced: &dyn Fn() -> bool,
    journal: &HostJournal,
    expiry: &super::expiry::ExpiryHandle,
    census_busy: &std::collections::HashSet<String>,
    busy: &dyn Fn() -> std::collections::HashSet<String>,
    config: &crate::config::Config,
    last_capacity: &mut Option<crate::vm_capacity::CapacityInspection>,
    transport: &mut dyn FnMut(anyhow::Error) -> anyhow::Error,
) -> Result<HostObservation> {
    let stop_requested = || {
        anyhow::ensure!(!options.shutdown.requested(), "daemon shutdown requested");
        Ok(())
    };
    let inventory = runtime
        .sandbox_inventory_skipping(census_busy)
        .map_err(|error| transport(startup_census_error(error)))?;
    super::expiry::check_inventory(journal, &inventory)?;
    stop_requested()?;
    // A second census is needed only if a local expiry may have changed the
    // inventory. On a busy host each census costs Incus time that eats the
    // carried work's grace (live observation Obs-1).
    let expiry_was_due = expiry.any_due()?;
    expiry.reconcile_until(super::expiry::RECONCILE_BUDGET, fenced)?;
    stop_requested()?;
    let inventory = if expiry_was_due || expiry.any_due()? {
        runtime
            .sandbox_inventory_skipping(census_busy)
            .map_err(|error| transport(startup_census_error(error)))?
    } else {
        inventory
    };
    let sandbox_count = inventory
        .len()
        .try_into()
        .context("host inventory too large")?;
    stop_requested()?;
    let capacity = crate::vm_capacity::inspect_capacity(
        options.runtime,
        crate::vm_capacity::CapacityOverrides {
            vcpu_budget: options.sandbox_vcpu_budget,
            memory_mib: options.sandbox_memory_mib,
            cpu_count: options.max_sandbox_cpu_count,
        },
        config,
        runtime.host_resources().map_err(anyhow::Error::from),
    )?;
    let vm_capacity = crate::vm_capacity::resolve_session_capacity(capacity, last_capacity)?;
    let vcpu_budget = last_capacity
        .as_ref()
        .context("capacity unavailable")?
        .require_vcpu_budget()?;
    let mut session_options = options.clone();
    session_options.sandbox_vcpu_budget = Some(vcpu_budget);
    // Persist ceilings before the connection can advertise or accept effects.
    // Carried and queued lifecycle work may still create or start its VM, so
    // its absence now proves nothing (§4.9).
    crate::storage_capacity::reconstruct_live_except(runtime, journal, &busy())?;
    let pools =
        crate::storage_capacity::connect_pools_until(runtime, config, journal, interrupted)?;
    let static_capacity = sandbox_protocol::capacity_v11::HostStaticCapacityV11 {
        vm_capacity: sandbox_protocol::capacity_v11::VmCapacityV11 {
            memory_budget_mi_b: vm_capacity.memory_budget_mi_b,
            max_cpu_count: vm_capacity.max_cpu_count,
            vcpu_budget,
        },
        storage_pools: pools,
    };
    Ok(HostObservation {
        session_options,
        vm_capacity,
        static_capacity,
        sandbox_count,
    })
}

/// The host observation a reconnect skipped to dial at once.
/// It runs on a fenced worker while the socket is read (a blocklist applies
/// meanwhile; a transport loss returns without waiting for it), and gates
/// admission exactly as the pre-dial observation did: nothing is admitted
/// before it succeeded. A changed static tuple cannot be re-advertised in
/// this epoch, so it ends the session; the next reconnect advertises it.
#[allow(clippy::too_many_arguments)]
fn observe_after_hello(
    socket: &mut RelaySocket,
    key_control: super::journal_key::KeyControl<'_>,
    deferred: &mut super::reconcile::DeferredPushes,
    options: &ConnectOptions,
    runtime: &Arc<dyn SandboxRuntime>,
    journal: &Arc<HostJournal>,
    expiry: &super::expiry::ExpiryService,
    authority: &HostAuthority,
    relay: &RelaySupervisor,
    config: &crate::config::Config,
    observed: &mut HostObservations,
    advertised: &HostObservation,
    resolutions: &super::resolutions::InFlightResolutions,
) -> Result<HostObservation> {
    let mut census_busy = authority.pending_lifecycle_sandboxes();
    census_busy.extend(relay.lifecycle_busy());
    census_busy.extend(resolutions.busy_sandboxes());
    let mut busy = authority.pending_sandboxes();
    busy.extend(relay.lifecycle_busy());
    busy.extend(resolutions.busy_sandboxes());
    let (options, runtime, journal) = (options.clone(), runtime.clone(), journal.clone());
    let (expiry, config) = (expiry.handle(), config.clone());
    let mut last_capacity = observed.last_capacity.clone();
    let (result, last_capacity) = super::reconcile::while_reading(
        socket,
        "host observation",
        key_control,
        deferred,
        move |fence| {
            let result = (|| {
                let _refresh_pause = expiry.pause_dns_refresh(&options.shutdown)?;
                let guard = RuntimeIoGuard::over(&options.shutdown, fence.clone())?;
                let runtime = runtime.with_cancellation(guard.permit.clone());
                observe_host(
                    &options,
                    runtime.as_ref(),
                    &|| options.shutdown.requested() || fence.is_cancelled(),
                    &|| fence.is_cancelled(),
                    &journal,
                    &expiry,
                    &census_busy,
                    &|| busy.clone(),
                    &config,
                    &mut last_capacity,
                    // As before hello: a failed runtime observation keeps
                    // carried work detached for the next attempt.
                    &mut |error| error.context(TransportLost),
                )
            })();
            (result, last_capacity)
        },
    )?;
    observed.last_capacity = last_capacity;
    let fresh = result?;
    observed.advertised = Some(fresh.clone());
    if !fresh.same_static_tuple(advertised) {
        return Err(anyhow::anyhow!(
            "host capacity changed since the last session; reconnecting to advertise it"
        )
        .context(TransportLost));
    }
    Ok(fresh)
}

#[allow(clippy::too_many_arguments)]
fn relay_session_active(
    advertised: HostObservation,
    observe: Option<(&crate::config::Config, &mut HostObservations)>,
    protocol_runtime: sandbox_protocol::RuntimeKind,
    binding: &mut TransportBindingV11,
    runtime: Arc<dyn SandboxRuntime>,
    exec_supervisor: Option<CommandSupervisor>,
    journal: Arc<HostJournal>,
    authority: HostAuthority,
    expiry: &super::expiry::ExpiryService,
    relay: &RelaySupervisor,
    terminal_slots: &Arc<super::terminal::TerminalSlots>,
    channel_slots: &Arc<super::channel::ChannelSlots>,
    host_policy: &mut super::host_policy::HostPolicy,
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    resolutions: &super::resolutions::InFlightResolutions,
) -> Result<()> {
    let mut pending_puts: HashMap<String, PendingFilePut> = HashMap::new();
    let mut downloads = Downloads::new();
    let result = relay_session_loop(
        advertised,
        observe,
        protocol_runtime,
        binding,
        runtime,
        exec_supervisor,
        journal,
        authority.clone(),
        expiry,
        relay,
        terminal_slots,
        channel_slots,
        host_policy,
        socket,
        &mut pending_puts,
        &mut downloads,
        resolutions,
    );
    if let Some(credentials) = relay.credentials() {
        credentials.on_disconnect();
    }
    if let Some(images) = relay.images() {
        images.on_disconnect();
    }
    // Exit guard (§4.7): uploads still receiving chunks, downloads and
    // `file.get` cannot survive the socket; reconciliation reports them.
    // Everything else, including commands with open stdin, may be carried.
    for id in pending_puts.keys().chain(downloads.keys()) {
        authority.forget(id);
    }
    for id in authority.pending_of_kind("file.get") {
        authority.revoke_carried(&id);
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn relay_session_loop(
    advertised: HostObservation,
    mut observe: Option<(&crate::config::Config, &mut HostObservations)>,
    protocol_runtime: sandbox_protocol::RuntimeKind,
    binding: &mut TransportBindingV11,
    runtime: Arc<dyn SandboxRuntime>,
    exec_supervisor: Option<CommandSupervisor>,
    journal: Arc<HostJournal>,
    mut authority: HostAuthority,
    expiry: &super::expiry::ExpiryService,
    relay: &RelaySupervisor,
    terminal_slots: &Arc<super::terminal::TerminalSlots>,
    channel_slots: &Arc<super::channel::ChannelSlots>,
    host_policy: &mut super::host_policy::HostPolicy,
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    pending_puts: &mut HashMap<String, PendingFilePut>,
    downloads: &mut Downloads,
    resolutions: &super::resolutions::InFlightResolutions,
) -> Result<()> {
    let options = &advertised.session_options;
    let vm_capacity = advertised.vm_capacity;
    let static_capacity = advertised.static_capacity.clone();
    let sandbox_count = advertised.sandbox_count;
    let socket = &mut *socket;
    set_ws_timeouts(socket, Duration::from_millis(100), RELAY_WRITE_TIMEOUT)?;
    // Stdin failures complete through the process-scoped channel (N5).
    let finished_tx = relay.finished_sender();
    #[cfg(not(target_os = "linux"))]
    let _ = &finished_tx;

    let _key_session =
        super::journal_key::KeySession::start_carrying(journal.clone(), authority.clone());
    let mut live_admission = LiveSandboxAdmission::new(
        options
            .sandbox_vcpu_budget
            .unwrap_or(sandbox_protocol::vm_size_limits()?.host_vcpu_budget_max),
        vm_capacity,
    );

    live_admission.set_pools(static_capacity.storage_pools.clone());
    let egress_policy = runtime.egress_enforcement_capability().unwrap_or(false);
    if !egress_policy {
        warn_egress_unavailable(runtime.as_ref());
    }
    // B12: advertised only on the runtime's own word; refusals are reported
    // only on a session that advertised it.
    let egress_refused_hints = runtime.refused_dns_hints_capability();
    let mut refused_names = super::egress_hints::RefusedNameReporter::default();
    host_policy.refresh(Instant::now());
    let local_policy = host_policy.current();
    // §2.5: `egressOpen` is static per session (runtime + resolver support,
    // never guard health); the hello guard bit is display evidence only.
    // Guard health is live: the 5 s `host.egress-state` renews the lease.
    if let Some(node) = relay.egress() {
        host_policy.take_egress_change();
        node.apply_policy(
            host_policy.open_egress_for_others(),
            host_policy.guest_sudo_for_others(),
            host_policy.egress_settings().clone(),
        );
    }
    let egress_capabilities = sandbox_protocol::EgressCapabilitiesV11 {
        open: runtime
            .egress_open_capability(host_policy.egress_settings())
            .unwrap_or(false),
        guard: runtime.egress_guard_check().is_ok(),
    };
    // The hello carries the live ceiling; any change seen so far is reported
    // by it, and the journal enforces the same value.
    host_policy.take_lease_change();
    journal.set_lease_ceiling(host_policy.lease_ceiling());
    if let Some(images) = relay.images() {
        images.configure_pools(runtime.as_ref(), &static_capacity.storage_pools);
    }
    // WP7: a reconnect while quiescing says so in its hello.
    let mut quiesce = super::quiesce::QuiesceLink::new(&options.shutdown);
    let hello = DaemonControlMessage::Hello {
        id: "hello-1".to_string(),
        protocol_version: SANDBOX_RELAY_PROTOCOL_VERSION.to_string(),
        supported_protocol_versions: vec![SANDBOX_RELAY_PROTOCOL_VERSION.to_owned()],
        daemon: DaemonHello {
            host_id: options.host_id.clone(),
            label: options.label.clone(),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            capabilities: DaemonCapabilities {
                host_terminal: local_policy.enabled
                    && matches!(protocol_runtime, sandbox_protocol::RuntimeKind::IncusKvm),
                host_commands: host_policy.agent().enabled,
                host_files: host_policy.agent().enabled && !host_policy.agent().roots.is_empty(),
                host_command_max_ms: host_policy
                    .agent()
                    .enabled
                    .then_some(host_policy.agent().max_ms),
                agent_policy_revision: host_policy.agent().revision,
                require_host_terminal_totp: local_policy.required,
                policy_revision: local_policy.revision,
                terminal: runtime.pty_capability(),
                max_lease_ms: host_policy.lease_ceiling(),
                image: relay.images().map(|images| images.capabilities()),
                egress_refused_hints,
                credentials: relay.credentials().map(|c| c.capabilities()),
                egress: egress_capabilities,
                quiesce: super::quiesce::QuiesceLink::capability(&options.shutdown),
                terminal_resume: terminal_slots.resume_capability(runtime.pty_capability()),
                command_retire: true,
                guest_sudo: !matches!(protocol_runtime, sandbox_protocol::RuntimeKind::Unsupported),
                // Disk offload also requires `image.fetch`.
                disk_offload: DISK_OFFLOAD_SUPPORTED
                    && relay.offload().is_some()
                    && relay
                        .images()
                        .is_some_and(|images| images.capabilities().fetch),
                tunnel: super::tunnel::installed().map(|tunnels| tunnels.capability()),
                // Every real runtime compiles a launch's `tunnelPorts` into
                // its recorded plan, whether or not a client is installed.
                channels: super::channel::capability(&*runtime),
                tunnel_ports: !matches!(
                    protocol_runtime,
                    sandbox_protocol::RuntimeKind::Unsupported
                ),
                ..daemon_capabilities(protocol_runtime.clone(), egress_policy)
            },
        },
        inventory: HostInventorySnapshot {
            host_id: options.host_id.clone(),
            // WP2: a latched journal is reported, so placement skips the host.
            schedulable: !journal.io_failed(),
            sandbox_count,
        },
        vm_capacity: static_capacity.vm_capacity.clone(),
        storage_pools: static_capacity.storage_pools.clone(),
        quiescing: quiesce.hello_flag(),
    };
    // D3b: new frames stay 8 KiB until this connection's `hello.ok` answers.
    relay.set_output_chunk_bytes(None);
    // Nothing is negotiated until this session's `hello.ok`, and
    // every exit of this session (any return, error or panic) revokes it.
    let _retire_scope = super::command_retire::SessionScope::begin(&journal);
    socket.send(Message::Text(super::plain_frame(&hello)?.into()))?;

    let (observations_tx, observations_rx) = mpsc::sync_channel::<DaemonControlMessage>(16);
    let mut registered = false;
    let mut hello_accepted = false;
    // Server pushes that arrived during reconciliation, processed first once
    // registered, in arrival order (they precede every later frame).
    let mut deferred = super::reconcile::DeferredPushes::default();
    let mut images_ready = false;
    // Credential frames flow only after reconciliation (the census needs it).
    let mut credentials_ready = false;
    let mut last_image_sweep = Instant::now();
    // Out-of-band image deletions (one Incus inventory read) and a periodic
    // census so the server's view converges without a reconnect.
    let mut last_image_reconcile = Instant::now();
    let mut last_image_census = Instant::now();
    // Disk offload reconciliation after `hello.ok` (`disk_ready`) and its
    // periodic pass on a live connection (`OffloadService::tick`).
    let mut disk_ready = false;
    let mut last_disk_tick = Instant::now();
    // Every registered session uses the exact 1.0 vocabulary.
    let mut wire = WireCodes::CURRENT;
    let mut admission_epoch: Option<u64> = None;
    // Dropped on every loop exit: stops every PTY of this connection.
    let mut terminals = super::terminal::TerminalHost::new(
        terminal_slots.clone(),
        runtime.clone(),
        journal.clone(),
        authority.clone(),
        options.host_id.clone(),
    );
    terminals.set_credentials(relay.credentials().cloned());
    // WP7: new terminal opens are refused once quiescing.
    terminals.set_quiesce(options.shutdown.quiesce_handle());
    // Dropped on every loop exit: kill-closes every channel of this connection.
    let mut channels = super::channel::ChannelHost::new(
        channel_slots.clone(),
        Arc::new(super::channel::ChannelRegistry::new(journal.clone())),
        runtime.clone(),
        journal.clone(),
        authority.clone(),
        options.host_id.clone(),
    );
    channels.set_credentials(relay.credentials().cloned());
    channels.set_quiesce(options.shutdown.quiesce_handle());
    let host_opener: Option<Arc<dyn sandbox_runtime::HostPtyOpener>> =
        if matches!(protocol_runtime, sandbox_protocol::RuntimeKind::IncusKvm) {
            Some(Arc::new(sandbox_runtime::LocalHostPtyOpener::default()))
        } else {
            None
        };
    terminals.configure_host(local_policy, host_opener.clone());
    let mut host_access =
        super::host_access::HostAccess::new(&options.host_token, options.state_dir.as_ref());
    let mut agent_sequence = 0u64;
    let mut agent_report_pending = true;
    let mut policy_sequence = 0u64;
    let mut policy_report_pending = true;
    let mut lease_sequence = 0u64;
    let mut lease_report_pending = false;
    let (raise_tx, raise_rx) = mpsc::sync_channel::<bool>(1);
    let mut raise_pending = false;
    let mut raise_requests = std::collections::VecDeque::new();
    // §2.5 guard lease and storage health: renewed on the session's own
    // cadence, by reconciliation's readers and by this loop (`host_reports`).
    deferred.install_reports(super::host_reports::HostReports::new(
        report_clock(),
        options.host_id.clone(),
        u32::try_from(live_admission.held())?,
        relay.egress().cloned(),
        runtime.clone(),
        static_capacity.storage_pools.clone(),
        relay.storage_observer(),
        {
            let journal = journal.clone();
            Arc::new(move || !journal.io_failed())
        },
    )?);
    let mut last_heartbeat = Instant::now();
    let mut heartbeat_sequence = 0u64;
    let mut expiry_reported = super::reconcile::ExpiryReported::new();
    /// A failed observation is retried after bounded backoff.
    enum ExpiryObservation {
        Offer(Option<super::reconcile::ExpiryOffer>),
    }
    let (expiry_tx, expiry_rx) = mpsc::sync_channel::<ExpiryObservation>(1);
    let mut expiry_observing = false;
    // Codex WP2 r1 #6: a failed observation delays the next one.
    let mut expiry_backoff = super::evidence::ObservationBackoff::default();
    let heartbeat = session_heartbeat(if options.heartbeat.is_zero() {
        Duration::from_secs(5)
    } else {
        options.heartbeat
    });
    // Minor 2: a half-open socket must not hold carried work "attached".
    let silence_deadline = server_silence_deadline(heartbeat);
    let mut silent = Duration::ZERO;
    // WP2: reconciliation's socket pumps keep the same deadline.
    deferred.set_silence_deadline(silence_deadline);
    // fu-a: set when the loop first observes a shutdown request; the flush
    // bound itself counts from the request (fu-d3).
    let mut shutdown_flush: Option<Instant> = None;
    // fu-d3: the shutdown request itself arms the IO bound (a short grace
    // past the flush lets the loop's own check close normally), so a frame
    // already trickling when it lands cannot hold the loop in `read`.
    let mut flush_deadline = FlushDeadline::after_shutdown(
        socket,
        &options.shutdown,
        SHUTDOWN_FLUSH + Duration::from_millis(500),
    );

    loop {
        // Reload before checking local enable witnesses, so a released lower
        // block updates file policy and reports in this same iteration.
        let refreshed_terminal = host_policy.refresh(Instant::now());
        let lowered_terminal = host_access.tick(host_policy);
        if refreshed_terminal || lowered_terminal {
            terminals.configure_host(host_policy.current(), host_opener.clone());
            policy_report_pending = true;
        }
        if raise_rx.try_recv().is_ok() {
            raise_pending = false;
            // Read the persisted tuple; failed persistence never confirms a raise.
            policy_report_pending |= host_policy.refresh(Instant::now() + Duration::from_secs(1));
            terminals.configure_host(host_policy.current(), host_opener.clone());
        }
        if registered
            && policy_report_pending
            && let Some(epoch) = admission_epoch
        {
            let policy = host_policy.current();
            policy_sequence += 1;
            socket.send(Message::Text(
                super::plain_frame(&DaemonControlMessage::HostTerminalPolicy(
                    sandbox_protocol::HostTerminalPolicyV11 {
                        connection_epoch: u32::try_from(epoch)?,
                        sequence: policy_sequence,
                        host_terminal: policy.enabled && host_opener.is_some(),
                        require_host_terminal_totp: policy.required,
                        policy_revision: policy.revision,
                    },
                ))?
                .into(),
            ))?;
            policy_report_pending = false;
        }
        if host_policy.take_agent_change() {
            host_access.changed(host_policy.agent());
            agent_report_pending = true;
        }
        if registered
            && agent_report_pending
            && let Some(epoch) = admission_epoch
        {
            agent_sequence += 1;
            socket.send(Message::Text(
                super::plain_frame(&DaemonControlMessage::HostAgentPolicy(
                    host_policy
                        .agent()
                        .report(u32::try_from(epoch)?, agent_sequence),
                ))?
                .into(),
            ))?;
            agent_report_pending = false;
        }
        if options.shutdown.requested() {
            host_access.shutdown();
        }
        if registered {
            for frame in host_access.replies() {
                socket.send(Message::Text(super::plain_frame(&frame)?.into()))?;
            }
            if let Some(tunnels) = super::tunnel::installed() {
                for status in tunnels.drain_events() {
                    socket.send(Message::Text(
                        super::plain_frame(&DaemonControlMessage::TunnelStatus(status))?.into(),
                    ))?;
                }
            }
            if let Some(ports) = super::tunnel_ports::installed() {
                for status in ports.drain() {
                    socket.send(Message::Text(
                        super::plain_frame(&DaemonControlMessage::TunnelPortsStatus(status))?
                            .into(),
                    ))?;
                }
            }
        }
        // The host lease ceiling is reported separately from the terminal
        // policy: a change never bumps the terminal policy revision. The
        // journal enforces the new value at once; the daemon never shortens
        // existing leases itself — the server pulls them in after the report.
        if host_policy.take_lease_change() {
            let ceiling = host_policy.lease_ceiling();
            journal.set_lease_ceiling(ceiling);
            let over =
                journal.leases_over_ceiling(journal.clock.now_ms().unwrap_or_default(), ceiling);
            tracing::info!(
                ceiling = %super::host_policy::describe_ceiling(ceiling),
                leases_over_ceiling = over,
                "host lease ceiling changed; the server shortens longer leases after this report"
            );
            lease_report_pending = true;
        }
        if registered
            && lease_report_pending
            && let Some(epoch) = admission_epoch
        {
            lease_sequence += 1;
            socket.send(Message::Text(
                super::plain_frame(&DaemonControlMessage::HostLeasePolicy(
                    sandbox_protocol::HostLeasePolicyV11 {
                        connection_epoch: u32::try_from(epoch)?,
                        sequence: lease_sequence,
                        max_lease_ms: host_policy.lease_ceiling(),
                    },
                ))?
                .into(),
            ))?;
            lease_report_pending = false;
        }
        // WP7: `host.quiesce` once registered.
        if let Some(frame) =
            quiesce.poll(&options.shutdown, admission_epoch.filter(|_| registered))?
        {
            socket.send(Message::Text(super::plain_frame(&frame)?.into()))?;
        }
        if egress_refused_hints {
            // An in-memory queue read: the runtime's hint maintenance (DNS
            // stub recovery) runs on its own worker, so control frames are
            // never read behind it.
            for (sandbox_id, name) in runtime.drain_refused_dns_names() {
                refused_names.observe(&sandbox_id, &name);
            }
            if registered {
                for report in refused_names.drain(Instant::now()) {
                    socket.send(Message::Text(
                        super::plain_frame(&DaemonControlMessage::EgressRefused(report))?.into(),
                    ))?;
                }
            }
        }
        if host_policy.take_egress_change()
            && let Some(node) = relay.egress()
        {
            node.apply_policy(
                host_policy.open_egress_for_others(),
                host_policy.guest_sudo_for_others(),
                host_policy.egress_settings().clone(),
            );
        }
        // fu-a: a finished command's tail output and result are published
        // (and their ACKs and confirmation read) before the close, at most
        // SHUTDOWN_FLUSH; nothing pending closes at once. Running commands
        // are not waited for: the exit revokes them as before.
        let flushing = options.shutdown.requested()
            && registered
            && {
                let until = match shutdown_flush {
                    Some(until) => until,
                    None => {
                        let until = options.shutdown.requested_at().unwrap_or_else(Instant::now)
                            + SHUTDOWN_FLUSH;
                        shutdown_flush = Some(until);
                        if relay.shutdown_flush_pending() {
                            tracing::info!(
                                "publishing finished command results before closing the relay"
                            );
                        }
                        until
                    }
                };
                let pending = relay.shutdown_flush_pending();
                if pending && Instant::now() >= until {
                    tracing::warn!(
                        flush_secs = SHUTDOWN_FLUSH.as_secs(),
                        "closing with finished command results still unconfirmed; the next daemon reports them"
                    );
                }
                pending && Instant::now() < until
            };
        if options.shutdown.requested() && !flushing {
            // The flush is over. One that delivered everything closes as
            // always; one that ran out of time faces a stuck or hung peer, so
            // its close (terminal exits, close frame) gets a short IO bound
            // of its own instead of every write's 30 s timeout.
            let timed_out = shutdown_flush.is_some() && relay.shutdown_flush_pending();
            drop(flush_deadline.take());
            let _close_deadline = if timed_out {
                FlushDeadline::arm(socket, Instant::now() + SHUTDOWN_FLUSH_CLOSE)
            } else {
                None
            };
            // C55 (C52-TB-3): terminals first, each with its `shutdown` exit
            // on the wire, then a normal close. Nothing reconnects.
            terminals.shutdown(TERMINAL_SHUTDOWN_DRAIN, |frame| {
                send_terminal_frame(socket, wire, frame)
            })?;
            channels.shutdown(TERMINAL_SHUTDOWN_DRAIN, |frame| {
                send_terminal_frame(socket, wire, frame)
            })?;
            let _ = socket.close(Some(tungstenite::protocol::CloseFrame {
                code: tungstenite::protocol::frame::coding::CloseCode::Normal,
                reason: "daemon shutdown".into(),
            }));
            let _ = socket.flush();
            return Err(anyhow::anyhow!("node daemon shutting down").context(CleanShutdown));
        }
        // Host reports with a server-side TTL (egress lease, storage health).
        // Older census proofs are discarded below when their sequence is stale.
        if let Some(reports) = deferred.reports() {
            reports.tick(socket)?;
            if let Some(health) = reports.take_health() {
                live_admission.update_health(&health);
            }
            if reports.storage_expired()? {
                live_admission.expire_storage_health();
            }
        }
        // Nothing publishes before registration (M5): carried results,
        // output and births wait in their bounded queues for adoption.
        if registered {
            for frame in relay.poll_output()? {
                socket.write(Message::Binary(frame.encoded()))?;
            }
            // Best-effort start observations before results; final receipts repeat
            // identity, so a lost frame is availability uncertainty only.
            for started in relay.poll_started() {
                socket.write(Message::Text(
                    super::spell(wire, &DaemonControlMessage::from(started), None)?.into(),
                ))?;
            }
            for message in observations_rx.try_iter().take(16) {
                socket.write(Message::Text(super::spell(wire, &message, None)?.into()))?;
            }
            // Credential frames precede results (an install's `installed`
            // frames reach the server before the create's READY result).
            if credentials_ready && let Some(credentials) = relay.credentials() {
                for message in credentials.drain() {
                    socket.write(Message::Text(super::spell(wire, &message, None)?.into()))?;
                }
            }
            // Image frames only after reconciliation (the server refuses earlier).
            if images_ready && let Some(images) = relay.images() {
                send_image_batch(socket, wire, images)?;
                if last_image_sweep.elapsed() >= Duration::from_secs(5) {
                    last_image_sweep = Instant::now();
                    images.resend_reports();
                    images.sweep_foreign();
                    images.sweep_staging();
                    images.poll_prune_request();
                    images.poll_list_request();
                }
                if last_image_reconcile.elapsed() >= Duration::from_secs(60) {
                    last_image_reconcile = Instant::now();
                    images.spawn_reconcile();
                }
                if last_image_census.elapsed() >= Duration::from_secs(600) {
                    last_image_census = Instant::now();
                    images.begin_periodic_census();
                }
            }
            if disk_ready
                && last_disk_tick.elapsed() >= disk_tick_every()
                && let Some(offload) = relay.offload()
            {
                last_disk_tick = Instant::now();
                offload.tick();
            }
            drain_finished(
                socket,
                wire,
                &authority,
                &mut live_admission,
                relay,
                &journal,
                downloads,
                egress_refused_hints.then_some(StepEndHints {
                    runtime: runtime.as_ref(),
                    reporter: &mut refused_names,
                }),
            )?;
            // WP2: a receipt resolution deferred by reconciliation is
            // delivered as soon as it finishes; `receipt.confirmed` clears it.
            // A failed one ends the session: the reconnect retries it.
            for (operation_id, finished) in resolutions.take_finished() {
                let receipt = finished.with_context(|| {
                    format!("deferred receipt resolution for {operation_id} failed")
                })?;
                super::reconcile::send_receipt(socket, wire, receipt)?;
            }
            // Per-command proofs for `retireCommand` confirmations.
            super::command_retire::start(&journal, &authority, &runtime, relay, binding);
        }
        let storage_sequence = deferred
            .reports()
            .map_or(0, |reports| reports.storage_sequence());
        match expiry_rx.try_recv() {
            Ok(ExpiryObservation::Offer(offer)) => {
                expiry_observing = false;
                if offer.is_some() {
                    expiry_backoff.succeeded();
                } else {
                    expiry_backoff.failed(Instant::now());
                }
                // As above, an overtaken observation is retried, never sent.
                if let Some(offer) = offer.filter(|offer| {
                    !offer.entries.iter().any(|entry| {
                        entry
                            .root
                            .as_ref()
                            .is_some_and(|root| root.observation_sequence < storage_sequence)
                    })
                }) {
                    let offered: std::collections::BTreeSet<&str> = offer
                        .entries
                        .iter()
                        .map(|entry| entry.sandbox_id.as_str())
                        .collect();
                    // A changed arm with nothing to observe is reported as
                    // is; a re-offer whose evidence is gone is obsolete. A
                    // raced entry (its lease changed while observing) is
                    // neither: the next observation retries it.
                    for (id, change) in &offer.changes {
                        if !offered.contains(id.as_str()) && !offer.raced.contains(id) {
                            match change {
                                Some(arm) => expiry_reported.insert(id.clone(), *arm),
                                None => expiry_reported.remove(id),
                            };
                        }
                    }
                    let health = deferred.published_health();
                    let evidence = deferred.evidence();
                    for id in &offer.reoffered {
                        if !offered.contains(id.as_str()) && !offer.raced.contains(id) {
                            evidence.forget(id);
                        }
                    }
                    for frame in evidence.offer(
                        offer.entries,
                        &offer.changes,
                        &offer.bindings,
                        storage_sequence,
                        &health,
                        Instant::now(),
                    ) {
                        socket.write(Message::Text(super::plain_frame(&frame)?.into()))?;
                    }
                }
            }
            Err(_) => {}
        }
        if deferred.evidence().overdue(Instant::now()) {
            return Err(
                anyhow::anyhow!("expiry status acknowledgement timed out").context(TransportLost)
            );
        }
        if registered {
            // Journal state only, no runtime IO: a completed local expiry frees
            // the slot unless a newer generation has acquired it since.
            for id in live_admission.sandbox_ids() {
                if let Some(row) = journal.lease(&id)
                    && row.expired
                    && row.expiry_complete
                {
                    live_admission.release_expired(&id, row.generation);
                    if row.root_deleted {
                        live_admission.release_root_confirmed(&id, row.generation);
                    }
                }
            }
        }
        // One owner settles every expired, cancelled, superseded or drained
        // transfer before any further frame for it can be produced.
        for item in settle_transfers(
            Instant::now(),
            pending_puts,
            downloads,
            &authority,
            &journal,
        )? {
            let kind = journal.lookup(&item.operation_id).map(|r| r.kind);
            send_finished(socket, wire, kind.as_deref(), item)?;
        }
        for (id, (item, window)) in downloads.iter_mut() {
            if authority
                .accept_stream(id, item.generation, item.attempt)
                .is_err()
            {
                continue;
            }
            if let Some(frame) = window.poll(id, item.generation, item.attempt, Instant::now())? {
                socket.write(Message::Binary(frame.encoded()))?;
            }
        }
        // Bounded per session per tick: a flooding PTY never starves the
        // heartbeat, dispatch or cancellation handling below.
        for frame in terminals.poll()? {
            write_terminal_frame(socket, wire, frame)?;
        }
        channels.poll_with(&mut |frame| write_terminal_frame(socket, wire, frame))?;
        // One flush for the whole batch above (output, starts, observations,
        // credentials, images, expiry and download frames, terminals).
        socket.flush()?;
        // A shutdown flush (fu-a) starts no new expiry observation: it only
        // delivers what already finished; the next daemon re-offers evidence.
        let observe_expiry = registered && shutdown_flush.is_none();
        if observe_expiry {
            // WP2: evidence is offered until the server judged it converged;
            // one batch in flight at a time, retries paced by observations.
            let failures = expiry.failures();
            let completions = expiry.completions();
            let health = deferred.published_health();
            let reoffer = deferred.evidence().due(storage_sequence, &health);
            // A refused arm waiting for a newer observation is paced by its
            // re-offer, never by the digest.
            let blocked = deferred.evidence().blocked(storage_sequence, &health);
            if !expiry_observing
                && expiry_backoff.ready(Instant::now())
                && !deferred.evidence().awaiting()
                && (!reoffer.is_empty()
                    || !super::reconcile::expiry_changes(
                        &failures,
                        &completions,
                        &expiry_reported,
                        &blocked,
                    )
                    .is_empty())
            {
                let journal = journal.clone();
                let runtime = runtime.with_cancellation(Arc::new(
                    sandbox_runtime::RuntimePermit::with_timeout(expiry_observation_timeout()),
                ));
                let observation_sequence = storage_sequence;
                let reported = expiry_reported.clone();
                let tx = expiry_tx.clone();
                expiry_observing = relay
                    .observe(move || {
                        let offer = match super::reconcile::expiry_status_offer(
                            &journal,
                            runtime.as_ref(),
                            &failures,
                            &completions,
                            &reported,
                            reoffer,
                            &blocked,
                        ) {
                            Ok(mut offer) => {
                                for root in offer.entries.iter_mut().filter_map(|e| e.root.as_mut())
                                {
                                    root.observation_sequence = observation_sequence;
                                }
                                Some(offer)
                            }
                            Err(error) => {
                                tracing::warn!("expiry status unavailable: {error:#}");
                                None
                            }
                        };
                        let _ = tx.try_send(ExpiryObservation::Offer(offer));
                    })
                    .is_ok();
            }
        }
        if registered && last_heartbeat.elapsed() >= heartbeat {
            journal.maintain()?;
            relay.resume_teardowns(&journal, binding)?;
            last_heartbeat = Instant::now();
            heartbeat_sequence += 1;
            socket.send(Message::Text(
                super::plain_frame(&DaemonControlMessage::Heartbeat {
                    id: format!("hb-{heartbeat_sequence}"),
                    sent_at: None,
                    policy_reconciler: Some(runtime.policy_reconciler_health()),
                })?
                .into(),
            ))?;
        }
        let read_started = Instant::now();
        let held = if registered { deferred.next() } else { None };
        let read = match held {
            Some(held) => Ok(held),
            None => socket.read(),
        };
        let message = match read {
            Ok(message) => {
                silent = Duration::ZERO;
                message
            }
            Err(tungstenite::Error::Io(err))
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                // Only idle read time counts; local work between reads
                // (rebuild, reconciliation, dispatch admission) never does.
                silent += read_started.elapsed();
                if silent >= silence_deadline {
                    return Err(
                        anyhow::anyhow!("relay server silent for {}s", silent.as_secs())
                            .context(TransportLost),
                    );
                }
                continue;
            }
            Err(err) => return Err(err.into()),
        };
        match message {
            Message::Text(text) => {
                // fu-a: a shutdown flush admits no new work, and judges that
                // before any parse can act (key and config installs do).
                if shutdown_flush.is_some() && !shutdown_flush_frame(&text) {
                    continue;
                }
                let Some(control) = (super::journal_key::KeyControl {
                    journal: &journal,
                    binding,
                    epoch: admission_epoch.filter(|_| registered),
                    // The dispatch loop routes credential frames itself.
                    credentials: None,
                })
                .parse(&text, socket)?
                else {
                    continue;
                };
                match control {
                    ServerControlMessage::TunnelApply(req) => {
                        if registered && let Some(tunnels) = super::tunnel::installed() {
                            tunnels.apply(req);
                        }
                    }
                    ServerControlMessage::TunnelClear(req) => {
                        if registered && let Some(tunnels) = super::tunnel::installed() {
                            tunnels.clear(&req);
                        }
                    }
                    ServerControlMessage::TunnelPorts(req) => {
                        if registered && let Some(ports) = super::tunnel_ports::installed() {
                            ports.submit(req);
                        }
                    }
                    ServerControlMessage::HostPolicyLower(req) => {
                        if registered && admission_epoch == Some(u64::from(req.connection_epoch)) {
                            if req.target == sandbox_protocol::HostPolicyLowerTarget::HostTerminal {
                                let mut off = host_policy.current(); off.enabled = false;
                                terminals.configure_host(off, host_opener.clone());
                            }
                            host_access.lower(req, options.state_dir.clone(), host_policy);
                        }
                    }
                    ServerControlMessage::HostExecStart(req) => {
                        if registered && admission_epoch == Some(u64::from(req.connection_epoch)) {
                            if host_policy.refresh(Instant::now()) {
                                terminals.configure_host(host_policy.current(),host_opener.clone());
                                policy_report_pending=true;
                            }
                            if host_policy.take_agent_change() { host_access.changed(host_policy.agent()); agent_report_pending=true; }
                            let frame = host_access.start(req,host_policy.agent());
                            socket.send(Message::Text(super::plain_frame(&frame)?.into()))?;
                        }
                    }
                    ServerControlMessage::HostExecPoll(req) => {
                        if registered && admission_epoch == Some(u64::from(req.connection_epoch)) {
                            let frame=host_access.commands.poll(&req.command_id,Some(req.request_id),req.stdout_offset,req.stderr_offset,req.max_bytes);
                            socket.send(Message::Text(super::plain_frame(&frame)?.into()))?;
                        }
                    }
                    ServerControlMessage::HostExecStdin(req) => {
                        if registered && admission_epoch == Some(u64::from(req.connection_epoch)) {
                            if host_policy.refresh(Instant::now()) {
                                terminals.configure_host(host_policy.current(),host_opener.clone());
                                policy_report_pending=true;
                            }
                            if host_policy.take_agent_change() { host_access.changed(host_policy.agent()); agent_report_pending=true; }
                            let frame=host_access.stdin(req,host_policy.agent());
                            socket.send(Message::Text(super::plain_frame(&frame)?.into()))?;
                        }
                    }
                    ServerControlMessage::HostExecCancel(req) => {
                        if registered && admission_epoch == Some(u64::from(req.connection_epoch)) {
                            host_access.commands.cancel(&req.command_id,sandbox_protocol::HostExecState::Cancelled);
                            let frame=host_access.commands.poll(&req.command_id,Some(req.request_id),0,0,0);
                            socket.send(Message::Text(super::plain_frame(&frame)?.into()))?;
                        }
                    }
                    ServerControlMessage::HostFileRequest(req) => {
                        if registered && admission_epoch == Some(u64::from(req.connection_epoch())) {
                            if host_policy.refresh(Instant::now()) {
                                terminals.configure_host(host_policy.current(),host_opener.clone());
                                policy_report_pending=true;
                            }
                            if host_policy.take_agent_change() { host_access.changed(host_policy.agent()); agent_report_pending=true; }
                            if let Some(files)=&mut host_access.files && let Some(frame)=files.request(req) {
                                socket.send(Message::Text(super::plain_frame(&frame)?.into()))?;
                            }
                        }
                    }
                    ServerControlMessage::HostTerminalPolicyRaise {
                        connection_epoch,
                        request_id,
                    } => {
                        // Direction/epoch/grammar is checked before persistence. No offline queue.
                        if !registered
                            || admission_epoch != Some(u64::from(connection_epoch))
                            || raise_pending
                            || raise_requests.contains(&request_id)
                        {
                            continue;
                        }
                        if raise_requests.len() == 64 {
                            raise_requests.pop_front();
                        }
                        raise_requests.push_back(request_id);
                        // Config/auth locking and fsync never block the socket control lane.
                        let done = raise_tx.clone();
                        let fixture_dir = options.state_dir.clone();
                        if thread::Builder::new()
                            .name("wssp-host-policy-raise".into())
                            .spawn(move || {
                                let deadline = Some(Instant::now() + Duration::from_secs(2));
                                let store = match fixture_dir {
                                    Some(dir) => crate::state::AuthStore::at(
                                        dir.join("policy-state"),
                                        dir.join("config.toml"),
                                        deadline,
                                    ),
                                    None => crate::state::AuthStore::open(deadline),
                                };
                                let saved = store
                                    .and_then(|store| {
                                        store.update_config(|c| c.set_host_terminal_totp(true))
                                    })
                                    .is_ok();
                                let _ = done.try_send(saved);
                            })
                            .is_ok()
                        {
                            raise_pending = true;
                        }
                    }
                    ServerControlMessage::HelloOk {
                        protocol_version,
                        host_owner_id,
                        capabilities,
                        supported_protocol_versions,
                        connection_epoch,
                        ..
                    } => {
                        if !sandbox_protocol::known_protocol_version(&protocol_version)
                            || capabilities.protocol_version != protocol_version
                            || supported_protocol_versions != vec![SANDBOX_RELAY_PROTOCOL_VERSION.to_owned()]
                        {
                            return Err(anyhow::anyhow!("unsupported relay protocol version").context(ServerVerdict).context(TerminalHelloRefusal));
                        }
                        if capabilities.output_chunk_bytes.is_none() || !capabilities.census_entry_results
                            || !capabilities.pending_receipts || !capabilities.expiry_status_results
                            || !capabilities.observation_fence || !capabilities.command_retire {
                            return Err(anyhow::anyhow!("hello.ok omitted required relay capabilities")
                                .context(ServerVerdict).context(TerminalHelloRefusal));
                        }
                        if registered || hello_accepted {
                            bail!("duplicate hello.ok");
                        }
                        hello_accepted = true;
                        wire = WireCodes::negotiated(&protocol_version);
                        let epoch = connection_epoch.context("hello.ok requires an epoch")?;
                        let quiesce_negotiated = capabilities.quiesce;
                        relay.set_output_chunk_bytes(capabilities.output_chunk_bytes);
                        // `retireCommand` only when answered here,
                        // and only to this session's own offer.
                        journal.set_command_retire(
                            capabilities.command_retire,
                        );
                        if let Some(images) = relay.images() {
                            images.on_registered(&host_owner_id);
                        }
                        if let Some(credentials) = relay.credentials() {
                            credentials.on_registered(&host_owner_id);
                        }
                        if let Some(node) = relay.egress() {
                            node.set_host_owner(&host_owner_id);
                        }
                        host_access.register(&host_owner_id, host_policy.agent())?;
                        binding.host_owner_id = host_owner_id;
                        // New dispatches bind to this epoch; carried work stays
                        // bound to its own until the adoption step below.
                        authority.attach(epoch);
                        // The hello reset the server's guard lease and storage
                        // observation; renew both on this epoch at once and
                        // keep them fresh through reconciliation (an Intent
                        // create's adoption re-runs those gates).
                        if let Some(reports) = deferred.reports() {
                            reports.attach(epoch, wire)?;
                            reports.tick(socket)?;
                        }
                        let mut census_busy = authority.pending_lifecycle_sandboxes();
                        census_busy.extend(relay.lifecycle_busy());
                        census_busy.extend(resolutions.busy_sandboxes());
                        // E6 / ruling (d): from here to `reconcile.complete`
                        // the socket is always read, and a blocklist sent
                        // right after hello.ok reaches the guard at once,
                        // even while this inventory or reconciliation's
                        // census blocks on the host daemon.
                        deferred.handle_egress_with(relay.egress().cloned());
                        // A reconnect that dialed at once runs
                        // the host observation it skipped here, before any
                        // admission, while the socket is read.
                        if let Some((config, observed)) = observe.take() {
                            let fresh = observe_after_hello(
                                socket,
                                super::journal_key::KeyControl {
                                    journal: &journal,
                                    binding,
                                    epoch: Some(epoch),
                                    credentials: relay.credentials(),
                                },
                                &mut deferred,
                                options,
                                &runtime,
                                &journal,
                                expiry,
                                &authority,
                                relay,
                                config,
                                observed,
                                &advertised,
                                resolutions,
                            )?;
                            // Same static tuple; fresher usage for local admission.
                            live_admission.set_pools(fresh.static_capacity.storage_pools);
                            census_busy = authority.pending_lifecycle_sandboxes();
                            census_busy.extend(relay.lifecycle_busy());
                            census_busy.extend(resolutions.busy_sandboxes());
                        }
                        let inventory = {
                            let runtime = runtime.clone();
                            super::reconcile::while_reading(
                                socket,
                                "admission inventory",
                                super::journal_key::KeyControl {
                                    journal: &journal,
                                    binding,
                                    epoch: Some(epoch),
                                    credentials: relay.credentials(),
                                },
                                &mut deferred,
                                move |fence| {
                                    runtime
                                        .with_cancellation(fence)
                                        .sandbox_inventory_skipping(&census_busy)
                                },
                            )??
                        };
                        live_admission.rebuild(&inventory, &journal, binding)?;
                        for (id, _) in authority.carried() {
                            if let Some(receipt) = journal.lookup(&id) {
                                live_admission.restore_carried(&receipt);
                            }
                        }
                        terminals.enable(epoch, binding.clone());
                        // WP8: detach and resume only when the server answered.
                        terminals.negotiate_resume(capabilities.terminal_resume);
                        // Channels only when this node offered them and the
                        // server echoed the offer.
                        channels.enable(
                            epoch,
                            binding.clone(),
                            runtime.channel_capability() && capabilities.channels.is_some(),
                        );
                        admission_epoch = Some(epoch);
                        socket.send(Message::Text(
                            super::spell(
                                wire,
                                &DaemonControlMessage::HostAdmission {
                                    journal_id: journal.instance_id().to_owned(),
                                    vm_capacity: static_capacity.vm_capacity.clone(),
                                    storage_pools: static_capacity.storage_pools.clone(),
                                    connection_epoch: epoch,
                                    runtime_kind: hello_runtime_kind(&hello),
                                    schedulable: !journal.io_failed(),
                                    egress_policy,
                                    terminal: runtime.pty_capability(),
                                    image: relay.images().map(|images| images.admission()),
                                    egress_open: egress_capabilities.open,
                                },
                                None,
                            )?
                            .into(),
                        ))?;
                        expiry_reported = reconcile_after_hello(
                            &journal,
                            binding,
                            &runtime,
                            socket,
                            wire,
                            expiry,
                            admission_epoch,
                            Some(&super::reconcile::Adoption {
                                authority: &authority,
                                relay,
                                epoch,
                                resolutions,
                            }),
                            &mut deferred,
                        )?;
                        if let Some(images) = relay.images() {
                            images.begin_census();
                            images_ready = true;
                        }
                        // Unfinished offloads are re-acked or
                        // released from the server's rows (after the census,
                        // in the same outbox).
                        if hello_disk_offload(&hello)
                            && let Some(offload) = relay.offload()
                        {
                            offload.on_connection();
                            disk_ready = true;
                            last_disk_tick = Instant::now();
                        }
                        if let Some(credentials) = relay.credentials() {
                            credentials.begin_census();
                            credentials_ready = true;
                        }
                        // Refused carried commands lose their exec as well.
                        #[cfg(target_os = "linux")]
                        if let Some(supervisor) = &exec_supervisor {
                            for id in authority.take_revoked_execs() {
                                let supervisor = supervisor.clone();
                                relay.control(move || {
                                    let _ = supervisor.cancel(&id);
                                })?;
                            }
                        }
                        relay.resume_teardowns(&journal, binding)?;
                        registered = true;
                        // Preview tunnels: the server learns which clients
                        // still run (it re-applies the ones that do not).
                        if let Some(tunnels) = super::tunnel::installed() {
                            tunnels.report_all();
                        }
                        quiesce.registered(&options.shutdown, quiesce_negotiated);
                        // WP3: only now is the outage over (max_carry anchor).
                        authority.end_outage();
                        super::revocation::clear(&journal);
                        tracing::info!("sandbox relay registered");
                    }
                    // E6: the deployment-wide blocklist, relayed to the guard by
                    // the monitor (next tick and every new guard instance). A
                    // frame whose digest does not match is ignored: the last
                    // list stays (M13), never an empty one. During
                    // reconciliation `DeferredPushes` applies it the same way.
                    ServerControlMessage::EgressBlocklist(list) => {
                        if !registered {
                            continue;
                        }
                        if let Some(node) = relay.egress() {
                            node.receive_blocklist(&list);
                        }
                    }
                    // KeyControl consumes install frames before dispatch matching.
                    ServerControlMessage::JournalKeyInstall(_) => {}
                    ServerControlMessage::PrivateConfigInstall(_) => {}
                    // WP7: only this connection's own `host.quiesce` counts.
                    ServerControlMessage::HostQuiesceAck(ack) => {
                        if !registered {
                            bail!("quiesce ack before hello.ok");
                        }
                        quiesce.ack(&options.shutdown, ack.sequence);
                    }
                    ServerControlMessage::HeartbeatPong { received_at, .. } => {
                        // The relayed server time judges eviction grants (S11).
                        if let Some(offload) = relay.offload() {
                            offload.note_server_time(&received_at);
                        }
                    }
                    ServerControlMessage::FileChunkAck {
                        operation_id,
                        generation,
                        attempt,
                        sequence,
                        offset,
                    } => {
                        if let Some((item, window)) = downloads.get_mut(&operation_id)
                            && item.generation == generation
                            && item.attempt == attempt
                        {
                            window.ack(sequence, offset);
                        }
                    }
                    ServerControlMessage::CommandOutputAck {
                        operation_id,
                        generation,
                        attempt,
                        sequence,
                        offset,
                    } => {
                        relay.ack_output(operation_id, generation, attempt, sequence, offset);
                    }
                    ServerControlMessage::ReceiptAck { .. }
                    | ServerControlMessage::ReceiptPrunedAck(_) => {}
                    ServerControlMessage::ReceiptConfirmed(confirmed) => {
                        journal.confirm(binding, &confirmed)?;
                    }
                    ServerControlMessage::OperationDispatch(dispatch) => {
                        if !registered {
                            bail!("dispatch before hello.ok");
                        }
                        // E4-01: a semantically invalid dispatch is refused as
                        // that one operation. Ending the session here let a
                        // durable bad frame (redispatched by every reconnect
                        // audit) hold the whole node offline.
                        if !fs_process_fields_allowed(&dispatch) {
                            refuse_invalid_dispatch(
                                socket,
                                wire,
                                &authority,
                                &journal,
                                &dispatch,
                                "invalid process identity field",
                            )?;
                            continue;
                        }
                        // Disk fields are served only while
                        // this daemon advertises `diskOffload`.
                        if sandbox_protocol::dispatch_has_disk_fields(&dispatch)
                            && (!DISK_OFFLOAD_SUPPORTED || relay.offload().is_none())
                        {
                            refuse_invalid_dispatch(
                                socket,
                                wire,
                                &authority,
                                &journal,
                                &dispatch,
                                "unsupported disk offload field",
                            )?;
                            continue;
                        }
                        // Versioned wire decoding precedes journal admission
                        // and any terminal supersession: a refused frame (e.g.
                        // a stop/kill missing its allocation) must not end the
                        // sandbox's live PTYs.
                        if wire.dispatch_size(&dispatch).is_err() {
                            refuse_invalid_dispatch(
                                socket,
                                wire,
                                &authority,
                                &journal,
                                &dispatch,
                                "invalid dispatch sizing fields",
                            )?;
                            continue;
                        }
                        handle_dispatch(
                            socket,
                            wire,
                            &mut authority,
                            &mut live_admission,
                            (&journal, binding),
                            relay,
                            &exec_supervisor,
                            pending_puts,
                            &dispatch,
                        )?;
                        // Supersession ends terminals bound to the old state.
                        terminals.on_dispatch(&dispatch);
                        channels.on_dispatch(&dispatch);
                    }
                    image @ (ServerControlMessage::ImageFetchGrant(_)
                    | ServerControlMessage::ImageFetchRefused(_)
                    | ServerControlMessage::ImageServeRequest(_)
                    | ServerControlMessage::ImagePublishRequest(_)
                    | ServerControlMessage::ImageLinksGrant(_)
                    | ServerControlMessage::ImageUploadGrant(_)
                    | ServerControlMessage::ImageJobResumeResult(_)
                    | ServerControlMessage::ImageJobCancel(_)
                    | ServerControlMessage::ImageRelease(_)
                    | ServerControlMessage::ImageCacheCensusAck(_)
                    // Acks of terminal reports, which the image outbox keeps
                    // (disk offload reports included).
                    | ServerControlMessage::ReportAck(_)) => {
                        if !registered {
                            bail!("image frame before hello.ok");
                        }
                        match relay.images() {
                            Some(images) => images.handle_server(image),
                            None => bail!("unnegotiated image frame"),
                        }
                    }
                    // Only to a daemon that advertised
                    // `diskOffload` (the offload service runs).
                    disk @ (ServerControlMessage::DiskOffloadRequest(_)
                    | ServerControlMessage::DiskOffloadStored(_)
                    | ServerControlMessage::DiskOffloadCancel(_)
                    | ServerControlMessage::DiskUploadGrant(_)
                    | ServerControlMessage::DiskUploadResumed(_)
                    | ServerControlMessage::DiskEvictSuggest(_)
                    | ServerControlMessage::DiskEvictGrant(_)
                    | ServerControlMessage::DiskEvictRefused(_)
                    | ServerControlMessage::DiskDiscard(_)) => {
                        if !registered {
                            bail!("disk offload frame before hello.ok");
                        }
                        match relay.offload() {
                            Some(offload) if DISK_OFFLOAD_SUPPORTED => offload.handle_server(disk),
                            _ => bail!("unnegotiated disk offload frame"),
                        }
                    }
                    message @ (ServerControlMessage::CredentialReturnKey(_)
                    | ServerControlMessage::CredentialSpecChunk(_)
                    | ServerControlMessage::CredentialSpecRefused(_)
                    | ServerControlMessage::CredentialBundleBegin(_)
                    | ServerControlMessage::CredentialBundleChunk(_)
                    | ServerControlMessage::CredentialBundleRefused(_)
                    | ServerControlMessage::CredentialQuarantineDiscard(_)
                    | ServerControlMessage::CredentialCaptureAck(_)
                    | ServerControlMessage::CredentialRevoke(_)
                    | ServerControlMessage::CredentialCensusAck(_)) => {
                        if !registered {
                            bail!("credential frame before hello.ok");
                        }
                        match relay.credentials() {
                            Some(credentials) => credentials.handle_server(message),
                            None => bail!("unnegotiated credential frame"),
                        }
                    }
                    channel @ (ServerControlMessage::ChannelOpen { .. }
                    | ServerControlMessage::ChannelAck { .. }
                    | ServerControlMessage::ChannelEof { .. }
                    | ServerControlMessage::ChannelResize { .. }
                    | ServerControlMessage::ChannelSignal { .. }
                    | ServerControlMessage::ChannelClose { .. }) => {
                        if !registered {
                            bail!("channel frame before hello.ok");
                        }
                        for frame in channels.handle_control(channel)? {
                            if let super::terminal::Outgoing::Text(message) = frame {
                                socket.send(Message::Text(super::spell(wire, &message, None)?.into()))?;
                            }
                        }
                    }
                    terminal @ (ServerControlMessage::TerminalOpen { .. }
                    | ServerControlMessage::TerminalResize { .. }
                    | ServerControlMessage::TerminalClose { .. }
                    | ServerControlMessage::TerminalAck { .. }
                    // WP8: like every terminal frame, only once registered
                    // (after this connection's `reconcile.complete`).
                    | ServerControlMessage::TerminalResume { .. }) => {
                        if !registered {
                            bail!("terminal frame before hello.ok");
                        }
                        for frame in terminals.handle_control(terminal)? {
                            if let super::terminal::Outgoing::Text(message) = frame {
                                socket.send(Message::Text(
                                    super::spell(wire, &message, None)?.into(),
                                ))?;
                            }
                        }
                    }
                    ServerControlMessage::OperationCancel {
                        operation_id,
                        generation,
                        attempt,
                        ..
                    } => {
                        // Durable intent precedes revocation and every cleanup effect.
                        let cancellation = journal.request_cancel(
                            &authority,
                            &operation_id,
                            generation,
                            attempt,
                        )?;
                        if let Some(receipt) = journal.lookup(&operation_id)
                            && receipt.generation == generation
                            && receipt.attempt == attempt
                            && receipt.is_terminal()
                        {
                            // A live output window means the completion is
                            // still draining; its receipt must publish through
                            // the same drain/grace owner as an uncancelled
                            // completion, or the server would seal `outputBytes`
                            // and refuse the retained frames that follow.
                            if relay.output_open(&operation_id, generation, attempt) {
                                continue;
                            }
                            super::reconcile::send_receipt(socket, wire, receipt)?;
                            continue;
                        }
                        if let Ok(work) = cancellation {
                            if let Some(put) = pending_puts.remove(&operation_id) {
                                let receipt = journal.record_result(
                                    &operation_id,
                                    OperationState::Failed,
                                    None,
                                    Some(SandboxErrorCode::Cancelled),
                                    Some("upload cancelled before write".into()),
                                )?;
                                deliver_receipt(socket, wire, &authority, &put.dispatch, receipt)?;
                                continue;
                            }
                            #[cfg(target_os = "linux")]
                            if exec_supervisor.is_some() && work.kind == "command.run" {
                                // The exec owner observes the durable request directly;
                                // duplicates need no extra control jobs or cleanup owner.
                                continue;
                            }
                            #[cfg(not(target_os = "linux"))]
                            let _ = work;
                            let runtime = runtime.clone();
                            relay.control(move || {
                                let _ = runtime.cancel_operation(&operation_id);
                            })?;
                        }
                    }
                    ServerControlMessage::SandboxState { .. } => {}
                    ServerControlMessage::SandboxProbeRequest {
                        incus_fingerprint,
                        request_id,
                        sandbox_owner_id,
                        host_owner_id,
                        host_id,
                        sandbox_id,
                        generation,
                        architecture,
                        guest_uid,
                        guest_gid,
                        guest_home,
                        guest_shell,
                    } => {
                        if !registered
                            || binding.host_owner_id != host_owner_id
                            || binding.host_id != host_id
                            || journal.sandbox_owner(&sandbox_id).as_deref()
                                != Some(sandbox_owner_id.as_str())
                            || journal
                                .lease(&sandbox_id)
                                .is_none_or(|l| l.generation != generation)
                        {
                            bail!("invalid live probe binding");
                        }
                        let runtime = runtime.clone();
                        let tx = observations_tx.clone();
                        let busy_id = request_id.clone();
                        if relay
                            .observe(move || {
                                let instance_name =
                                    sandbox_runtime::default_incus_instance_name(&sandbox_id);
                                let result =
                                    runtime.probe_sandbox(&sandbox_runtime::ProbeSandboxRequest {
                                        template_fingerprint: incus_fingerprint,
                                        sandbox_id,
                                        instance_name,
                                        operation_id: String::new(),
                                        idempotency_key: String::new(),
                                        architecture: Some(architecture),
                                        guest: sandbox_runtime::GuestIdentity {
                                            guest_uid,
                                            guest_gid,
                                            guest_home,
                                            guest_shell,
                                        },
                                    });
                                let state = match result.map(|v| v.state) {
                                    Ok(sandbox_runtime::SandboxLiveProbeState::GuestReady) => {
                                        "guest_ready"
                                    }
                                    Ok(sandbox_runtime::SandboxLiveProbeState::Stopped) => {
                                        "stopped"
                                    }
                                    Ok(sandbox_runtime::SandboxLiveProbeState::ConfirmedAbsent) => {
                                        "confirmed_absent"
                                    }
                                    _ => "unreachable",
                                };
                                let _ = tx.try_send(DaemonControlMessage::SandboxProbeResult {
                                    request_id,
                                    state: state.into(),
                                });
                            })
                            .is_err()
                        {
                            socket.send(Message::Text(
                                super::plain_frame(&DaemonControlMessage::SandboxProbeResult {
                                    request_id: busy_id,
                                    state: "unreachable".into(),
                                })?
                                .into(),
                            ))?;
                        }
                    }
                    ServerControlMessage::AllocationAttestRequest {
                        connection_epoch,
                        barrier,
                        sandbox_ids,
                        allocations,
                    } => {
                        if !registered || !wire.valid() || admission_epoch != Some(connection_epoch)
                        {
                            bail!("unnegotiated allocation attestation");
                        }
                        // handle_dispatch above synchronously journals intent (or
                        // refuses it) before this reader can process the barrier.
                        let settled = journal.never_issued(&sandbox_ids);
                        let journal_id = journal.instance_id().to_owned();
                        let runtime = runtime.clone();
                        let tx = observations_tx.clone();
                        let _ = relay.observe(move || {
                            let entries = sandbox_ids
                                .into_iter()
                                .zip(settled)
                                .map(|(sandbox_id, clear)| {
                                    let storage_clear =
                                        allocations.as_ref().is_some_and(|probes| {
                                            probes
                                                .iter()
                                                .find(|p| p.sandbox_id == sandbox_id)
                                                .is_some_and(|p| {
                                                    exact_probe_absent(
                                                        runtime.as_ref(),
                                                        &sandbox_id,
                                                        &p.allocation,
                                                    )
                                                })
                                        });
                                    let settled_never_issued = clear
                                        && storage_clear
                                        && matches!(runtime.sandbox_exists(&sandbox_id), Ok(false));
                                    sandbox_protocol::AllocationVerdict {
                                        sandbox_owner_id: allocations
                                            .as_ref()
                                            .and_then(|probes| {
                                                probes.iter().find(|p| p.sandbox_id == sandbox_id)
                                            })
                                            .map(|p| p.sandbox_owner_id.clone())
                                            .unwrap_or_default(),
                                        sandbox_id,
                                        settled_never_issued,
                                    }
                                })
                                .collect();
                            let _ = tx.try_send(DaemonControlMessage::AllocationAttestResult {
                                connection_epoch,
                                barrier,
                                journal_id,
                                entries,
                            });
                        });
                    }
                    ServerControlMessage::AvailabilityRequest {
                        request_id,
                        connection_epoch,
                        page,
                        bindings,
                    } => {
                        if !registered || admission_epoch != Some(connection_epoch) {
                            bail!("unnegotiated availability request");
                        }
                        let runtime = runtime.clone();
                        let tx = observations_tx.clone();
                        // The server sends one outstanding page. The existing bounded
                        // observation worker keeps image IO off the relay reader.
                        let _ = relay.observe(move || {
                            let entries = bindings
                                .into_iter()
                                .map(|binding| {
                                    let status = availability_status(runtime.as_ref(), &binding);
                                    sandbox_protocol::AvailabilityVerdict {
                                        binding,
                                        status,
                                        size_bytes: None,
                                        format: None,
                                    }
                                })
                                .collect();
                            let _ = tx.try_send(DaemonControlMessage::AvailabilityResult {
                                request_id,
                                connection_epoch,
                                page,
                                entries,
                            });
                        });
                    }
                    ServerControlMessage::ImageVerifyRequest {
                        request_id,
                        image_ref,
                        expected_architecture,
                    } => {
                        if !registered {
                            bail!("image verify before hello.ok");
                        }
                        handle_image_verify(
                            relay,
                            runtime.clone(),
                            observations_tx.clone(),
                            &request_id,
                            &image_ref,
                            &expected_architecture,
                        )?;
                    }
                    // Socket limits retry; a refused hello ends this daemon.
                    ServerControlMessage::ProtocolError {
                        failure, message, ..
                    } => {
                        let accepted = registered || hello_accepted;
                        return Err(protocol_error_end(accepted, failure, &message));
                    }
                    ServerControlMessage::InventoryAck { .. } => {
                        bail!("inventory ack outside reconciliation");
                    }
                    ServerControlMessage::SandboxExpiryStatusAck {
                        batch,
                        entry_results,
                    } => {
                        if !registered {
                            bail!("unnegotiated expiry status ack");
                        }
                        deferred.evidence().acknowledge(
                            batch,
                            &entry_results,
                            &mut expiry_reported,
                        )?;
                    }
                    ServerControlMessage::OperationAdoptResult { .. } => {
                        bail!("adoption result outside reconciliation");
                    }
                    ServerControlMessage::DispatchAuditPage { .. } => {
                        bail!("dispatch audit outside reconciliation");
                    }
                }
            }
            Message::Binary(data) => {
                if !registered {
                    bail!("binary before hello.ok");
                }
                // fu-a: a shutdown flush takes no terminal input or upload.
                if shutdown_flush.is_some() {
                    continue;
                }
                // Terminal input has its own lane, fenced and windowed there.
                if let Some(frame) = sandbox_protocol::parse_terminal_frame(&data) {
                    let (metadata, body) = frame?;
                    terminals.handle_input(metadata, body)?;
                    continue;
                }
                // Channel stdin, fenced and windowed in the channel host.
                if let Some(frame) = sandbox_protocol::parse_channel_frame(&data) {
                    let (metadata, body) = frame?;
                    channels.handle_input(metadata, body)?;
                    continue;
                }
                // One borrowed parse serves both the stdin and the upload lane.
                let (file_meta, file_body) = parse_binary_frame_ref(&data)?;
                #[cfg(target_os = "linux")]
                if file_meta.flags.as_ref().and_then(|f| f.stdin) == Some(true) {
                    let exec = exec_supervisor.clone();
                    let runtime = runtime.clone();
                    let authority = authority.clone();
                    let tx = finished_tx.clone();
                    let journal = journal.clone();
                    let body = file_body.to_vec();
                    relay.control(move || {
                        let outcome = apply_stdin(
                            &journal,
                            exec.as_ref(),
                            runtime.as_ref(),
                            &authority,
                            &file_meta,
                            body,
                        );
                        if let Err(result) = outcome {
                            let _ = tx.send(persist_finished(&journal, *result));
                        }
                    })?;
                    continue;
                }
                let applied = apply_file_put_chunk(pending_puts, &authority, &file_meta, file_body);
                if matches!(applied, PutChunk::Accepted | PutChunk::Ready(_)) {
                    socket.send(Message::Text(
                        super::plain_frame(&DaemonControlMessage::FileChunkAck {
                            operation_id: file_meta.operation_id.clone(),
                            generation: file_meta.generation,
                            attempt: file_meta.attempt,
                            sequence: file_meta.sequence,
                            offset: file_meta.offset.unwrap_or(0) + file_body.len() as u64,
                        })?
                        .into(),
                    ))?;
                }
                match applied {
                    PutChunk::Ready((dispatch, instance_name, bytes, reservation)) => {
                        if relay
                            .submit_upload(dispatch.clone(), instance_name, bytes, reservation)
                            .is_err()
                        {
                            let receipt = journal.record_result(
                                &dispatch.operation_id,
                                OperationState::Failed,
                                None,
                                Some(SandboxErrorCode::HostCapacity),
                                Some("host work queue full".into()),
                            )?;
                            deliver_receipt(socket, wire, &authority, &dispatch, receipt)?;
                        }
                    }
                    PutChunk::Failed(dispatch, code, message) => {
                        // Nothing reached the runtime: a definite FAILED receipt.
                        let receipt = journal.record_result(
                            &dispatch.operation_id,
                            OperationState::Failed,
                            None,
                            Some(code),
                            Some(message),
                        )?;
                        deliver_receipt(socket, wire, &authority, &dispatch, receipt)?;
                    }
                    PutChunk::Accepted | PutChunk::Ignored => {}
                }
            }
            Message::Ping(payload) => {
                socket.send(Message::Pong(payload))?;
            }
            Message::Close(frame) => {
                let error = close_during_read(
                    frame.as_ref().map(|frame| u16::from(frame.code)),
                    frame.as_ref().map(|frame| frame.reason.as_str()),
                );
                return Err(
                    if !hello_accepted && error.downcast_ref::<ServerVerdict>().is_some() {
                        error.context(TerminalHelloRefusal)
                    } else {
                        error
                    },
                );
            }
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn drain_finished(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    wire: WireCodes,
    authority: &HostAuthority,
    live_admission: &mut LiveSandboxAdmission,
    relay: &RelaySupervisor,
    journal: &HostJournal,
    downloads: &mut Downloads,
    mut hints: Option<StepEndHints<'_>>,
) -> Result<()> {
    // These refusals never acquired local execution authority. Their exact
    // operation/generation/attempt still passes the server's epoch/owner fence.
    for (kind, item) in relay.poll_refusals() {
        send_finished(socket, wire, Some(&kind), item)?;
    }
    let mut batch: std::collections::VecDeque<FinishedOp> = relay.poll_finished().into();
    // E3B-01 step-end barrier. The stub records a refused name before it
    // answers the query, so every name a step looked up is queued in the
    // runtime before that step's completion could be polled above: collect
    // them now, and let each sandbox's names reach the server before its
    // completion (the server attributes a hint to the step running when the
    // hint arrives). A completion whose names still wait for the rate
    // window is held and polled again next tick (bounded by `HOLD_MAX`).
    let mut held: Vec<FinishedOp> = Vec::new();
    let mut held_sandboxes: std::collections::HashSet<String> = Default::default();
    if let Some(hints) = &mut hints
        && !batch.is_empty()
    {
        for (sandbox_id, name) in hints.runtime.drain_refused_dns_names() {
            hints.reporter.observe(&sandbox_id, &name);
        }
    }
    while let Some(item) = batch.pop_front() {
        if let Some(hints) = &mut hints {
            if held_sandboxes.contains(&item.sandbox_id) {
                held.push(item);
                continue;
            }
            let (frame, clear) = hints
                .reporter
                .completion_barrier(&item.sandbox_id, Instant::now());
            if let Some(frame) = frame {
                let sent = super::plain_frame(&DaemonControlMessage::EgressRefused(frame))
                    .and_then(|text| Ok(socket.send(Message::Text(text.into()))?));
                if let Err(error) = sent {
                    held.push(item);
                    held.extend(batch);
                    relay.requeue_finished(held);
                    return Err(error);
                }
            }
            if !clear {
                held_sandboxes.insert(item.sandbox_id.clone());
                held.push(item);
                continue;
            }
        }
        if let Err(error) = publish_completion(
            socket,
            wire,
            authority,
            live_admission,
            journal,
            downloads,
            item,
        ) {
            // A socket failure mid-batch: the failed item's ownership token
            // went with it; every untouched completion goes back to the
            // supervisor with its token, never discarded (review round 3).
            held.extend(batch);
            relay.requeue_finished(held);
            return Err(error);
        }
    }
    relay.requeue_finished(held);
    Ok(())
}

/// The step-end barrier's inputs: the runtime's refused-name queue and the
/// session's hint reporter (only on a session that advertised hints).
pub(super) struct StepEndHints<'a> {
    pub(super) runtime: &'a dyn SandboxRuntime,
    pub(super) reporter: &'a mut super::egress_hints::RefusedNameReporter,
}

/// Publishes one completion. Its ownership token (a worker's final
/// completion only) is released when the item is consumed here: after its
/// publication, when it moves into a download window, or on failure.
fn publish_completion(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    wire: WireCodes,
    authority: &HostAuthority,
    live_admission: &mut LiveSandboxAdmission,
    journal: &HostJournal,
    downloads: &mut Downloads,
    mut item: FinishedOp,
) -> Result<()> {
    let current = authority
        .accept_completion(&item.operation_id, item.generation, item.attempt)
        .is_ok();
    let terminal = item.state != OperationState::UnknownOutcome;
    let completed_identity = (item.operation_id.clone(), item.generation, item.attempt);
    // Account before any socket write can fail, including stale completions
    // whose authority entry was removed by supersession. Only a current
    // completion may release a hold (minor 4); carried completions were
    // reflected by the reconnect's rebuild.
    if let Some(receipt) = journal.lookup(&item.operation_id) {
        if current && confirmed_release(&receipt.kind, item.state, item.payload.as_ref()) {
            live_admission.release_confirmed(&item.sandbox_id);
            if receipt.kind == "sandbox.kill" {
                live_admission.release_root_confirmed(&item.sandbox_id, item.generation);
            }
        } else if matches!(
            receipt.kind.as_str(),
            "sandbox.create" | "sandbox.reconnect"
        ) {
            live_admission.finish_allocation(&item.sandbox_id, &item.operation_id, item.state);
        }
    }
    let complete = |authority: &HostAuthority| {
        if terminal
            && authority
                .pending(&completed_identity.0)
                .is_some_and(|work| {
                    work.generation == completed_identity.1
                        && work.attempt == completed_identity.2
                        && work.epoch == authority.session_epoch()
                })
        {
            authority.complete(&completed_identity.0);
        }
    };
    if current {
        if let Some(bytes) = item.download.take() {
            // The download window takes the item, and with it the token.
            downloads.insert(
                item.operation_id.clone(),
                (item, super::files::DownloadWindow::new(bytes)),
            );
            // Still pending: the transfer settles it.
            return Ok(());
        }
        // UNKNOWN may already have been published by this same owner.
        // Exact-binding receipts can upgrade it on the current connection.
        let receipt = (terminal && item.download.is_none())
            .then(|| journal.lookup(&item.operation_id))
            .flatten();
        let kind = journal.lookup(&item.operation_id).map(|r| r.kind);
        send_finished(socket, wire, kind.as_deref(), item)?;
        if let Some(receipt) = receipt {
            super::reconcile::send_receipt(socket, wire, receipt)?;
        }
    } else if !item.interim
        && authority.take_late(&item.operation_id, item.generation, item.attempt)
        && let Some(receipt) = journal.lookup(&item.operation_id).filter(|r| {
            r.phase == super::journal::ReceiptPhase::Result
                && r.generation == item.generation
                && r.attempt == item.attempt
        })
    {
        drop(item);
        // M5 late-receipt rule: carried work revoked before it could
        // publish settles through its exact-bound journal Result.
        super::reconcile::send_receipt(
            socket,
            wire,
            super::reconcile::reportable_receipt(receipt),
        )?;
    }
    complete(authority);
    Ok(())
}

/// Whether this session's hello advertised `diskOffload` (the server
/// accepts `disk.*` frames only then).
fn hello_disk_offload(hello: &DaemonControlMessage) -> bool {
    matches!(hello, DaemonControlMessage::Hello { daemon, .. } if daemon.capabilities.disk_offload)
}

fn hello_runtime_kind(hello: &DaemonControlMessage) -> sandbox_protocol::RuntimeKind {
    match hello {
        DaemonControlMessage::Hello { daemon, .. } => daemon.capabilities.runtime_kind.clone(),
        _ => sandbox_protocol::RuntimeKind::Unsupported,
    }
}

pub(super) fn availability_status(
    runtime: &dyn SandboxRuntime,
    binding: &sandbox_protocol::AvailabilityBinding,
) -> sandbox_protocol::AvailabilityStatus {
    use sandbox_protocol::AvailabilityStatus;
    match runtime.resolve_image_ref(&binding.artifact) {
        Ok(image)
            if image.fingerprint == binding.artifact
                && image.architecture == binding.architecture =>
        {
            AvailabilityStatus::Present
        }
        Err(error) if error.code == SandboxErrorCode::NotFound => AvailabilityStatus::Missing,
        _ => AvailabilityStatus::Rejected,
    }
}

/// A successful image verification includes every fact the runtime resolved.
fn image_verified(
    request_id: &str,
    resolved: sandbox_runtime::ResolvedHostImage,
) -> DaemonControlMessage {
    DaemonControlMessage::ImageVerifyResult {
        request_id: request_id.to_string(),
        incus_fingerprint: Some(resolved.fingerprint),
        architecture: Some(resolved.architecture),
        error: None,
        size_bytes: resolved.size_bytes,
        format: None,
    }
}

fn handle_image_verify(
    relay: &RelaySupervisor,
    runtime: Arc<dyn SandboxRuntime>,
    tx: mpsc::SyncSender<DaemonControlMessage>,
    request_id: &str,
    image_ref: &str,
    expected_architecture: &str,
) -> Result<()> {
    let busy_id = request_id.to_string();
    let busy_tx = tx.clone();
    let request_id = request_id.to_string();
    let image_ref = image_ref.to_string();
    let expected_architecture = expected_architecture.to_string();
    let queued = relay.observe(move || {
        let outcome = runtime.resolve_image_ref(&image_ref).and_then(|resolved| {
            if resolved.architecture != expected_architecture
            {
                Err(sandbox_runtime::RuntimeError::new(
                    SandboxErrorCode::ProtocolError,
                    format!(
                        "image `{image_ref}` architecture `{}` does not match expected `{expected_architecture}`",
                        resolved.architecture
                    ),
                ))
            } else {
                Ok(resolved)
            }
        });
        let message = match outcome {
            Ok(resolved) => image_verified(&request_id, resolved),
            Err(err) => DaemonControlMessage::ImageVerifyResult {
                request_id: request_id.to_string(),
                incus_fingerprint: None,
                architecture: None,
                size_bytes: None,
                format: None,
                error: Some(ProtocolErrorDetail { reason: None,
                    code: err.code.into(),
                    message: err.message,
                    operation_id: None,
                    sandbox_id: None,
                }),
            },
        };
        let _ = tx.try_send(message);
    });
    if queued.is_err() {
        let _ = busy_tx.try_send(DaemonControlMessage::ImageVerifyResult {
            request_id: busy_id,
            incus_fingerprint: None,
            architecture: None,
            size_bytes: None,
            format: None,
            error: Some(ProtocolErrorDetail {
                reason: None,
                code: SandboxErrorCode::HostCapacity.into(),
                message: "host image observation queue full".into(),
                operation_id: None,
                sandbox_id: None,
            }),
        });
    }
    Ok(())
}

/// Validate bounded, kind-bound process identity before journal intent or
/// any worker effect. Only command.run carries a new process identity, and
/// only process.signal (always) carries a tracked target.
fn fs_process_fields_allowed(dispatch: &OperationDispatch) -> bool {
    let opaque = |id: &str| {
        !id.is_empty()
            && id.len() <= 64
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    };
    let identity = match &dispatch.process_id {
        None => true,
        Some(id) => dispatch.kind == "command.run" && opaque(id),
    };
    let target = match (&dispatch.process, &dispatch.target_operation_id) {
        (None, None) => dispatch.kind != "process.signal",
        (Some(process), Some(target)) => {
            dispatch.kind == "process.signal"
                && process.validate()
                && process.sandbox_id == dispatch.sandbox_id
                && dispatch.pid == Some(process.pid)
                && opaque(target)
        }
        _ => false,
    };
    // 1.0 servers version every result kind and bind every command to a
    // process identity; an unversioned result kind has no reply shape.
    let result = match (
        dispatch.result_version,
        sandbox_protocol::results::host::kind_from_dispatch(&dispatch.kind),
    ) {
        (None, None) => true,
        (Some(1), Some(_)) => dispatch.kind != "command.run" || dispatch.process_id.is_some(),
        _ => false,
    };
    let page_kind = matches!(dispatch.kind.as_str(), "file.list" | "process.list");
    let page = dispatch
        .limit
        .is_none_or(|n| page_kind && (1..=100).contains(&n))
        && dispatch.continuation.as_ref().is_none_or(|c| {
            page_kind
                && c.validate()
                && Some(c.kind)
                    == sandbox_protocol::results::host::kind_from_dispatch(&dispatch.kind)
        });
    identity && target && result && page
}

#[allow(clippy::too_many_arguments)]
fn handle_dispatch(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    wire: WireCodes,
    authority: &mut HostAuthority,
    live_admission: &mut LiveSandboxAdmission,
    receipt_context: (&HostJournal, &TransportBindingV11),
    relay: &RelaySupervisor,
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] exec_supervisor: &Option<
        CommandSupervisor,
    >,
    pending_puts: &mut HashMap<String, PendingFilePut>,
    dispatch: &OperationDispatch,
) -> Result<()> {
    let (journal, binding) = receipt_context;
    // Versioned wire decoding precedes journal admission. A protocol refusal
    // does not prove any earlier effect absent or release its reservation; it
    // is one operation's refusal, never the session's end (E4-01). The relay
    // loop also refuses these before calling here, so terminal supersession
    // never runs for them; this check keeps direct callers equally strict.
    if wire.dispatch_size(dispatch).is_err() {
        return refuse_invalid_dispatch(
            socket,
            wire,
            authority,
            journal,
            dispatch,
            "invalid dispatch sizing fields",
        );
    }
    // Receipt history must be known BEFORE validation or any digest/key refusal.
    let prior = journal.lookup(&dispatch.operation_id);
    let receipt = match journal.prepare_dispatch(binding, dispatch) {
        Ok(receipt) => receipt,
        Err(code) => {
            if let Some(existing) = prior {
                return deliver_unknown(socket, wire, authority, dispatch, existing);
            }
            return send_operation_result(
                socket,
                wire,
                &dispatch.kind,
                &dispatch.operation_id,
                &dispatch.sandbox_id,
                dispatch.generation,
                dispatch.attempt,
                Err(DispatchError {
                    reason: None,
                    code: code.into(),
                    message: digest_refusal_message(code).into(),
                }),
            );
        }
    };
    if let Err(_err) = super::journal::validate_receipt(&receipt) {
        if let Some(existing) = prior {
            return deliver_unknown(socket, wire, authority, dispatch, existing);
        }
        return send_operation_result(
            socket,
            wire,
            &dispatch.kind,
            &dispatch.operation_id,
            &dispatch.sandbox_id,
            dispatch.generation,
            dispatch.attempt,
            Err(DispatchError {
                reason: None,
                code: if sandbox_protocol::classify_dispatch_kind(&dispatch.kind)
                    == sandbox_protocol::DispatchKindClass::UnsupportedCapability
                {
                    SandboxErrorCode::UnsupportedCapability.into()
                } else {
                    SandboxErrorCode::ProtocolError.into()
                },
                message: "invalid host receipt".into(),
            }),
        );
    }
    let instance_name =
        match resolve_instance_name(&dispatch.sandbox_id, dispatch.incus_name.as_deref()) {
            Ok(name) => name,
            Err(err) => {
                if let Some(existing) = prior {
                    return deliver_unknown(socket, wire, authority, dispatch, existing);
                }
                send_operation_result(
                    socket,
                    wire,
                    &dispatch.kind,
                    &dispatch.operation_id,
                    &dispatch.sandbox_id,
                    dispatch.generation,
                    dispatch.attempt,
                    Err(err),
                )?;
                return Ok(());
            }
        };
    // A conflicting immutable allocation is a normal pre-effect refusal.
    // Keep the original root journal intact and classify the outcome using
    // the same first-attempt/runtime evidence fence as other refusals.
    if matches!(
        dispatch.kind.as_str(),
        "sandbox.create" | "sandbox.reconnect"
    ) && let (Some(old), Some(requested)) = (
        journal.retained_roots().get(&dispatch.sandbox_id),
        dispatch.allocation.as_ref(),
    ) && (old.root() != super::journal::storage::allocation_root(requested)
        || old.allocation.root_charge_gi_b != requested.root_charge_gi_b
        || old.allocation.cpu_count != requested.cpu_count
        || old.allocation.memory_mi_b != requested.memory_mi_b
        || (old.live && old.allocation != *requested))
    {
        if let Some(finished) = relay.refuse_unadmitted(
            dispatch,
            journal.first_unadmitted_allocation(&receipt),
            false,
            DispatchError {
                reason: None,
                code: SandboxErrorCode::VmSizeMismatch.into(),
                message: "pinned allocation differs from retained root".into(),
            },
        ) {
            send_finished(socket, wire, Some(&dispatch.kind), finished)?;
        }
        return Ok(());
    }
    // Lifecycle admission can revoke an existing exec permit and trigger a kill.
    // Its intent must be durable before even that in-memory authority change.
    let decision = journal.record_intent(&receipt)?;
    if matches!(
        decision,
        Decision::Capacity | Decision::SandboxReceipts | Decision::Conflict
    ) {
        if let Some(existing) = prior {
            return deliver_unknown(socket, wire, authority, dispatch, existing);
        }
        let code = if matches!(decision, Decision::Conflict) {
            SandboxErrorCode::IdempotencyConflict
        } else {
            SandboxErrorCode::HostCapacity
        };
        let error = DispatchError {
            // The owner sees a per-sandbox condition, not "host capacity".
            reason: matches!(decision, Decision::SandboxReceipts)
                .then_some(sandbox_protocol::capacity_v11::CapacityReason::SandboxReceipts.into()),
            code: code.into(),
            message: "host refused dispatch admission".into(),
        };
        if matches!(
            dispatch.kind.as_str(),
            "sandbox.create" | "sandbox.reconnect"
        ) {
            if let Some(finished) = relay.refuse_unadmitted(
                dispatch,
                journal.first_unadmitted_allocation(&receipt),
                false,
                error,
            ) {
                send_finished(socket, wire, Some(&dispatch.kind), finished)?;
            }
            return Ok(());
        }
        return send_operation_result(
            socket,
            wire,
            &dispatch.kind,
            &dispatch.operation_id,
            &dispatch.sandbox_id,
            dispatch.generation,
            dispatch.attempt,
            Err(error),
        );
    }
    match authority.accept_dispatch(
        &dispatch.operation_id,
        &dispatch.sandbox_id,
        &dispatch.kind,
        dispatch.generation,
        dispatch.attempt,
    ) {
        Ok(false) => {
            if let Decision::Replay(existing) = decision
                && authority.pending(&dispatch.operation_id).is_none()
            {
                deliver_receipt(socket, wire, authority, dispatch, existing)?;
            }
            return Ok(());
        }
        Ok(true) => {}
        Err(err) => {
            if matches!(decision, Decision::Fresh) {
                if matches!(
                    dispatch.kind.as_str(),
                    "sandbox.create" | "sandbox.reconnect"
                ) {
                    let first_claim = journal.first_allocation_attempt(dispatch);
                    if let Some(finished) = relay.refuse_unadmitted(
                        dispatch,
                        first_claim,
                        true,
                        DispatchError {
                            reason: None,
                            code: err.refusal_code(&dispatch.kind, first_claim).into(),
                            message: err.message,
                        },
                    ) {
                        send_finished(socket, wire, Some(&dispatch.kind), finished)?;
                    }
                    return Ok(());
                }
                let stored = journal.record_result(
                    &dispatch.operation_id,
                    OperationState::Failed,
                    None,
                    Some(err.code),
                    Some(err.message.clone()),
                )?;
                return deliver_receipt(socket, wire, authority, dispatch, stored);
            }
            send_operation_result(
                socket,
                wire,
                &dispatch.kind,
                &dispatch.operation_id,
                &dispatch.sandbox_id,
                dispatch.generation,
                dispatch.attempt,
                Err(DispatchError {
                    reason: None,
                    code: err.code.into(),
                    message: err.message,
                }),
            )?;
            return Ok(());
        }
    }
    #[cfg(target_os = "linux")]
    if dispatch.kind == "command.run" {
        authority.start_stdin(&dispatch.operation_id, dispatch.stdin_sequence.unwrap_or(0));
    }
    pending_puts.retain(|id, _| authority.pending(id).is_some());
    #[cfg(target_os = "linux")]
    if let Some(supervisor) = exec_supervisor {
        for id in authority.take_revoked_execs() {
            let supervisor = supervisor.clone();
            relay.control(move || {
                let _ = supervisor.cancel(&id);
            })?;
        }
        let current = authority.pending_ids();
        supervisor.retain_pending_stdin(|id| current.contains(id));
    }
    match decision {
        Decision::Fresh => {}
        Decision::Replay(existing) => {
            deliver_receipt(socket, wire, authority, dispatch, existing)?;
            return Ok(());
        }
        Decision::Unknown(existing) => {
            deliver_unknown(socket, wire, authority, dispatch, existing)?;
            return Ok(());
        }
        Decision::Capacity | Decision::SandboxReceipts => {
            unreachable!("capacity rejected before authority admission")
        }
        Decision::Conflict => bail!("dispatch changed receipt binding"),
    }
    let live_decision = if matches!(
        dispatch.kind.as_str(),
        "sandbox.create" | "sandbox.reconnect"
    ) {
        live_admission.try_acquire_pinned(dispatch)
    } else {
        Ok(())
    };
    if let Err(code) = live_decision {
        let message = if code == SandboxErrorCode::VmSizeMismatch {
            "VM allocation differs; refusing start"
        } else {
            "host live sandbox capacity reached"
        };
        tracing::warn!(operation_id = %dispatch.operation_id, sandbox_id = %dispatch.sandbox_id,
            kind = %dispatch.kind, held = live_admission.held(), vcpu_budget = live_admission.vcpu_budget(),
            reason = "live_reservations", "host refused dispatch: live sandbox capacity reached");
        if matches!(
            dispatch.kind.as_str(),
            "sandbox.create" | "sandbox.reconnect"
        ) {
            relay.refuse_before_runtime(
                dispatch,
                DispatchError {
                    reason: (code == SandboxErrorCode::HostCapacity)
                        .then(|| live_admission.capacity_reason(dispatch).into()),
                    code: code.into(),
                    message: message.into(),
                },
            );
            return Ok(());
        }
        let receipt = journal.record_result(
            &dispatch.operation_id,
            OperationState::Failed,
            None,
            Some(code),
            Some(message.into()),
        )?;
        return deliver_receipt(socket, wire, authority, dispatch, receipt);
    }
    // Live finding B-2: the acceptance frame is sent only after the work has
    // an owner (a queued job, or the upload staging map). A send failure in
    // between would otherwise strand received work that cannot be carried.
    let accepted = |socket: &mut tungstenite::WebSocket<
        tungstenite::stream::MaybeTlsStream<std::net::TcpStream>,
    >| {
        socket.send(Message::Text(
            super::plain_frame(&DaemonControlMessage::OperationProgress {
                id: format!("accepted-{}", dispatch.operation_id),
                operation_id: dispatch.operation_id.clone(),
                sandbox_id: dispatch.sandbox_id.clone(),
                generation: dispatch.generation,
                attempt: dispatch.attempt,
                state: OperationState::Accepted,
                progress: None,
            })?
            .into(),
        ))?;
        anyhow::Ok(())
    };
    if dispatch.kind == "file.put" {
        let Some(_path) = dispatch.path.clone() else {
            let receipt = journal.record_result(
                &dispatch.operation_id,
                OperationState::Failed,
                None,
                Some(SandboxErrorCode::ProtocolError),
                Some("file.put requires path".into()),
            )?;
            return deliver_receipt(socket, wire, authority, dispatch, receipt);
        };
        if pending_puts.len() >= 4 {
            let receipt = journal.record_result(
                &dispatch.operation_id,
                OperationState::Failed,
                None,
                Some(SandboxErrorCode::HostCapacity),
                Some("host upload capacity reached".into()),
            )?;
            return deliver_receipt(socket, wire, authority, dispatch, receipt);
        }
        let reservation = match relay.reserve_upload(&dispatch.sandbox_id) {
            Ok(reservation) => reservation,
            Err(_) => {
                let receipt = journal.record_result(
                    &dispatch.operation_id,
                    OperationState::Failed,
                    None,
                    Some(SandboxErrorCode::HostCapacity),
                    Some("host work queue full".into()),
                )?;
                return deliver_receipt(socket, wire, authority, dispatch, receipt);
            }
        };
        let staged = match (dispatch.file_size, dispatch.file_sha256.as_deref()) {
            (Some(size), Some(digest)) if sandbox_protocol::canonical_body_hash(digest) => {
                sandbox_runtime::FileStaging::for_creator(size, reservation.creator())
                    .map_err(|error| (error.code, error.message))
            }
            _ => Err((
                SandboxErrorCode::ProtocolError,
                "file.put requires a declared length and SHA-256".into(),
            )),
        };
        let spool = match staged {
            Ok(spool) => spool,
            Err((code, message)) => {
                // Reservation failure precedes allocation and any guest work.
                let receipt = journal.record_result(
                    &dispatch.operation_id,
                    OperationState::Failed,
                    None,
                    Some(code),
                    Some(message),
                )?;
                return deliver_receipt(socket, wire, authority, dispatch, receipt);
            }
        };
        pending_puts.insert(
            dispatch.operation_id.clone(),
            PendingFilePut {
                reservation,
                dispatch: dispatch.clone(),
                instance_name,
                spool,
                next: 0,
                last: None,
                started: Instant::now(),
                touched: Instant::now(),
            },
        );
        return accepted(socket);
    }
    if let Err(error) = relay.submit(dispatch.clone(), instance_name, None) {
        let (code, message) = error
            .downcast_ref::<sandbox_runtime::RuntimeError>()
            .map(|error| (error.code, error.message.clone()))
            .unwrap_or((
                SandboxErrorCode::HostCapacity,
                "host work queue full".into(),
            ));
        if matches!(
            dispatch.kind.as_str(),
            "sandbox.create" | "sandbox.reconnect"
        ) {
            relay.refuse_before_runtime(
                dispatch,
                DispatchError {
                    reason: None,
                    code: code.into(),
                    message,
                },
            );
            return Ok(());
        }
        live_admission.finish_allocation(
            &dispatch.sandbox_id,
            &dispatch.operation_id,
            OperationState::Failed,
        );
        let receipt = journal.record_result(
            &dispatch.operation_id,
            OperationState::Failed,
            None,
            Some(code),
            Some(message),
        )?;
        deliver_receipt(socket, wire, authority, dispatch, receipt)?;
        return Ok(());
    }
    // The queued job owns the attempt now; a failed send just ends the
    // session and the attempt is carried.
    accepted(socket)
}

fn deliver_receipt(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    wire: WireCodes,
    authority: &HostAuthority,
    dispatch: &OperationDispatch,
    existing: HostReceipt,
) -> Result<()> {
    if existing.kind == "file.get" && existing.state == OperationState::Succeeded {
        return deliver_unknown(socket, wire, authority, dispatch, existing);
    }
    authority.complete(&dispatch.operation_id);
    let err = existing.error_code.map(|code| DispatchError {
        reason: None,
        code,
        message: existing.error_message.unwrap_or_default(),
    });
    send_finished(
        socket,
        wire,
        Some(&existing.kind),
        FinishedOp {
            operation_id: dispatch.operation_id.clone(),
            sandbox_id: dispatch.sandbox_id.clone(),
            generation: dispatch.generation,
            attempt: dispatch.attempt,
            state: existing.state,
            payload: existing.result,
            error: err,
            download: None,
            interim: false,
            readiness_detail: None,
            owner: None,
        },
    )
}

/// Pre-journal refusal of a frame that decoded but is not a valid dispatch of
/// its kind (identity, sizing). Nothing is recorded and no effect is issued:
/// fresh work fails `protocol_error`; an operation this host already has a
/// receipt for answers unknown, because the bad frame proves nothing about the
/// earlier attempt; work still pending here is left to its owner's result.
/// Either way the server settles it, so no reconnect audit
/// can redeliver it, and the relay session stays up (E4-01).
fn refuse_invalid_dispatch(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    wire: WireCodes,
    authority: &HostAuthority,
    journal: &HostJournal,
    dispatch: &OperationDispatch,
    message: &str,
) -> Result<()> {
    tracing::warn!(operation_id = %dispatch.operation_id, sandbox_id = %dispatch.sandbox_id,
        kind = %dispatch.kind, reason = message, "host refused invalid dispatch");
    // Work this host still owns keeps its owner: its own result settles it.
    if authority.pending(&dispatch.operation_id).is_some() {
        return Ok(());
    }
    if let Some(existing) = journal.lookup(&dispatch.operation_id) {
        return deliver_unknown(socket, wire, authority, dispatch, existing);
    }
    send_operation_result(
        socket,
        wire,
        &dispatch.kind,
        &dispatch.operation_id,
        &dispatch.sandbox_id,
        dispatch.generation,
        dispatch.attempt,
        Err(DispatchError {
            reason: None,
            code: SandboxErrorCode::ProtocolError.into(),
            message: message.into(),
        }),
    )
}

fn digest_refusal_message(code: SandboxErrorCode) -> &'static str {
    match code {
        SandboxErrorCode::DigestKeyChanged => "Digest key changed.",
        SandboxErrorCode::DigestKeyUnavailable => "Digest key unavailable.",
        SandboxErrorCode::ReceiptDigestPruned => "Receipt digest pruned.",
        _ => "Host dispatch digest refused.",
    }
}

fn deliver_unknown(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    wire: WireCodes,
    authority: &HostAuthority,
    dispatch: &OperationDispatch,
    existing: HostReceipt,
) -> Result<()> {
    let pruned = existing.digest_pruned;
    authority.complete(&dispatch.operation_id);
    send_finished(
        socket,
        wire,
        Some(&dispatch.kind),
        FinishedOp {
            operation_id: dispatch.operation_id.clone(),
            sandbox_id: dispatch.sandbox_id.clone(),
            generation: dispatch.generation,
            attempt: dispatch.attempt,
            state: OperationState::UnknownOutcome,
            payload: None,
            download: None,
            error: Some(DispatchError {
                reason: None,
                code: if pruned {
                    SandboxErrorCode::ReceiptDigestPruned.into()
                } else {
                    SandboxErrorCode::UnknownOutcome.into()
                },
                message: if pruned {
                    "Receipt digest pruned."
                } else {
                    "previous attempt has no confirmed result"
                }
                .into(),
            }),
            interim: false,
            readiness_detail: None,
            owner: None,
        },
    )
}

/// Local-stack opt-in for `--runtime fake`: advertise egress enforcement so
/// the control plane dispatches creates to the fake host. Honoured only by
/// the fake runtime; `wssp host run` refuses to start a real runtime with it.
pub(crate) const FAKE_ENFORCE_EGRESS_ENV: &str = "WSSP_FAKE_ENFORCE_EGRESS";
/// Local-stack failure injection for `--runtime fake`: while the named file
/// exists, every new create fails definitively. Fake runtime only.
pub(crate) const FAKE_FAIL_CREATE_FILE_ENV: &str = "WSSP_FAKE_FAIL_CREATE_FILE";

/// Fake-runtime-only local testing knobs, read from the environment.
#[derive(Debug, Default, PartialEq, Eq)]
struct FakeRuntimeKnobs {
    enforce_egress: bool,
    fail_create_file: Option<PathBuf>,
}

impl FakeRuntimeKnobs {
    fn from_lookup(lookup: impl Fn(&str) -> Option<std::ffi::OsString>) -> Result<Self> {
        let enforce_egress = match lookup(FAKE_ENFORCE_EGRESS_ENV) {
            None => false,
            Some(value) => match value.to_str() {
                Some("1" | "true") => true,
                Some("" | "0" | "false") => false,
                _ => bail!("`{FAKE_ENFORCE_EGRESS_ENV}` must be `1`, `true`, `0` or `false`"),
            },
        };
        let fail_create_file = match lookup(FAKE_FAIL_CREATE_FILE_ENV) {
            Some(path) if !path.is_empty() => Some(PathBuf::from(path)),
            _ => None,
        };
        Ok(Self {
            enforce_egress,
            fail_create_file,
        })
    }

    /// The fake runtime these knobs describe; logs each active knob.
    fn build(self) -> sandbox_runtime::FakeRuntime {
        let mut runtime = sandbox_runtime::FakeRuntime::new();
        // A debug fake daemon needs a verifiable base for local public-API
        // qualification. This inventory never reaches the Incus runtime.
        #[cfg(debug_assertions)]
        runtime.register_image("fake:base", &format!("sha256:{}", "a".repeat(64)), "x86_64");
        if self.enforce_egress {
            tracing::warn!(
                "{FAKE_ENFORCE_EGRESS_ENV}: the fake runtime advertises egress enforcement it does not perform (local testing only)"
            );
            runtime = runtime.with_advertised_egress_enforcement(true);
        }
        if let Some(path) = self.fail_create_file {
            tracing::warn!(
                "{FAKE_FAIL_CREATE_FILE_ENV}: new creates fail while `{}` exists (local testing only)",
                path.display()
            );
            runtime = runtime.with_create_failure_switch(path);
        }
        runtime
    }

    /// A real runtime never honours the fake knobs; refuse instead of
    /// silently ignoring them.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn refuse_for_real_runtime(&self) -> Result<()> {
        if *self != Self::default() {
            bail!(
                "`{FAKE_ENFORCE_EGRESS_ENV}` and `{FAKE_FAIL_CREATE_FILE_ENV}` apply only to `--runtime fake`; unset them to run a real runtime"
            );
        }
        Ok(())
    }
}

/// The daemon's claim on its Incus server, held from runtime setup until
/// the relay has stopped (one wssp daemon per Incus server).
#[cfg(target_os = "linux")]
type LeaseSlot = Option<sandbox_runtime::ServerLease>;
#[cfg(not(target_os = "linux"))]
type LeaseSlot = ();

/// TEST-ONLY: lets this daemon share its Incus server with another wssp
/// daemon (the local chaos stack runs two on one machine). Debug builds
/// only, with a loopback control plane; release builds never name it (the
/// release smoke step in `cli-ci.yml` greps the binary).
#[cfg(any(debug_assertions, test))]
pub(crate) const SHARED_INCUS_TEST_ENV: &str = "WSSP_TEST_SHARED_INCUS";

/// Whether this daemon skips the one-daemon-per-Incus-server guard. Release
/// builds: never.
#[cfg(target_os = "linux")]
fn shared_incus_override_enabled(server_url: &str) -> Result<bool> {
    #[cfg(debug_assertions)]
    {
        let enabled = shared_incus_override(std::env::var_os(SHARED_INCUS_TEST_ENV), server_url)?;
        if enabled {
            tracing::warn!(
                "TEST-ONLY OVERRIDE `{SHARED_INCUS_TEST_ENV}=1`: this daemon does NOT check for \
                 another wssp daemon on its Incus server, whose image fingerprints and sandbox \
                 bridge names can collide with this one's; never set it in production"
            );
        }
        Ok(enabled)
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = server_url;
        Ok(false)
    }
}

/// The debug-build override rule: off unless set; only `1`, and only with
/// a loopback control plane. Anything else refuses the start.
#[cfg(all(target_os = "linux", debug_assertions))]
fn shared_incus_override(value: Option<std::ffi::OsString>, server_url: &str) -> Result<bool> {
    let Some(value) = value else {
        return Ok(false);
    };
    if value != "1" {
        bail!(
            "`{SHARED_INCUS_TEST_ENV}` accepts only `1` and is a test-only override; unset it to run \
             a normal daemon"
        );
    }
    let loopback = loopback_control_plane(server_url).with_context(|| {
        format!("`{SHARED_INCUS_TEST_ENV}` needs a valid loopback control-plane URL")
    })?;
    if !loopback {
        bail!(
            "`{SHARED_INCUS_TEST_ENV}` is a test-only override accepted only with a loopback control \
             plane (`localhost`, 127.0.0.0/8 or `::1`); unset it: one wssp daemon per Incus server \
             is supported"
        );
    }
    Ok(true)
}

/// Whether `server_url` names a loopback control plane (`localhost`,
/// 127.0.0.0/8 or `::1`): the gate of every debug-only test override.
#[cfg(debug_assertions)]
pub(super) fn loopback_control_plane(server_url: &str) -> Result<bool, url::ParseError> {
    let url = Url::parse(server_url)?;
    Ok(match url.host() {
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    })
}

/// Start as this Incus server's only wssp daemon, and keep checking. A
/// conflict found later never stops the daemon: its guard probe refuses new
/// sandboxes until the conflict clears. `None`: this Incus client may not
/// manage profiles in `default`, so the guard is unavailable to it.
#[cfg(target_os = "linux")]
fn claim_incus_server(
    config: &IncusConfig,
    options: &ConnectOptions,
    state_dir: &std::path::Path,
) -> Result<Option<sandbox_runtime::ServerLease>> {
    use sandbox_runtime::{DaemonIdentity, LeaseEvent, LeaseTiming, ServerLease, ServerLeaseError};
    let client = sandbox_runtime::IncusClient::new(config.binary.clone(), config.project.clone());
    let state_dir = std::fs::canonicalize(state_dir).unwrap_or_else(|_| state_dir.to_path_buf());
    let identity = DaemonIdentity {
        machine_id: DaemonIdentity::local_machine_id(),
        host_id: options.host_id.clone(),
        label: options.label.clone(),
        state_dir: state_dir.display().to_string(),
        machine: DaemonIdentity::local_machine(),
        pid: std::process::id(),
    };
    let lease = match ServerLease::acquire(&client, &identity, LeaseTiming::default()) {
        Ok(lease) => lease,
        Err(err @ ServerLeaseError::Forbidden { .. }) => {
            tracing::warn!(
                "{err}; continuing without it. A restricted Incus project normally keeps its own \
                 images and networks, so two daemons do not collide there"
            );
            return Ok(None);
        }
        Err(err) => bail!("{err}"),
    };
    tracing::info!(
        profile = lease.profile_name(),
        "this daemon is the only wssp daemon on its Incus server"
    );
    lease
        .spawn_renewal(Arc::new(|event| match event {
            LeaseEvent::Conflict(other) => tracing::error!(
                "{other}; one wssp daemon per Incus server is supported, so this daemon refuses \
                 new sandboxes (running sandboxes, expiry and reconnects continue) until the \
                 other daemon stops"
            ),
            LeaseEvent::Cleared => tracing::info!(
                "no other wssp daemon drives this Incus server any more; new sandboxes are \
                 accepted again"
            ),
            LeaseEvent::RenewFailed(detail) => {
                tracing::warn!("could not renew this daemon's Incus server marker: {detail}");
            }
        }))
        .context("cannot start the Incus server marker renewal")?;
    Ok(Some(lease))
}

fn init_runtime(
    options: &ConnectOptions,
    state_dir: &std::path::Path,
    lease: &mut LeaseSlot,
) -> Result<RuntimeSetup> {
    #[cfg(not(target_os = "linux"))]
    let _: &mut () = lease;
    let knobs = FakeRuntimeKnobs::from_lookup(|key| std::env::var_os(key))?;
    match options.runtime {
        HostRuntimeKind::Fake => Ok((Box::new(knobs.build()), None)),
        #[cfg(target_os = "linux")]
        HostRuntimeKind::IncusKvm => {
            knobs.refuse_for_real_runtime()?;
            let mut config = IncusConfig::from_env();
            if let Some(project) = &options.incus_project {
                config.project = project.clone();
            }
            // The shared daemon-allocation lock lives in an
            // administrator-provisioned system directory (outside every
            // private-temp-affected path). Provision it when we can and
            // otherwise fail enrollment with the exact operator command,
            // before the relay starts serving creates.
            // Skipped when the deliberate dev/test binary override is in
            // use (shim-driven harness); acquisition still validates the
            // directory at every use regardless.
            if std::env::var_os("WSSP_INCUS_BINARY").is_none() {
                incus_host_preflight(std::path::Path::new(
                    sandbox_runtime::IncusClient::BRIDGE_NETFILTER_PROC,
                ))?;
            }
            // One wssp daemon per Incus server: check before the runtime
            // touches Incus (project setup included). Only this daemon path
            // checks; CLI commands that read Incus never do.
            if !shared_incus_override_enabled(&options.server_url)? {
                *lease = claim_incus_server(&config, options, state_dir)?;
            }
            let mut runtime = IncusKvmRuntime::new(config)?;
            // Debug test daemons on an Incus double only (gated at start);
            // set before `exec_supervisor` below clones the client.
            #[cfg(debug_assertions)]
            if let Some(timeout) =
                installed_runtime_test_timing().and_then(|timing| timing.guest_terminate)
            {
                runtime.set_guest_terminate_timeout(timeout);
            }
            // The runtime's durable host state (network cleanup journal,
            // resolved plans, locks) lives under the same host state dir the
            // relay journal already uses — passed in, never env-derived.
            runtime.set_host_state_dir(state_dir.join("runtime"));
            // The root egress guard's socket client (G1): the start fence,
            // the early admission, the heartbeat and the deployment push all
            // ask this one guard, fresh per decision.
            // The socket is the system path (debug builds: under
            // `WSSP_TEST_GUARD_ROOT`, the same stand-in `wssp host guard status` uses).
            let probe: Arc<dyn sandbox_runtime::guard::probe::GuardProbe> =
                Arc::new(sandbox_runtime::guard::client::SocketGuardProbe::new(
                    crate::commands::guard::Paths::local().socket(),
                ));
            // A live second daemon on this Incus server reads as an unhealthy
            // guard: new sandboxes refused, running ones untouched.
            runtime.set_guard_probe(match lease.as_ref() {
                Some(lease) => Arc::new(lease.fence_probe(probe)),
                None => probe,
            });
            // run_connect_with performs the authoritative startup census.
            let supervisor = runtime.exec_supervisor();
            Ok((Box::new(runtime), Some(supervisor)))
        }
    }
}

/// Incus host prerequisites, checked before the relay serves any create
/// (E-11). Each failure names the exact operator command. Bridge netfilter
/// is checked first: it needs no daemon or lock-directory access.
#[cfg(target_os = "linux")]
fn incus_host_preflight(bridge_netfilter_proc: &std::path::Path) -> Result<()> {
    sandbox_runtime::IncusClient::preflight_bridge_netfilter(bridge_netfilter_proc)
        .map_err(|err| anyhow::anyhow!("{err}"))?;
    sandbox_runtime::IncusClient::ensure_daemon_lock_dir_provisioned()
        .map_err(|err| anyhow::anyhow!("{err}"))
}

/// The hello will advertise `egressPolicy: false`, so the server refuses
/// every create on this host (`UNSUPPORTED_CAPABILITY`). The wire carries no
/// reason; the operator reads it here (E-06).
fn egress_unavailable_message(runtime: &dyn SandboxRuntime) -> String {
    let reason = runtime
        .egress_enforcement_unavailable_reason()
        .unwrap_or_else(|| "the runtime cannot prove egress enforcement".to_string());
    format!("egress enforcement unavailable; this host cannot create sandboxes: {reason}")
}

fn warn_egress_unavailable(runtime: &dyn SandboxRuntime) {
    tracing::warn!("{}", egress_unavailable_message(runtime));
}

fn canonical_server_binding(url: &Url) -> String {
    let mut canonical = url.clone();
    canonical.set_query(None);
    canonical.set_fragment(None);
    let _ = canonical.set_username("");
    let _ = canonical.set_password(None);
    if let Some(host) = canonical.host_str().map(str::to_ascii_lowercase) {
        let _ = canonical.set_host(Some(&host));
    }
    if canonical.port() == canonical.port_or_known_default() {
        let default = match canonical.scheme() {
            "wss" | "https" => 443,
            "ws" | "http" => 80,
            _ => 0,
        };
        if canonical.port() == Some(default) {
            let _ = canonical.set_port(None);
        }
    }
    canonical.to_string()
}

fn resolve_instance_name(
    sandbox_id: &str,
    incus_name: Option<&str>,
) -> Result<String, DispatchError> {
    resolve_managed_instance_name(sandbox_id, incus_name).map_err(runtime_err)
}

#[cfg(target_os = "linux")]
type CommandSupervisor = ExecSupervisor;
#[cfg(not(target_os = "linux"))]
type CommandSupervisor = ();

struct PendingFilePut {
    reservation: super::supervisor::UploadReservation,
    dispatch: OperationDispatch,
    instance_name: String,
    spool: sandbox_runtime::FileStaging,
    next: u64,
    last: Option<(u64, String, bool, u64)>,
    started: Instant,
    touched: Instant,
}

#[cfg(test)]
fn apply_cancel(
    supervisor: Option<&CommandSupervisor>,
    runtime: &dyn SandboxRuntime,
    authority: &mut HostAuthority,
    pending_puts: &mut HashMap<String, PendingFilePut>,
    operation_id: &str,
    generation: u64,
    attempt: u64,
) {
    if authority
        .accept_cancel(operation_id, generation, attempt)
        .is_err()
    {
        return;
    }
    #[cfg(target_os = "linux")]
    if let Some(supervisor) = supervisor {
        let _ = supervisor.cancel(operation_id);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = supervisor;
    let _ = runtime.cancel_operation(operation_id);
    if pending_puts.remove(operation_id).is_some() {
        authority.complete(operation_id);
    }
}

/// Test entry point: parses a whole frame, then applies it as stdin when it is
/// flagged so (the relay loop parses once and calls [`apply_stdin`]).
#[cfg(all(test, target_os = "linux"))]
fn apply_stdin_chunk(
    journal: &HostJournal,
    supervisor: Option<&ExecSupervisor>,
    runtime: &dyn SandboxRuntime,
    authority: &HostAuthority,
    frame: &[u8],
) -> Result<bool, Box<FinishedOp>> {
    let Ok((metadata, body)) = parse_binary_frame_ref(frame) else {
        return Ok(false);
    };
    let is_stdin = metadata
        .flags
        .as_ref()
        .and_then(|flags| flags.stdin)
        .unwrap_or(false);
    if !is_stdin {
        return Ok(false);
    }
    apply_stdin(
        journal,
        supervisor,
        runtime,
        authority,
        &metadata,
        body.to_vec(),
    )
}

/// Applies one stdin-flagged chunk whose frame the caller already parsed.
#[cfg(target_os = "linux")]
fn apply_stdin(
    journal: &HostJournal,
    supervisor: Option<&ExecSupervisor>,
    runtime: &dyn SandboxRuntime,
    authority: &HostAuthority,
    metadata: &StreamBinaryMetadata,
    body: Vec<u8>,
) -> Result<bool, Box<FinishedOp>> {
    let eof = metadata.r#type == StreamKind::End || metadata.final_chunk == Some(true);
    let accepted = authority.accept_stdin(
        &metadata.operation_id,
        metadata.generation,
        metadata.attempt,
        metadata.sequence,
        body,
        eof,
    );
    let requests = match accepted {
        Ok(requests) => requests,
        Err(err) => {
            return Err(fail_stdin(
                journal,
                supervisor,
                runtime,
                authority,
                metadata,
                DispatchError {
                    reason: None,
                    code: err.code.into(),
                    message: err.message,
                },
            ));
        }
    };
    for request in requests {
        let result = if let Some(supervisor) = supervisor {
            supervisor.write_stdin(&request)
        } else {
            runtime.write_stdin(&request)
        };
        if let Err(err) = result {
            return Err(fail_stdin(
                journal,
                supervisor,
                runtime,
                authority,
                metadata,
                runtime_err(err.into_error()),
            ));
        }
    }
    Ok(true)
}

#[cfg(target_os = "linux")]
fn fail_stdin(
    journal: &HostJournal,
    supervisor: Option<&ExecSupervisor>,
    runtime: &dyn SandboxRuntime,
    authority: &HostAuthority,
    metadata: &StreamBinaryMetadata,
    error: DispatchError,
) -> Box<FinishedOp> {
    let sandbox_id = authority
        .pending(&metadata.operation_id)
        .map(|work| work.sandbox_id)
        .unwrap_or_default();
    // Stdin failure joins the same durable cancellation owner. It must not
    // revoke the exec's cleanup permit or race a user cancel with a second kill.
    if journal
        .request_cancel(
            authority,
            &metadata.operation_id,
            metadata.generation,
            metadata.attempt,
        )
        .is_ok_and(|accepted| accepted.is_ok())
        && supervisor.is_none()
    {
        let _ = runtime.cancel_operation(&metadata.operation_id);
    }
    Box::new(super::supervisor::finish_effect(
        &metadata.operation_id,
        &sandbox_id,
        metadata.generation,
        metadata.attempt,
        Err(error.into_runtime().into()),
    ))
}

type ReadyUpload = (
    OperationDispatch,
    String,
    sandbox_runtime::FileContent,
    super::supervisor::UploadReservation,
);
/// Outcome of one inbound upload frame. A bad frame settles its own operation;
/// it never tears down the relay connection.
enum PutChunk {
    /// Not an upload frame for current pending work (stale, foreign, late).
    Ignored,
    /// Written (or an identical replay of the last frame); ACK it.
    Accepted,
    /// Final frame written and the manifest verified; ACK it and submit.
    Ready(ReadyUpload),
    /// The upload is refused; its pending entry is gone. Settle it terminally.
    Failed(OperationDispatch, SandboxErrorCode, String),
}
fn apply_file_put_chunk(
    pending: &mut HashMap<String, PendingFilePut>,
    authority: &HostAuthority,
    m: &StreamBinaryMetadata,
    body: &[u8],
) -> PutChunk {
    if m.flags.as_ref().and_then(|f| f.file_upload) != Some(true)
        || authority
            .accept_stream(&m.operation_id, m.generation, m.attempt)
            .is_err()
    {
        return PutChunk::Ignored;
    }
    let Some(entry) = pending.get_mut(&m.operation_id) else {
        return PutChunk::Ignored;
    };
    if entry.dispatch.generation != m.generation || entry.dispatch.attempt != m.attempt {
        return PutChunk::Ignored;
    }
    let digest = super::journal::sha256_hex(body);
    let ended = m.r#type == StreamKind::End || m.final_chunk == Some(true);
    let refuse = |pending: &mut HashMap<String, PendingFilePut>, code, message: &str| {
        let put = pending.remove(&m.operation_id).expect("entry exists");
        PutChunk::Failed(put.dispatch, code, message.into())
    };
    let Some(offset) = m.offset else {
        return refuse(
            pending,
            SandboxErrorCode::ProtocolError,
            "upload frame lacks offset",
        );
    };
    if entry.last.as_ref() == Some(&(m.sequence, digest.clone(), ended, offset)) {
        return PutChunk::Accepted;
    }
    if m.sequence != entry.next
        || entry.next >= 16384
        || offset != entry.spool.len()
        || (!ended && body.is_empty())
    {
        return refuse(
            pending,
            SandboxErrorCode::ProtocolError,
            "upload has a gap or conflicting replay",
        );
    }
    if let Err(error) = entry.spool.write_all(body) {
        // Oversize (beyond the declared length) or a host disk fault.
        let code = if entry.spool.len() + body.len() as u64 > entry.dispatch.file_size.unwrap_or(0)
        {
            SandboxErrorCode::RequestTooLarge
        } else {
            SandboxErrorCode::Internal
        };
        return refuse(pending, code, &format!("upload staging failed: {error}"));
    }
    entry.next += 1;
    entry.last = Some((m.sequence, digest, ended, offset));
    entry.touched = Instant::now();
    if !ended {
        return PutChunk::Accepted;
    }
    let put = pending.remove(&m.operation_id).expect("entry exists");
    let expected = (
        put.dispatch.file_size.unwrap_or_default(),
        put.dispatch.file_sha256.clone().unwrap_or_default(),
    );
    match put.spool.seal(Some((expected.0, &expected.1))) {
        Ok(content) => PutChunk::Ready((put.dispatch, put.instance_name, content, put.reservation)),
        Err(error) => PutChunk::Failed(put.dispatch, error.code, error.message),
    }
}

type Downloads = HashMap<String, (FinishedOp, super::files::DownloadWindow)>;
/// Idle and absolute transfer lifetimes (shared transfer defaults).
const TRANSFER_IDLE: Duration = Duration::from_secs(15 * 60);
const TRANSFER_ABSOLUTE: Duration = Duration::from_secs(60 * 60);

/// Single settlement owner for host transfer state (C28 G3). Every pending
/// upload and download window leaves this function either still live or with
/// a terminal outcome: expired uploads are journaled FAILED (nothing reached
/// the runtime) and returned for delivery; drained downloads return their
/// result; expired or cancelled downloads return a FAILED terminal. Authority
/// is completed only for the exact (generation, attempt) this state owns.
/// Superseded state (authority now belongs to another attempt or none) is
/// dropped without touching the successor; the journal keeps its evidence.
fn settle_transfers(
    now: Instant,
    pending_puts: &mut HashMap<String, PendingFilePut>,
    downloads: &mut Downloads,
    authority: &HostAuthority,
    journal: &HostJournal,
) -> Result<Vec<FinishedOp>> {
    let owns = |id: &str, generation: u64, attempt: u64| {
        authority.accept_completion(id, generation, attempt).is_ok()
    };
    let mut deliver = Vec::new();
    let expired_puts: Vec<String> = pending_puts
        .iter()
        .filter(|(id, put)| {
            !owns(id, put.dispatch.generation, put.dispatch.attempt)
                || now.duration_since(put.started) >= TRANSFER_ABSOLUTE
                || now.duration_since(put.touched) >= TRANSFER_IDLE
        })
        .map(|(id, _)| id.clone())
        .collect();
    for id in expired_puts {
        let put = pending_puts.remove(&id).expect("listed above");
        let d = &put.dispatch;
        if !owns(&id, d.generation, d.attempt) {
            // Authority moved on (lifecycle revocation or supersession); this
            // connection may not answer for it. Nothing reached the runtime, so
            // the exact attempt's receipt becomes a definite FAILED for replay.
            if journal.lookup(&id).is_some_and(|receipt| {
                receipt.generation == d.generation
                    && receipt.attempt == d.attempt
                    && !receipt.is_terminal()
            }) {
                journal.record_result(
                    &id,
                    OperationState::Failed,
                    None,
                    Some(SandboxErrorCode::Cancelled),
                    Some("upload authority revoked before any write".into()),
                )?;
            }
            continue;
        }
        let receipt = journal.record_result(
            &id,
            OperationState::Failed,
            None,
            Some(SandboxErrorCode::Timeout),
            Some("upload expired before all chunks arrived; nothing was written".into()),
        )?;
        authority.complete(&id);
        let reason = receipt.error_reason();
        deliver.push(FinishedOp {
            operation_id: id,
            sandbox_id: d.sandbox_id.clone(),
            generation: d.generation,
            attempt: d.attempt,
            state: receipt.state,
            payload: receipt.result,
            error: receipt.error_code.map(|code| DispatchError {
                reason,
                code,
                message: receipt.error_message.unwrap_or_default(),
            }),
            download: None,
            interim: false,
            readiness_detail: None,
            owner: None,
        });
    }
    let settled: Vec<String> = downloads
        .iter()
        .filter(|(id, (item, window))| {
            !owns(id, item.generation, item.attempt)
                || authority
                    .accept_stream(id, item.generation, item.attempt)
                    .is_err()
                || window.drained()
                || now.duration_since(window.started()) >= TRANSFER_ABSOLUTE
                || now.duration_since(window.progressed()) >= TRANSFER_IDLE
        })
        .map(|(id, _)| id.clone())
        .collect();
    for id in settled {
        let (mut item, window) = downloads.remove(&id).expect("listed above");
        if !owns(&id, item.generation, item.attempt) {
            continue;
        }
        if !window.drained() {
            let cancelled = authority
                .accept_stream(&id, item.generation, item.attempt)
                .is_err();
            item.state = OperationState::Failed;
            item.payload = None;
            item.error = Some(DispatchError {
                reason: None,
                code: if cancelled {
                    SandboxErrorCode::Cancelled.into()
                } else {
                    SandboxErrorCode::Timeout.into()
                },
                message: if cancelled {
                    "download cancelled before the final chunk was acknowledged".into()
                } else {
                    "download expired before the final chunk was acknowledged".into()
                },
            });
        }
        authority.complete(&id);
        deliver.push(item);
    }
    Ok(deliver)
}

#[cfg(all(test, target_os = "linux"))]
fn spawn_supervised_run(
    supervisor: ExecSupervisor,
    finished_tx: mpsc::Sender<FinishedOp>,
    dispatch: &OperationDispatch,
    instance_name: String,
    authority: HostAuthority,
) -> Option<thread::JoinHandle<()>> {
    spawn_supervised_run_after(
        supervisor,
        finished_tx,
        dispatch,
        instance_name,
        authority,
        || {},
    )
}

#[cfg(all(test, target_os = "linux"))]
fn spawn_supervised_run_after(
    supervisor: ExecSupervisor,
    finished_tx: mpsc::Sender<FinishedOp>,
    dispatch: &OperationDispatch,
    instance_name: String,
    authority: HostAuthority,
    before_run: impl FnOnce() + Send + 'static,
) -> Option<thread::JoinHandle<()>> {
    let request =
        match super::supervisor::run_command_request_from_dispatch(dispatch, instance_name, &[]) {
            Ok(request) => request,
            Err(err) => {
                let _ = finished_tx.send(FinishedOp {
                    operation_id: dispatch.operation_id.clone(),
                    sandbox_id: dispatch.sandbox_id.clone(),
                    generation: dispatch.generation,
                    attempt: dispatch.attempt,
                    state: OperationState::Failed,
                    payload: None,
                    error: Some(err),
                    download: None,
                    interim: false,
                    readiness_detail: None,
                    owner: None,
                });
                return None;
            }
        };
    let operation_id = dispatch.operation_id.clone();
    let sandbox_id = dispatch.sandbox_id.clone();
    let generation = dispatch.generation;
    let attempt = dispatch.attempt;
    Some(thread::spawn(move || {
        let finished = match supervisor.run_with_admission(
            &supervisor.bind(&request).unwrap(),
            &request,
            || {
                // Early tuple check grants no spawn authority. The guard below must
                // revalidate even when this worker was descheduled after that check.
                authority
                    .accept_stream(&request.operation_id, request.generation, request.attempt)
                    .map_err(|err| sandbox_runtime::RuntimeError::new(err.code, err.message))?;
                before_run();
                authority
                    .register_exec(&request.operation_id, request.generation, request.attempt)
                    .map_err(|err| sandbox_runtime::RuntimeError::new(err.code, err.message))
            },
        ) {
            Ok(response) => FinishedOp {
                operation_id,
                sandbox_id,
                generation,
                attempt,
                state: response.command.state,
                payload: Some(command_result_json(&response)),
                error: (response.command.state == OperationState::Cancelled).then(|| {
                    DispatchError {
                        reason: None,
                        code: SandboxErrorCode::Cancelled.into(),
                        message: "command was cancelled".to_string(),
                    }
                }),
                download: None,
                interim: false,
                readiness_detail: None,
                owner: None,
            },
            Err(err) => FinishedOp {
                operation_id,
                sandbox_id,
                generation,
                attempt,
                state: err.state(),
                payload: err.command().map(command_result_json),
                error: Some(runtime_err(err.into_error())),
                download: None,
                interim: false,
                readiness_detail: None,
                owner: None,
            },
        };
        let _ = finished_tx.send(finished);
    }))
}

// Drop runs on every socket-loop exit, including `?` and protocol errors.
struct RelayWorkers {
    authority: HostAuthority,
    handles: Vec<thread::JoinHandle<()>>,
    supervisor: Option<CommandSupervisor>,
}
impl RelayWorkers {
    /// Revoke-and-reconnect: every pending attempt loses its gates now (each
    /// is owed a late receipt) and every local exec group is killed, exactly
    /// as the per-session teardown did. Returns the revoked count.
    fn revoke(&mut self) -> usize {
        let revoked = self.authority.revoke_all();
        #[cfg(target_os = "linux")]
        if let Some(supervisor) = &self.supervisor {
            supervisor.kill_local_groups();
        }
        self.reap();
        revoked
    }
    fn reap(&mut self) {
        let mut index = 0;
        while index < self.handles.len() {
            if self.handles[index].is_finished() {
                let _ = self.handles.swap_remove(index).join();
            } else {
                index += 1;
            }
        }
    }
}
impl Drop for RelayWorkers {
    fn drop(&mut self) {
        self.authority.shutdown();
        #[cfg(not(target_os = "linux"))]
        let _ = &self.supervisor;
        #[cfg(target_os = "linux")]
        if let Some(supervisor) = &self.supervisor {
            supervisor.kill_local_groups();
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !self.handles.is_empty() && std::time::Instant::now() < deadline {
            self.reap();
            if !self.handles.is_empty() {
                thread::sleep(Duration::from_millis(10));
            }
        }
        #[cfg(target_os = "linux")]
        if let Some(supervisor) = &self.supervisor {
            supervisor.kill_local_groups();
        }
        // Remaining JoinHandles detach on drop. Authority stays revoked forever.
    }
}

/// Short reads keep the loop responsive; a write blocked past `write` (N2)
/// fails the session, which classifies the IO error as a lost transport (a
/// partially written frame leaves the socket unusable anyway).
fn set_ws_timeouts(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    read: Duration,
    write: Duration,
) -> Result<()> {
    match socket.get_mut() {
        tungstenite::stream::MaybeTlsStream::Plain(stream) => {
            stream.set_read_timeout(Some(read))?;
            stream.set_write_timeout(Some(write))?;
        }
        tungstenite::stream::MaybeTlsStream::Rustls(stream) => {
            stream.get_mut().set_read_timeout(Some(read))?;
            stream.get_mut().set_write_timeout(Some(write))?;
        }
        _ => {}
    }
    Ok(())
}

/// Preserve precise catalog codes in the strict 1.0 result envelope.
fn send_finished(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    wire: WireCodes,
    kind: Option<&str>,
    finished: FinishedOp,
) -> Result<()> {
    let error = finished.error.map(|err| ProtocolErrorDetail {
        reason: err.reason,
        code: err.code,
        message: err.message,
        operation_id: Some(finished.operation_id.clone()),
        sandbox_id: Some(finished.sandbox_id.clone()),
    });
    let frame = DaemonControlMessage::OperationResult {
        id: format!("result-{}", finished.operation_id),
        operation_id: finished.operation_id,
        sandbox_id: finished.sandbox_id,
        generation: finished.generation,
        attempt: finished.attempt,
        state: finished.state,
        error,
        result: finished.payload,
    };
    socket.send(Message::Text(super::spell(wire, &frame, kind)?.into()))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn send_operation_result(
    socket: &mut tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<std::net::TcpStream>>,
    wire: WireCodes,
    kind: &str,
    operation_id: &str,
    sandbox_id: &str,
    generation: u64,
    attempt: u64,
    result: Result<Option<serde_json::Value>, DispatchError>,
) -> Result<()> {
    let finished = match result {
        Ok(payload) => FinishedOp {
            operation_id: operation_id.to_string(),
            sandbox_id: sandbox_id.to_string(),
            generation,
            attempt,
            state: OperationState::Succeeded,
            payload,
            error: None,
            download: None,
            interim: false,
            readiness_detail: None,
            owner: None,
        },
        Err(err) => FinishedOp {
            operation_id: operation_id.to_string(),
            sandbox_id: sandbox_id.to_string(),
            generation,
            attempt,
            // No admitted receipt or absence proof exists on this path.
            state: if matches!(kind, "sandbox.create" | "sandbox.reconnect") {
                sandbox_runtime::allocation_refusal_state(false, None)
            } else {
                OperationState::Failed
            },
            payload: None,
            error: Some(err),
            download: None,
            interim: false,
            readiness_detail: None,
            owner: None,
        },
    };
    send_finished(socket, wire, Some(kind), finished)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // The helper exists only in debug builds (the knob does), so does its test.
    #[cfg(debug_assertions)]
    #[test]
    fn a_short_test_silence_floor_shortens_the_heartbeat_so_it_is_the_deadline() {
        let heartbeat = Duration::from_secs(5);
        let floor = Duration::from_secs(3);
        let shortened = heartbeat_within_silence(heartbeat, floor);
        assert_eq!(shortened, Duration::from_millis(500));
        assert_eq!(floor.max(shortened.saturating_mul(6)), floor);
        // A floor that already fits six heartbeats keeps the heartbeat.
        assert_eq!(
            heartbeat_within_silence(heartbeat, Duration::from_secs(60)),
            heartbeat
        );
        assert_eq!(
            heartbeat_within_silence(heartbeat, Duration::from_millis(1)),
            Duration::from_millis(1)
        );
    }

    #[cfg(unix)]
    #[test]
    fn bz_current_over_max_timeout_is_per_operation_protocol_error() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().to_owned();
        let fake = sandbox_runtime::FakeRuntime::new();
        let binding = TransportBindingV11 {
            server: format!("ws://{address}/ws/sandbox-host"),
            host_owner_id: "owner-1".into(),
            host_id: "host-1".into(),
        };
        let clock = Arc::new(crate::sandbox_relay::clock::LeaseClock::default());
        super::expiry_tests::seed(
            dir.path(),
            &binding,
            &clock,
            &fake,
            "sbx",
            clock.now_ms().unwrap() + 600_000,
            sandbox_protocol::LeaseAction::Stop,
        );
        let shutdown = ShutdownSignal::default();
        let daemon_shutdown = shutdown.clone();
        let client = thread::spawn(move || {
            run_connect_with(
                &ConnectOptions {
                    host_terminal: None,
                    server_url: format!("ws://{address}"),
                    host_token: ["test", "only", "token"].join("-"),
                    host_id: "host-1".into(),
                    label: "over-max".into(),
                    runtime: HostRuntimeKind::Fake,
                    incus_project: None,
                    state_dir: Some(state_dir),
                    heartbeat: Duration::from_secs(30),
                    sandbox_memory_mib: None,
                    max_sandbox_cpu_count: None,
                    sandbox_vcpu_budget: Some(4),
                    max_concurrent_commands: 16,
                    shutdown: daemon_shutdown,
                },
                |_| Ok((Box::new(fake), None)),
            )
        });
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake).unwrap();
        wire.read().unwrap();
        let mut ack: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
        ))
        .unwrap();
        ack["supportedProtocolVersions"] = json!(["1.0"]);
        ack["protocolVersion"] = json!("1.0");
        ack["capabilities"]["protocolVersion"] = json!("1.0");
        ack["connectionEpoch"] = json!(3);
        crate::sandbox_relay::test_support::send_ready_hello_value(&mut wire, ack, "host-1");
        crate::sandbox_relay::test_support::ack_registration(&mut wire);
        // A second operation on this very socket proves the first refusal did
        // not tear down the host session or enter a reconnect loop.
        let mut results = Vec::new();
        for id in ["over-max-1", "over-max-2"] {
            wire.send(Message::Text(
                crate::sandbox_relay::test_support::current_control_fixture(
                    json!({"sandboxOwnerId":"owner",
                        "type":"operation.dispatch", "operationId":id, "sandboxId":"sbx",
                        "kind":"command.run", "resultVersion":1, "generation":1, "attempt":1,
                        "idempotencyKey":id, "argv":["true"], "timeoutMs":1_800_001,
                        "processId":format!("process-{id}"), "bodyHash":"a".repeat(64),
                        "incusFingerprint":format!("sha256:{}", "a".repeat(64))
                    }),
                )
                .to_string()
                .into(),
            ))
            .unwrap();
            loop {
                let frame = wire.read();
                let Ok(Message::Text(text)) = frame else {
                    break;
                };
                let value: serde_json::Value = serde_json::from_str(&text).unwrap();
                if value["type"] == "operation.result" {
                    results.push(value);
                    break;
                }
            }
            if results.len() < (if id == "over-max-1" { 1 } else { 2 }) {
                break;
            }
        }
        shutdown.request();
        let _ = wire.close(None);
        drop(wire);
        let _ = client.join().unwrap();
        assert_eq!(
            results.len(),
            2,
            "both operations must return on the same host connection"
        );
        for (result, id) in results.iter().zip(["over-max-1", "over-max-2"]) {
            assert_eq!(result["operationId"], id);
            assert_eq!(result["state"], "failed");
            assert_eq!(result["error"]["code"], "protocol_error");
            assert_eq!(result["error"]["message"], "invalid command timeout");
        }
    }

    /// Shared with `apps/server/src/sandbox-relay/protocol-signal.test.ts`.
    fn signal_fixture() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../../crates/sandbox-protocol/fixtures/control_process_signal.json"
        ))
        .unwrap()
    }

    fn signal_dispatch(frame: &serde_json::Value) -> OperationDispatch {
        match sandbox_protocol::parse_server_control(&frame.to_string()) {
            Ok(ServerControlMessage::OperationDispatch(dispatch)) => *dispatch,
            other => panic!("{frame}: {other:?}"),
        }
    }

    /// E4-01: the server frame for a queued signal carries `pid` copied from
    /// its qualified target; a frame without it (what production sent) or
    /// with another pid decodes but is not a valid signal dispatch.
    #[test]
    fn shared_signal_fixture_identity_is_checked_per_operation() {
        let fixture = signal_fixture();
        let dispatch = signal_dispatch(&fixture["dispatch"]);
        assert!(fs_process_fields_allowed(&dispatch));
        assert_eq!(
            dispatch.pid,
            dispatch.process.as_ref().map(|process| process.pid)
        );
        assert_eq!(
            Some(fixture["queuedPayload"]["process"]["pid"].as_u64().unwrap()),
            dispatch.pid.map(u64::from)
        );
        for frame in fixture["refusedDispatch"].as_array().unwrap() {
            assert!(
                !fs_process_fields_allowed(&signal_dispatch(frame)),
                "{frame}"
            );
        }
    }

    /// E4-01 end to end on one socket with the fake runtime: invalid signal
    /// (and mis-sized) dispatches are refused as single operations
    /// (`protocol_error`) and the session survives to deliver a valid SIGTERM
    /// to the running command.
    #[cfg(unix)]
    #[test]
    fn invalid_signal_dispatch_is_refused_per_operation_and_sigterm_still_delivers() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().to_owned();
        let fake = sandbox_runtime::FakeRuntime::with_command_delay(Duration::from_secs(3));
        let observed = fake.clone();
        let binding = TransportBindingV11 {
            server: format!("ws://{address}/ws/sandbox-host"),
            host_owner_id: "owner-1".into(),
            host_id: "host-1".into(),
        };
        let clock = Arc::new(crate::sandbox_relay::clock::LeaseClock::default());
        super::expiry_tests::seed(
            dir.path(),
            &binding,
            &clock,
            &fake,
            "sbx-signal",
            clock.now_ms().unwrap() + 600_000,
            sandbox_protocol::LeaseAction::Stop,
        );
        let shutdown = ShutdownSignal::default();
        let daemon_shutdown = shutdown.clone();
        let client = thread::spawn(move || {
            run_connect_with(
                &ConnectOptions {
                    host_terminal: None,
                    server_url: format!("ws://{address}"),
                    host_token: ["test", "only", "token"].join("-"),
                    host_id: "host-1".into(),
                    label: "signal".into(),
                    runtime: HostRuntimeKind::Fake,
                    incus_project: None,
                    state_dir: Some(state_dir),
                    heartbeat: Duration::from_secs(30),
                    sandbox_memory_mib: None,
                    max_sandbox_cpu_count: None,
                    sandbox_vcpu_budget: Some(4),
                    max_concurrent_commands: 16,
                    shutdown: daemon_shutdown,
                },
                |_| Ok((Box::new(fake), None)),
            )
        });
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake).unwrap();
        wire.read().unwrap();
        let mut ack: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
        ))
        .unwrap();
        ack["supportedProtocolVersions"] = json!(["1.0"]);
        ack["protocolVersion"] = json!("1.0");
        ack["capabilities"]["protocolVersion"] = json!("1.0");
        ack["connectionEpoch"] = json!(3);
        crate::sandbox_relay::test_support::send_ready_hello_value(&mut wire, ack, "host-1");
        crate::sandbox_relay::test_support::ack_registration(&mut wire);
        let read_until = |wire: &mut tungstenite::WebSocket<std::net::TcpStream>,
                          want: &dyn Fn(&serde_json::Value) -> bool|
         -> Option<serde_json::Value> {
            loop {
                // Output chunks are binary; only a read error ends the wait.
                let text = match wire.read() {
                    Ok(Message::Text(text)) => text,
                    Ok(_) => continue,
                    Err(_) => return None,
                };
                let value: serde_json::Value = serde_json::from_str(&text).unwrap();
                if want(&value) {
                    return Some(value);
                }
            }
        };
        // A tracked command that stays running long enough to be signalled.
        wire.send(Message::Text(
            crate::sandbox_relay::test_support::current_control_fixture(
                json!({"sandboxOwnerId":"owner", "type":"operation.dispatch",
                "operationId":"op-command", "sandboxId":"sbx-signal", "kind":"command.run",
                "generation":1, "attempt":1, "idempotencyKey":"op-command",
                "argv":["sleep","300"], "processId":"proc-signal", "resultVersion":1,
                "bodyHash":"a".repeat(64),
                "incusFingerprint":format!("sha256:{}", "a".repeat(64))}),
            )
            .to_string()
            .into(),
        ))
        .unwrap();
        let started = read_until(&mut wire, &|v| v["type"] == "process.started")
            .expect("command start observation");
        let pid = started["pid"].as_u64().unwrap();
        let fixture = signal_fixture();
        let mut outcomes = Vec::new();
        for frame in fixture["refusedDispatch"].as_array().unwrap() {
            let mut frame = frame.clone();
            frame["process"]["pid"] = json!(pid);
            if frame.get("pid").is_some() {
                frame["pid"] = json!(pid + 1);
            }
            let id = frame["operationId"].clone();
            wire.send(Message::Text(
                crate::sandbox_relay::test_support::current_control_fixture(frame)
                    .to_string()
                    .into(),
            ))
            .unwrap();
            outcomes.push(read_until(&mut wire, &|v| {
                v["type"] == "operation.result" && v["operationId"] == id
            }));
        }
        // Sizing fields on non-launch work were also a session-ending bail.
        wire.send(Message::Text(
            crate::sandbox_relay::test_support::current_control_fixture(json!({"sandboxOwnerId":"owner", "type":"operation.dispatch",
                "operationId":"op-sized-stat", "sandboxId":"sbx-signal", "kind":"file.stat", "resultVersion":1,
                "generation":1, "attempt":1, "idempotencyKey":"op-sized-stat",
                "path":"/tmp", "bodyHash":"a".repeat(64),
                "allocation":{"cpuCount":1, "memoryMiB":1024, "diskGiB":32,
                    "storagePoolName":"default", "storageMarker":"a".repeat(32),
                    "chargedMemoryMiB":1280, "chargedVcpu":1, "rootChargeGiB":33}}))
            .to_string()
            .into(),
        ))
        .unwrap();
        let sized = read_until(&mut wire, &|v| {
            v["type"] == "operation.result" && v["operationId"] == "op-sized-stat"
        });
        // A result-kind dispatch without its required result version is
        // refused as that one operation while the session stays usable.
        let mut unversioned = Vec::new();
        for (id, kind) in [
            ("op-unversioned-stat", "file.stat"),
            ("op-unversioned-run", "command.run"),
        ] {
            wire.send(Message::Text(
                crate::sandbox_relay::test_support::current_control_fixture(
                    json!({"sandboxOwnerId":"owner", "type":"operation.dispatch",
                    "operationId":id, "sandboxId":"sbx-signal", "kind":kind,
                    "generation":1, "attempt":1, "idempotencyKey":id, "path":"/tmp",
                    "argv":["true"], "processId":format!("proc-{id}"), "bodyHash":"a".repeat(64),
                    "incusFingerprint":format!("sha256:{}", "a".repeat(64))}),
                )
                .to_string()
                .into(),
            ))
            .unwrap();
            unversioned.push(read_until(&mut wire, &|v| {
                v["type"] == "operation.result" && v["operationId"] == id
            }));
        }
        let mut valid = fixture["dispatch"].clone();
        valid["process"]["pid"] = json!(pid);
        valid["pid"] = json!(pid);
        wire.send(Message::Text(
            crate::sandbox_relay::test_support::current_control_fixture(valid)
                .to_string()
                .into(),
        ))
        .unwrap();
        let delivered = read_until(&mut wire, &|v| {
            v["type"] == "operation.result" && v["operationId"] == "op-signal"
        });
        shutdown.request();
        let _ = wire.close(None);
        drop(wire);
        let _ = client.join().unwrap();
        for (outcome, frame) in outcomes
            .iter()
            .zip(fixture["refusedDispatch"].as_array().unwrap())
        {
            let outcome = outcome.as_ref().expect("refusal on the same connection");
            assert_eq!(outcome["operationId"], frame["operationId"]);
            assert_eq!(outcome["state"], "failed");
            assert_eq!(outcome["error"]["code"], "protocol_error");
            assert_eq!(
                outcome["error"]["message"],
                "invalid process identity field"
            );
        }
        let sized = sized.expect("sizing refusal on the same connection");
        assert_eq!(sized["state"], "failed");
        assert_eq!(sized["error"]["code"], "protocol_error");
        assert_eq!(sized["error"]["message"], "invalid dispatch sizing fields");
        for refused in unversioned {
            let refused = refused.expect("unversioned refusal on the same connection");
            assert_eq!(refused["state"], "failed", "{refused}");
            assert_eq!(refused["error"]["code"], "protocol_error");
            assert_eq!(
                refused["error"]["message"],
                "invalid process identity field"
            );
        }
        let delivered = delivered.expect("valid signal on the same connection");
        assert_eq!(delivered["state"], "succeeded", "{delivered}");
        assert_eq!(delivered["result"]["payload"]["signal"], "SIGTERM");
        assert_eq!(delivered["result"]["payload"]["delivery"], "process_group");
        assert_eq!(
            observed.delivered_signals(),
            vec![(
                "op-command".to_string(),
                sandbox_runtime::ProcessSignal::Sigterm
            )]
        );
    }

    #[cfg(unix)]
    struct TerminalDaemon {
        dir: tempfile::TempDir,
        binding: TransportBindingV11,
        fingerprint: &'static str,
        shutdown: ShutdownSignal,
        client: thread::JoinHandle<Result<()>>,
        wire: tungstenite::WebSocket<std::net::TcpStream>,
    }

    /// An in-process daemon on the fake runtime, registered over a loopback
    /// relay at epoch 3, whose journal holds one ready sandbox (`sbx-term`,
    /// generation 1) with the guest and template identity a terminal needs.
    #[cfg(unix)]
    fn terminal_daemon(fake: sandbox_runtime::FakeRuntime) -> TerminalDaemon {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().to_owned();
        fake.fixture_root().unwrap();
        let binding = TransportBindingV11 {
            server: format!("ws://{address}/ws/sandbox-host"),
            host_owner_id: "owner-1".into(),
            host_id: "host-1".into(),
        };
        // The fake's fixture template (`CreateSandboxRequest::for_test`).
        let fingerprint: &'static str =
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        {
            // A ready sandbox whose journaled create carries the guest and
            // template identity a terminal open requires.
            let journal =
                crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                    .unwrap();
            let now = journal.clock.now_ms().unwrap();
            let create: OperationDispatch = serde_json::from_value(json!({
                "sandboxOwnerId":"owner", "operationId":"create-sbx-term",
                "sandboxId":"sbx-term", "kind":"sandbox.create",
                "allocation": crate::sandbox_relay::test_support::allocation(),
                "generation":1, "attempt":1, "idempotencyKey":"create-sbx-term",
                "bodyHash":"a".repeat(64), "incusFingerprint":fingerprint,
                "templateDigest":fingerprint, "guestUid":1234, "guestGid":2345,
                "guestHome":"/home/declared", "guestShell":"/bin/sh",
                "lease":{"revision":1, "deadlineUnixMs":now + 600_000,
                    "action":"stop", "expiryPolicy":"retry-force-60s"}}))
            .unwrap();
            journal
                .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &create))
                .unwrap();
            journal.accept_fixture_lease(&create).unwrap();
            let mut request =
                sandbox_runtime::CreateSandboxRequest::for_test("sbx-term", "create-sbx-term");
            request.lease = sandbox_protocol::HostLease {
                deadline_unix_ms: sandbox_protocol::HostLease::for_test().deadline_unix_ms,
                ..create.lease.clone().unwrap()
            };
            fake.create_fixture(&request).unwrap();
            journal
                .record_result(
                    "create-sbx-term",
                    OperationState::Succeeded,
                    Some(json!({"state":"ready","lease":create.lease})),
                    None,
                    None,
                )
                .unwrap();
        }
        let shutdown = ShutdownSignal::default();
        let daemon_shutdown = shutdown.clone();
        let client = thread::spawn(move || {
            run_connect_with(
                &ConnectOptions {
                    host_terminal: None,
                    server_url: format!("ws://{address}"),
                    host_token: ["test", "only", "token"].join("-"),
                    host_id: "host-1".into(),
                    label: "terminal".into(),
                    runtime: HostRuntimeKind::Fake,
                    incus_project: None,
                    state_dir: Some(state_dir),
                    heartbeat: Duration::from_secs(30),
                    sandbox_memory_mib: None,
                    max_sandbox_cpu_count: None,
                    sandbox_vcpu_budget: Some(4),
                    max_concurrent_commands: 16,
                    shutdown: daemon_shutdown,
                },
                |_| Ok((Box::new(fake), None)),
            )
        });
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake).unwrap();
        wire.read().unwrap();
        let mut ack: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
        ))
        .unwrap();
        ack["supportedProtocolVersions"] = json!(["1.0"]);
        ack["protocolVersion"] = json!("1.0");
        ack["capabilities"]["protocolVersion"] = json!("1.0");
        ack["connectionEpoch"] = json!(3);
        crate::sandbox_relay::test_support::send_ready_hello_value(&mut wire, ack, "host-1");
        crate::sandbox_relay::test_support::ack_registration(&mut wire);
        TerminalDaemon {
            dir,
            binding,
            fingerprint,
            shutdown,
            client,
            wire,
        }
    }

    /// A stop/kill refused for its wire sizing (no `allocation`) is one
    /// operation's `protocol_error`: it never reaches journal admission and
    /// never supersedes the sandbox's live PTYs (the relay loop used to run
    /// `terminals.on_dispatch` after `handle_dispatch` refused it).
    #[cfg(unix)]
    #[test]
    fn mis_sized_stop_and_kill_are_refused_without_superseding_live_terminals() {
        let fake = sandbox_runtime::FakeRuntime::new();
        let observed = fake.clone();
        let TerminalDaemon {
            dir,
            fingerprint,
            shutdown,
            client,
            mut wire,
            ..
        } = terminal_daemon(fake);
        let mut terminal_exits = Vec::new();
        let mut read_until = |wire: &mut tungstenite::WebSocket<std::net::TcpStream>,
                              want: &dyn Fn(&serde_json::Value) -> bool|
         -> Option<serde_json::Value> {
            loop {
                let text = match wire.read() {
                    Ok(Message::Text(text)) => text,
                    Ok(_) => continue,
                    Err(_) => return None,
                };
                let value: serde_json::Value = serde_json::from_str(&text).unwrap();
                if value["type"] == "terminal.exit" {
                    terminal_exits.push(value.clone());
                }
                if want(&value) {
                    return Some(value);
                }
            }
        };
        let fence = json!({"sessionId":"term-live", "operationId":"termop-live",
            "hostId":"host-1", "epoch":3,
            "target":{"kind":"sandbox", "sandboxId":"sbx-term", "generation":1}});
        wire.send(Message::Text(
            json!({"type":"terminal.open", "requestId":"open-live", "fence":fence,
                "rows":24, "cols":80})
            .to_string()
            .into(),
        ))
        .unwrap();
        let ready = read_until(&mut wire, &|v| {
            matches!(v["type"].as_str(), Some("terminal.ready" | "terminal.exit"))
        });
        let mut outcomes = Vec::new();
        for (id, kind) in [("op-stop", "sandbox.stop"), ("op-kill", "sandbox.kill")] {
            // Decodable, but invalid sizing: stop/kill must carry `allocation`.
            wire.send(Message::Text(
                crate::sandbox_relay::test_support::current_control_fixture(
                    json!({"sandboxOwnerId":"owner", "type":"operation.dispatch",
                    "operationId":id, "sandboxId":"sbx-term", "kind":kind,
                    "generation":1, "attempt":1, "idempotencyKey":id,
                    "bodyHash":"a".repeat(64), "incusFingerprint":fingerprint}),
                )
                .to_string()
                .into(),
            ))
            .unwrap();
            outcomes.push(read_until(&mut wire, &|v| {
                v["type"] == "operation.result" && v["operationId"] == id
            }));
        }
        // Give a (wrongly) superseded PTY time to stop and report its exit,
        // while proving the session still answers: a third refused frame on
        // the same connection round-trips.
        thread::sleep(Duration::from_millis(500));
        wire.send(Message::Text(
            crate::sandbox_relay::test_support::current_control_fixture(
                json!({"sandboxOwnerId":"owner", "type":"operation.dispatch",
                "operationId":"op-stop-again", "sandboxId":"sbx-term",
                "kind":"sandbox.stop", "generation":1, "attempt":1,
                "idempotencyKey":"op-stop-again", "bodyHash":"a".repeat(64),
                "incusFingerprint":fingerprint}),
            )
            .to_string()
            .into(),
        ))
        .unwrap();
        let again = read_until(&mut wire, &|v| {
            v["type"] == "operation.result" && v["operationId"] == "op-stop-again"
        });
        let control = observed.pty_control("sbx-term", "term-live");
        let terminated_while_connected = control.as_ref().map(|c| c.terminated());
        shutdown.request();
        let _ = wire.close(None);
        drop(wire);
        let _ = client.join().unwrap();
        let ready = ready.expect("terminal open answered on the connection");
        assert_eq!(ready["type"], "terminal.ready", "{ready}");
        assert_eq!(ready["requestId"], "open-live");
        for (outcome, id) in outcomes.iter().zip(["op-stop", "op-kill"]) {
            let outcome = outcome.as_ref().expect("refusal on the same connection");
            assert_eq!(outcome["operationId"], id);
            assert_eq!(outcome["state"], "failed");
            assert_eq!(outcome["error"]["code"], "protocol_error");
            assert_eq!(
                outcome["error"]["message"],
                "invalid dispatch sizing fields"
            );
        }
        let again = again.expect("session survives both refusals");
        assert_eq!(again["error"]["code"], "protocol_error");
        assert!(
            terminal_exits.is_empty(),
            "a refused stop/kill ended the live terminal: {terminal_exits:?}"
        );
        assert_eq!(
            terminated_while_connected,
            Some(false),
            "the live PTY must not be terminated by a refused dispatch"
        );
        assert_eq!(
            observed.query_sandbox("sbx-term", None, None).unwrap(),
            Some(sandbox_protocol::SandboxLifecycleState::Ready)
        );
        // Journal admission persists `receipts/<operationId>.json` before any
        // effect; a refused frame must leave none.
        let receipts = dir.path().join("receipts");
        assert!(receipts.join("create-sbx-term.json").exists());
        for id in ["op-stop", "op-kill", "op-stop-again"] {
            assert!(
                !receipts.join(format!("{id}.json")).exists(),
                "refused `{id}` must not create a journal intent"
            );
        }
    }

    /// A clean in-process shutdown after a terminal was opened releases the
    /// journal lock even while another handle onto the runtime survives (here
    /// a clone of the fake; in a daemon, any detached thread still holding the
    /// runtime): the runtime's enforcement-loss hook must not keep the
    /// daemon's journal, and with it the exclusive state-dir lock, alive.
    /// A second daemon instance on the same state directory then starts.
    #[cfg(unix)]
    #[test]
    fn clean_shutdown_after_a_terminal_releases_the_journal_lock() {
        let fake = sandbox_runtime::FakeRuntime::new();
        let observed = fake.clone();
        let TerminalDaemon {
            dir,
            binding,
            shutdown,
            client,
            mut wire,
            ..
        } = terminal_daemon(fake);
        let fence = json!({"sessionId":"term-live", "operationId":"termop-live",
            "hostId":"host-1", "epoch":3,
            "target":{"kind":"sandbox", "sandboxId":"sbx-term", "generation":1}});
        wire.send(Message::Text(
            json!({"type":"terminal.open", "requestId":"open-live", "fence":fence,
                "rows":24, "cols":80})
            .to_string()
            .into(),
        ))
        .unwrap();
        let ready = loop {
            let Message::Text(text) = wire.read().expect("terminal open answered") else {
                continue;
            };
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            if matches!(
                value["type"].as_str(),
                Some("terminal.ready" | "terminal.exit")
            ) {
                break value;
            }
        };
        assert_eq!(ready["type"], "terminal.ready", "{ready}");
        shutdown.request();
        let _ = wire.close(None);
        drop(wire);
        client.join().unwrap().expect("clean shutdown");
        // The shutdown closed the PTY; the surviving handle still sees it.
        let control = observed
            .pty_control("sbx-term", "term-live")
            .expect("the terminal was opened on the runtime");
        assert!(control.terminated(), "shutdown closes every PTY");
        // The lock is free once the daemon returned. The probe retries for at
        // most 1 s only because another test thread of this binary may fork
        // while the journal file is open: until that child execs (its copy
        // is close-on-exec) it shares the open file description and so the
        // lock. A daemon that kept the lock still fails here.
        let lock = std::fs::OpenOptions::new()
            .write(true)
            .open(dir.path().join("LOCK"))
            .unwrap();
        let probe_until = std::time::Instant::now() + Duration::from_secs(1);
        let mut locked = lock.try_lock().is_ok();
        while !locked && std::time::Instant::now() < probe_until {
            std::thread::sleep(Duration::from_millis(20));
            locked = lock.try_lock().is_ok();
        }
        assert!(
            locked,
            "the journal lock outlived a clean in-process shutdown"
        );
        drop(lock);
        let reopened = crate::sandbox_relay::journal::HostJournal::open(dir.path(), &binding)
            .expect("a second daemon instance takes the journal");
        assert!(reopened.lease("sbx-term").is_some());
        drop(observed);
    }

    #[test]
    fn command_timeouts_use_current_semantics_before_journal_intent() {
        let mut d: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":"timer", "sandboxId":"sbx", "kind":"command.run", "generation":1, "attempt":1, "idempotencyKey":"timer", "argv":["true"], "resultVersion":1, "processId":"proc-timer"})).unwrap();
        for timeout in [None, Some(0), Some(1), Some(1_800_000), Some(1_800_001)] {
            d.timeout_ms = timeout;
            assert!(fs_process_fields_allowed(&d));
        }
    }

    #[test]
    fn process_identity_fields_are_bounded_and_kind_bound() {
        let mut d: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":"c", "sandboxId":"sbx", "kind":"command.run", "generation":1, "attempt":1, "idempotencyKey":"c", "resultVersion":1})).unwrap();
        assert!(
            !fs_process_fields_allowed(&d),
            "a command without its process identity has no reply shape"
        );
        d.process_id = Some("proc-1".into());
        assert!(fs_process_fields_allowed(&d));
        for bad in ["", "has space", &"x".repeat(65)] {
            d.process_id = Some(bad.to_string());
            assert!(!fs_process_fields_allowed(&d), "{bad:?}");
        }
        d.process_id = Some("proc-1".into());
        d.kind = "file.stat".into();
        assert!(
            !fs_process_fields_allowed(&d),
            "only command.run carries identity"
        );
        assert!(sandbox_protocol::known_protocol_version("1.0"));
        for version in ["10.0", "10.5", "10.6", "10.7", "11.1"] {
            assert!(!sandbox_protocol::known_protocol_version(version));
        }
    }

    #[test]
    fn fs_process_result_and_page_fields_are_bounded_and_kind_bound() {
        let base = json!({"sandboxOwnerId":"owner", "operationId":"c", "sandboxId":"sbx", "kind":"file.list", "generation":1, "attempt":1, "idempotencyKey":"c", "resultVersion":1});
        let continuation = json!({"lastKey":"x", "root":"/", "depth":1, "limit":1, "generation":1, "kind":"LIST_DIR"});
        for (key, value) in [
            ("resultVersion", json!(1)),
            ("limit", json!(1)),
            ("continuation", continuation.clone()),
        ] {
            let mut value_base = base.clone();
            value_base[key] = value;
            let d: OperationDispatch = serde_json::from_value(value_base).unwrap();
            assert!(fs_process_fields_allowed(&d), "1.0 accepts {key}");
        }
        for limit in [0, 101] {
            let mut value = base.clone();
            value["limit"] = json!(limit);
            let d = serde_json::from_value(value).unwrap();
            assert!(!fs_process_fields_allowed(&d));
        }
        for kind in [
            "file.stat",
            "file.mkdir",
            "file.remove",
            "file.move",
            "command.run",
            "process.signal",
        ] {
            for (key, value) in [("limit", json!(1)), ("continuation", continuation.clone())] {
                let mut input = base.clone();
                input["kind"] = json!(kind);
                input[key] = value;
                let d = serde_json::from_value(input).unwrap();
                assert!(
                    !fs_process_fields_allowed(&d),
                    "{kind} must not page via {key}"
                );
            }
        }
        for (kind, cursor_kind) in [
            ("file.list", "LIST_PROCESSES"),
            ("process.list", "LIST_DIR"),
        ] {
            let mut value = base.clone();
            value["kind"] = json!(kind);
            value["continuation"] = continuation.clone();
            value["continuation"]["kind"] = json!(cursor_kind);
            let d = serde_json::from_value(value).unwrap();
            assert!(
                !fs_process_fields_allowed(&d),
                "continuation kind must match"
            );
        }
        let mut invalid = base.clone();
        invalid["continuation"] = continuation;
        invalid["continuation"]["depth"] = json!(0);
        assert!(!fs_process_fields_allowed(
            &serde_json::from_value(invalid).unwrap()
        ));
        for (kind, version, process_id, allowed) in [
            ("command.run", Some(1), None, false),
            ("command.run", Some(1), Some("proc"), true),
            ("file.list", Some(2), None, false),
            ("sandbox.stop", Some(1), None, false),
            ("sandbox.stop", None, None, true),
            ("file.list", None, None, false),
            ("file.stat", None, None, false),
            ("file.mkdir", None, None, false),
            ("file.remove", None, None, false),
            ("file.move", None, None, false),
            ("process.list", None, None, false),
            ("command.run", None, Some("proc"), false),
        ] {
            let mut value = base.clone();
            value["kind"] = json!(kind);
            value["resultVersion"] = json!(version);
            if let Some(id) = process_id {
                value["processId"] = json!(id);
            }
            let d = serde_json::from_value(value).unwrap();
            assert_eq!(fs_process_fields_allowed(&d), allowed);
        }
    }

    #[test]
    fn certificate_failure_keeps_hint_and_retries_only_after_first_session() {
        for reconnect in [false, true] {
            let error = tungstenite::Error::Tls(tungstenite::error::TlsError::Rustls(Box::new(
                rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
            )));
            let error = relay_dial_error(error, "wss://example.test/relay", reconnect);
            assert_eq!(
                error.downcast_ref::<RetryableSession>().is_some(),
                reconnect
            );
            let message = format!("{error:#}");
            assert!(message.contains("--ca-file"), "{message}");
            assert!(message.contains("wss://example.test"), "{message}");
        }
    }

    #[cfg(unix)]
    pub(super) struct RelayHandshake;
    #[cfg(unix)]
    impl tungstenite::handshake::server::Callback for RelayHandshake {
        fn on_request(
            self,
            _: &tungstenite::handshake::server::Request,
            mut response: tungstenite::handshake::server::Response,
        ) -> std::result::Result<
            tungstenite::handshake::server::Response,
            tungstenite::handshake::server::ErrorResponse,
        > {
            response.headers_mut().insert(
                "Sec-WebSocket-Protocol",
                SANDBOX_RELAY_SUBPROTOCOL.parse().expect("header"),
            );
            Ok(response)
        }
    }
    /// C55-L11: a server that accepts TCP but never answers the upgrade
    /// (plain or TLS) cannot hold the daemon: the handshake ends at its
    /// timeout, and a shutdown request ends it within a poll slice. Through
    /// `run_connect`, a shutdown during a stalled first handshake returns
    /// cleanly, well inside the 60 s forced-shutdown bound.
    #[cfg(unix)]
    #[test]
    fn c55_l11_stalled_relay_handshake_is_bounded_and_shutdown_aware() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        // Accept and hold every connection without ever replying.
        let held = Arc::new(std::sync::Mutex::new(Vec::new()));
        let holder = held.clone();
        thread::spawn(move || {
            for tcp in listener.incoming().flatten() {
                holder.lock().unwrap().push(tcp);
            }
        });
        let config = tungstenite::protocol::WebSocketConfig::default();
        for scheme in ["ws", "wss"] {
            let request = format!("{scheme}://{address}/ws/sandbox-host")
                .into_client_request()
                .unwrap();
            let started = Instant::now();
            let Err(error) = connect_relay_socket(
                request.clone(),
                config,
                &ShutdownSignal::default(),
                Duration::from_millis(400),
            ) else {
                panic!("{scheme}: a stalled handshake must fail");
            };
            let elapsed = started.elapsed();
            assert!(
                matches!(&*error, tungstenite::Error::Io(io) if io.kind() == ErrorKind::TimedOut),
                "{scheme}: {error}"
            );
            assert!(error.to_string().contains("handshake timed out"), "{error}");
            assert!(
                elapsed >= Duration::from_millis(400) && elapsed < Duration::from_secs(3),
                "{scheme}: {elapsed:?}"
            );
            let shutdown = ShutdownSignal::default();
            let signal = shutdown.clone();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(200));
                signal.request();
            });
            let started = Instant::now();
            let Err(error) =
                connect_relay_socket(request, config, &shutdown, Duration::from_secs(30))
            else {
                panic!("{scheme}: shutdown must end the handshake");
            };
            assert!(error.to_string().contains("daemon shutdown"), "{error}");
            assert!(started.elapsed() < Duration::from_secs(2), "{scheme}");
        }
        let shutdown = ShutdownSignal::default();
        let signal = shutdown.clone();
        let state_dir = tempfile::tempdir().unwrap();
        let options = ConnectOptions {
            host_terminal: None,
            server_url: format!("ws://{address}"),
            host_token: "test-only-token".into(),
            host_id: "host-1".into(),
            label: "test".into(),
            runtime: HostRuntimeKind::Fake,
            incus_project: None,
            state_dir: Some(state_dir.path().into()),
            heartbeat: Duration::from_millis(20),
            sandbox_memory_mib: None,
            max_sandbox_cpu_count: None,
            sandbox_vcpu_budget: Some(4),
            max_concurrent_commands: 16,
            shutdown,
        };
        let (done_tx, done_rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = done_tx.send(
                crate::sandbox_relay::test_support::run_fixture_connect(&options)
                    .map_err(|e| format!("{e:#}")),
            );
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while held.lock().unwrap().is_empty() {
            assert!(Instant::now() < deadline, "the daemon never connected");
            thread::sleep(Duration::from_millis(10));
        }
        let requested = Instant::now();
        signal.request();
        let result = done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the daemon returns promptly after shutdown");
        assert!(requested.elapsed() < Duration::from_secs(3));
        assert!(result.is_ok(), "{result:?}");
    }

    /// C55-L11 (G8-R1): a peer that trickles its reply every 50 ms (never a
    /// gap a read timeout could see) cannot hold the handshake. For wss it
    /// sends one byte at a time of a 16 KiB TLS record; for ws, 200-byte
    /// pieces of an upgrade response header that never ends (tungstenite's
    /// own attack check would end a one-byte ws trickle after 64 reads, so
    /// that would not test the bound). The deadline ends it on time, and a
    /// shutdown request mid-handshake ends it within a poll slice.
    #[cfg(unix)]
    #[test]
    fn c55_l11_trickling_relay_handshake_is_bounded_and_shutdown_aware() {
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicUsize, Ordering};
        fn trickle_server(tls: bool) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let sent = Arc::new(AtomicUsize::new(0));
            let counter = sent.clone();
            thread::spawn(move || {
                for mut tcp in listener.incoming().flatten() {
                    let counter = counter.clone();
                    thread::spawn(move || {
                        let (head, piece): (&[u8], &[u8]) = if tls {
                            // A TLS handshake record header announcing 16 KiB.
                            (&[0x16, 0x03, 0x03, 0x40, 0x00], &[0])
                        } else {
                            (
                                b"HTTP/1.1 101 Switching Protocols\r\nX-Trickle: ",
                                &[b'a'; 200],
                            )
                        };
                        if tcp.write_all(head).is_err() {
                            return;
                        }
                        // Self-limited so a broken client cannot leak this.
                        let until = Instant::now() + Duration::from_secs(10);
                        while Instant::now() < until && tcp.write_all(piece).is_ok() {
                            counter.fetch_add(1, Ordering::Relaxed);
                            thread::sleep(Duration::from_millis(50));
                        }
                    });
                }
            });
            (address, sent)
        }
        let config = tungstenite::protocol::WebSocketConfig::default();
        for (scheme, tls) in [("ws", false), ("wss", true)] {
            let (address, sent) = trickle_server(tls);
            let request = format!("{scheme}://{address}/ws/sandbox-host")
                .into_client_request()
                .unwrap();
            let started = Instant::now();
            let Err(error) = connect_relay_socket(
                request.clone(),
                config,
                &ShutdownSignal::default(),
                Duration::from_millis(400),
            ) else {
                panic!("{scheme}: a trickling handshake must fail");
            };
            let elapsed = started.elapsed();
            assert!(
                matches!(&*error, tungstenite::Error::Io(io) if io.kind() == ErrorKind::TimedOut),
                "{scheme}: {error}"
            );
            assert!(error.to_string().contains("handshake timed out"), "{error}");
            assert!(
                elapsed >= Duration::from_millis(400) && elapsed < Duration::from_secs(3),
                "{scheme}: deadline 400 ms, returned after {elapsed:?}"
            );
            let shutdown = ShutdownSignal::default();
            let signal = shutdown.clone();
            let before = sent.load(Ordering::Relaxed);
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(300));
                signal.request();
            });
            let started = Instant::now();
            let Err(error) =
                connect_relay_socket(request, config, &shutdown, Duration::from_secs(30))
            else {
                panic!("{scheme}: shutdown must end the trickling handshake");
            };
            let elapsed = started.elapsed();
            assert!(error.to_string().contains("daemon shutdown"), "{error}");
            assert!(
                elapsed < Duration::from_secs(3),
                "{scheme}: shutdown at 300 ms, returned after {elapsed:?}"
            );
            // The peer really was feeding this handshake, not sitting silent.
            assert!(
                sent.load(Ordering::Relaxed) > before,
                "{scheme}: the peer never trickled"
            );
        }
    }

    /// C55-L11 (G8-R2): a TCP connect that never completes observes the
    /// deadline and a shutdown request too. A listener whose accept queue is
    /// full drops new SYNs, so the next connect hangs the way a blackholed
    /// relay address does.
    #[cfg(target_os = "linux")]
    #[test]
    fn c55_l11_hanging_tcp_connect_is_bounded_and_shutdown_aware() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        // Fill the accept queue (never accepted) until a connect hangs.
        let mut queued = Vec::new();
        loop {
            assert!(queued.len() < 4096, "the accept queue never filled");
            match std::net::TcpStream::connect_timeout(&address, Duration::from_millis(200)) {
                Ok(tcp) => queued.push(tcp),
                Err(error) if error.kind() == ErrorKind::TimedOut => break,
                Err(error) => panic!("unexpected connect error: {error}"),
            }
        }
        let request = format!("ws://{address}/ws/sandbox-host")
            .into_client_request()
            .unwrap();
        let config = tungstenite::protocol::WebSocketConfig::default();
        let started = Instant::now();
        let Err(error) = connect_relay_socket(
            request.clone(),
            config,
            &ShutdownSignal::default(),
            Duration::from_millis(400),
        ) else {
            panic!("a hanging connect must fail");
        };
        let elapsed = started.elapsed();
        assert!(error.to_string().contains("connect timed out"), "{error}");
        assert!(
            elapsed >= Duration::from_millis(400) && elapsed < Duration::from_secs(3),
            "deadline 400 ms, returned after {elapsed:?}"
        );
        let shutdown = ShutdownSignal::default();
        let signal = shutdown.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(300));
            signal.request();
        });
        let started = Instant::now();
        let Err(error) = connect_relay_socket(request, config, &shutdown, Duration::from_secs(30))
        else {
            panic!("shutdown must end a hanging connect");
        };
        let elapsed = started.elapsed();
        assert!(
            error
                .to_string()
                .contains("connect stopped by daemon shutdown"),
            "{error}"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "shutdown at 300 ms, returned after {elapsed:?}"
        );
        drop(queued);
    }

    /// C55-L11: a dial that gave up at the deadline is a timeout even when
    /// its empty result reaches the waiter before the waiter's own poll
    /// slice ends (seen under load: the result arrived 1.8 ms after the
    /// deadline and was reported as "Unable to connect").
    #[test]
    fn c55_l11_a_dial_ending_at_the_deadline_is_a_timeout_not_unreachable() {
        let uri = "ws://127.0.0.1:9/ws/sandbox-host";
        let quiet = ShutdownSignal::default();
        let passed = Instant::now() - Duration::from_millis(2);
        let error = dial_failure(uri, &quiet, passed).to_string();
        assert!(error.contains("connect timed out"), "{error}");
        let stopping = ShutdownSignal::default();
        stopping.request();
        let error =
            dial_failure(uri, &stopping, Instant::now() + Duration::from_secs(30)).to_string();
        assert!(
            error.contains("connect stopped by daemon shutdown"),
            "{error}"
        );
        // A dial that failed well before the deadline (every address
        // refused) really found the relay unreachable.
        let error = dial_failure(uri, &quiet, Instant::now() + Duration::from_secs(30)).to_string();
        assert!(error.contains("Unable to connect"), "{error}");
    }

    /// C55-L11 (G8-R1): the watchdog never touches a handshake that
    /// finished. A relay session opened with a 300 ms bound still carries
    /// frames both ways well after that bound has passed, and disarming
    /// joins the watchdog at once.
    #[cfg(unix)]
    #[test]
    fn c55_l11_handshake_watchdog_leaves_a_completed_session_alone() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let mut socket = tungstenite::accept(tcp).unwrap();
            let message = socket.read().unwrap();
            socket.send(message).unwrap();
            socket
        });
        let request = format!("ws://{address}/ws/sandbox-host")
            .into_client_request()
            .unwrap();
        let (mut socket, _) = connect_relay_socket(
            request,
            tungstenite::protocol::WebSocketConfig::default(),
            &ShutdownSignal::default(),
            Duration::from_millis(300),
        )
        .unwrap();
        thread::sleep(Duration::from_millis(700));
        socket.send(Message::text("after the bound")).unwrap();
        assert_eq!(
            socket.read().unwrap(),
            Message::text("after the bound"),
            "the session survives its handshake deadline"
        );
        drop(server.join().unwrap());

        // Disarm cancels and joins at once, and reports that it never fired;
        // a disarmed watchdog leaves the socket open past its deadline.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        let watchdog = HandshakeWatchdog::arm(
            &tcp,
            &ShutdownSignal::default(),
            Instant::now() + Duration::from_millis(200),
        )
        .unwrap();
        let started = Instant::now();
        assert_eq!(watchdog.disarm(), None);
        assert!(started.elapsed() < Duration::from_secs(1));
        thread::sleep(Duration::from_millis(400));
        (&tcp).write_all(b"x").unwrap();
        let mut byte = [0u8; 1];
        std::io::Read::read_exact(&mut peer, &mut byte).unwrap();
        assert_eq!(&byte, b"x");
        // An armed one fires at its deadline and shuts the socket down.
        let watchdog = HandshakeWatchdog::arm(
            &tcp,
            &ShutdownSignal::default(),
            Instant::now() + Duration::from_millis(100),
        )
        .unwrap();
        let mut read = [0u8; 1];
        assert_eq!(std::io::Read::read(&mut &tcp, &mut read).unwrap(), 0);
        assert_eq!(watchdog.disarm(), Some("timed out"));
    }

    /// C55 (C52-TB-3): a shutdown request ends a live relay session with a
    /// normal close (after the terminal drain), the daemon returns within its
    /// bound, and it never reconnects or waits on accepted leases.
    #[cfg(unix)]
    #[test]
    fn c55_shutdown_request_closes_normally_and_never_reconnects() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let state_dir = std::env::temp_dir().join(format!(
            "wssp-c55-shutdown-{}-{}",
            std::process::id(),
            address.port()
        ));
        let shutdown = ShutdownSignal::default();
        let signal = shutdown.clone();
        let (done_tx, done_rx) = mpsc::channel();
        thread::spawn(move || {
            let result = crate::sandbox_relay::test_support::run_fixture_connect(&ConnectOptions {
                host_terminal: None,
                server_url: format!("ws://{address}"),
                host_token: "test-only-token".into(),
                host_id: "host-1".into(),
                label: "test".into(),
                runtime: HostRuntimeKind::Fake,
                incus_project: None,
                state_dir: Some(state_dir),
                heartbeat: Duration::from_millis(20),
                sandbox_memory_mib: None,
                max_sandbox_cpu_count: None,
                sandbox_vcpu_budget: Some(4),
                max_concurrent_commands: 16,
                shutdown: signal,
            });
            let _ = done_tx.send(result.is_ok());
        });
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake).unwrap();
        let _hello = wire.read().unwrap();
        let ack: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
        ))
        .unwrap();
        crate::sandbox_relay::test_support::send_ready_hello_value(&mut wire, ack, "host-1");
        crate::sandbox_relay::test_support::ack_registration(&mut wire);
        loop {
            let frame = wire.read().unwrap();
            if frame.to_text().is_ok_and(|t| t.contains("\"heartbeat\"")) {
                break;
            }
        }
        let requested = Instant::now();
        shutdown.request();
        let close = loop {
            match wire.read() {
                Ok(Message::Close(frame)) => break frame,
                Ok(_) => continue,
                Err(error) => panic!("no normal close before the socket ended: {error}"),
            }
        };
        assert_eq!(
            close.map(|frame| frame.code),
            Some(tungstenite::protocol::frame::coding::CloseCode::Normal)
        );
        let clean = done_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("daemon returned within its shutdown bound");
        assert!(clean, "a requested shutdown is a clean exit");
        assert!(requested.elapsed() < Duration::from_secs(30));
        // No reconnect attempt follows.
        listener.set_nonblocking(true).unwrap();
        thread::sleep(Duration::from_millis(500));
        assert!(
            listener.accept().is_err(),
            "a shutdown daemon never reconnects"
        );
    }

    #[test]
    fn advertised_capabilities_mirror_the_runtime_egress_proof() {
        for runtime_kind in [
            sandbox_protocol::RuntimeKind::Fake,
            sandbox_protocol::RuntimeKind::IncusKvm,
            sandbox_protocol::RuntimeKind::Unsupported,
        ] {
            let capabilities = daemon_capabilities(runtime_kind.clone(), false);
            assert!(!capabilities.egress_policy);
            let capabilities = daemon_capabilities(runtime_kind, true);
            assert!(capabilities.egress_policy);
            assert_eq!(
                capabilities.protocol_version,
                SANDBOX_RELAY_PROTOCOL_VERSION
            );
        }
    }

    #[test]
    fn fake_and_missing_runtimes_never_prove_egress_enforcement() {
        let fake = sandbox_runtime::FakeRuntime::new();
        assert!(!fake.egress_enforcement_capability().unwrap_or(false));
    }

    #[test]
    fn fake_runtime_knobs_parse_and_only_enable_on_the_fake_runtime() {
        let knobs = |pairs: &[(&str, &str)]| {
            let pairs: Vec<(String, String)> = pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            FakeRuntimeKnobs::from_lookup(move |key| {
                pairs
                    .iter()
                    .find(|(k, _)| k == key)
                    .map(|(_, v)| std::ffi::OsString::from(v))
            })
        };
        let none = knobs(&[]).unwrap();
        assert_eq!(none, FakeRuntimeKnobs::default());
        none.refuse_for_real_runtime().unwrap();
        assert!(!none.build().egress_enforcement_capability().unwrap());
        for off in ["", "0", "false"] {
            assert!(
                !knobs(&[(FAKE_ENFORCE_EGRESS_ENV, off)])
                    .unwrap()
                    .enforce_egress
            );
        }
        assert!(knobs(&[(FAKE_ENFORCE_EGRESS_ENV, "yes")]).is_err());

        let on = knobs(&[
            (FAKE_ENFORCE_EGRESS_ENV, "1"),
            (FAKE_FAIL_CREATE_FILE_ENV, "/nonexistent/wssp-fail-create"),
        ])
        .unwrap();
        assert!(on.enforce_egress);
        assert_eq!(
            on.fail_create_file.as_deref(),
            Some(std::path::Path::new("/nonexistent/wssp-fail-create"))
        );
        // A real runtime refuses either knob instead of ignoring it.
        let message = on.refuse_for_real_runtime().unwrap_err().to_string();
        assert!(
            message.contains("apply only to `--runtime fake`"),
            "{message}"
        );
        assert!(
            knobs(&[(FAKE_FAIL_CREATE_FILE_ENV, "/x")])
                .unwrap()
                .refuse_for_real_runtime()
                .is_err()
        );
        let fake = on.build();
        assert!(fake.egress_enforcement_capability().unwrap());
        assert_eq!(fake.egress_enforcement_unavailable_reason(), None);
    }

    /// E-06: the operator-facing warning logged before an
    /// `egressPolicy: false` hello names the runtime's reason.
    #[test]
    fn egress_unavailable_warning_names_the_runtime_reason() {
        let fake = sandbox_runtime::FakeRuntime::new();
        let message = egress_unavailable_message(&fake);
        assert!(
            message
                .starts_with("egress enforcement unavailable; this host cannot create sandboxes: ")
                && message.contains("the fake runtime never enforces egress policies")
                && message.contains("incus 6.14 or later"),
            "{message}"
        );
        let unsupported = sandbox_runtime::UnsupportedRuntime;
        assert!(
            egress_unavailable_message(&unsupported)
                .ends_with("the runtime cannot prove egress enforcement"),
        );
    }

    /// One daemon per Incus server: the test-only shared-Incus override is
    /// off unless set, accepted only as `1` with a loopback control plane,
    /// and refuses (never ignores) every other combination.
    #[cfg(all(target_os = "linux", debug_assertions))]
    #[test]
    fn shared_incus_override_is_accepted_only_for_a_loopback_control_plane() {
        let on = || Some(std::ffi::OsString::from("1"));
        for server in [
            "http://127.0.0.1:4310",
            "http://127.9.9.9",
            "https://localhost:8443",
            "http://LOCALHOST",
            "http://[::1]:3000",
        ] {
            assert!(shared_incus_override(on(), server).unwrap(), "{server}");
        }
        assert!(!shared_incus_override(None, "https://wssp.example.com").unwrap());
        assert!(!shared_incus_override(None, "http://127.0.0.1:4310").unwrap());
        for server in [
            "https://wssp.example.com",
            "https://10.0.0.5",
            "https://localhost.example.com",
            "https://[2001:db8::1]",
            "not a url",
        ] {
            let err = shared_incus_override(on(), server).expect_err(server);
            assert!(
                format!("{err:#}").contains(SHARED_INCUS_TEST_ENV),
                "{err:#}"
            );
        }
        for value in ["0", "true", "yes", ""] {
            let err =
                shared_incus_override(Some(value.into()), "http://127.0.0.1").expect_err(value);
            assert!(format!("{err:#}").contains("accepts only `1`"), "{err:#}");
        }
    }

    /// Release builds compile the shared-Incus override out: it is never
    /// enabled, whatever the environment (`cli-ci.yml` also greps the
    /// release binary for the variable name).
    #[cfg(all(target_os = "linux", not(debug_assertions)))]
    #[test]
    fn shared_incus_override_is_compiled_out_of_release_builds() {
        for server in ["http://127.0.0.1:4310", "https://wssp.example.com"] {
            assert!(!shared_incus_override_enabled(server).unwrap());
        }
        assert_eq!(SHARED_INCUS_TEST_ENV, "WSSP_TEST_SHARED_INCUS");
    }

    /// E-11: `wssp host run --runtime incus` refuses before the relay
    /// starts when bridge netfilter is missing, naming the exact commands;
    /// the bridge check runs before any daemon-lock provisioning.
    #[cfg(target_os = "linux")]
    #[test]
    fn incus_preflight_refuses_without_bridge_netfilter() {
        let missing =
            std::env::temp_dir().join(format!("wssp-no-bridge-{}-{}", std::process::id(), line!()));
        let err = incus_host_preflight(&missing).expect_err("refused");
        let text = format!("{err:#}");
        assert!(
            text.contains("`sudo modprobe br_netfilter`")
                && text.contains("/etc/modules-load.d/wssp-br_netfilter.conf")
                && !text.contains("daemon lock directory"),
            "{text}"
        );
    }

    /// E2E-P2-1 / E2E-P3-1: the connect-time Incus preflight provisions
    /// and validates the directory named by `WSSP_INCUS_DAEMON_LOCK_DIR`,
    /// never the fixed `/var/lib` path. A fresh override is created 2770
    /// and passes; a symlink is refused and its target left alone; a
    /// pre-existing caller-owned 0755 directory is refused by name and NOT
    /// chmodded. The variable is process-wide, so each case runs in a child
    /// test process that has it set.
    #[cfg(target_os = "linux")]
    #[test]
    fn connect_preflight_honours_the_daemon_lock_dir_override() {
        use std::os::unix::fs::PermissionsExt;
        const CASE: &str = "WSSP_E2E_P2_1_CASE";
        let fixed = std::path::Path::new("/var/lib/wssp/incus-daemon-locks");
        if let Some(case) = std::env::var_os(CASE) {
            let lock_dir = std::path::PathBuf::from(
                std::env::var_os("WSSP_INCUS_DAEMON_LOCK_DIR").expect("override set"),
            );
            let root = lock_dir.parent().expect("parent").to_path_buf();
            let proc_dir = root.join("proc-bridge");
            std::fs::create_dir_all(&proc_dir).unwrap();
            std::fs::write(proc_dir.join("bridge-nf-call-ip6tables"), "1\n").unwrap();
            let fixed_before = std::fs::symlink_metadata(fixed).is_ok();
            let result = incus_host_preflight(&proc_dir);
            assert_eq!(std::fs::symlink_metadata(fixed).is_ok(), fixed_before);
            let mode = |path: &std::path::Path| {
                std::fs::symlink_metadata(path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777
            };
            match case.to_str() {
                Some("fresh") => {
                    result.expect("a fresh override is provisioned");
                    assert_eq!(mode(&lock_dir), 0o2770);
                }
                Some("symlink") => {
                    let text = format!("{:#}", result.expect_err("symlink refused"));
                    assert!(text.contains("is not a real directory"), "{text}");
                    assert!(text.contains(&lock_dir.display().to_string()), "{text}");
                    assert_eq!(mode(&root.join("target")), 0o700);
                }
                Some("existing") => {
                    let text = format!("{:#}", result.expect_err("0755 refused"));
                    assert!(text.contains("must be mode 2770"), "{text}");
                    assert!(text.contains(&lock_dir.display().to_string()), "{text}");
                    assert_eq!(mode(&lock_dir), 0o755, "pre-existing mode unchanged");
                }
                other => panic!("unknown case {other:?}"),
            }
            return;
        }
        for case in ["fresh", "symlink", "existing"] {
            let root = tempfile::tempdir().unwrap();
            let lock_dir = root.path().join("locks");
            match case {
                "symlink" => {
                    let target = root.path().join("target");
                    std::fs::create_dir(&target).unwrap();
                    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700))
                        .unwrap();
                    std::os::unix::fs::symlink(&target, &lock_dir).unwrap();
                }
                "existing" => {
                    std::fs::create_dir(&lock_dir).unwrap();
                    std::fs::set_permissions(&lock_dir, std::fs::Permissions::from_mode(0o755))
                        .unwrap();
                }
                _ => {}
            }
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "sandbox_relay::connect::tests::connect_preflight_honours_the_daemon_lock_dir_override",
                    "--exact",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CASE, case)
                .env("WSSP_INCUS_DAEMON_LOCK_DIR", &lock_dir)
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success() && stdout.contains("1 passed"),
                "{case} child failed: {:?}\nstdout:\n{stdout}\nstderr:\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn snapshot_restore_fork_fail_closed() {
        for kind in ["snapshot.create", "snapshot.restore", "sandbox.fork"] {
            let err = reject_unsupported_dispatch(kind).expect("rejected");
            assert_eq!(err.code, SandboxErrorCode::UnsupportedCapability);
            assert!(err.message.contains(kind));
        }
    }

    #[test]
    fn availability_is_exact_and_missing_is_explicit() {
        let runtime = sandbox_runtime::FakeRuntime::default();
        let artifact = format!("sha256:{}", "c".repeat(64));
        runtime.register_image("base", &artifact, "x86_64");
        let mut binding = sandbox_protocol::AvailabilityBinding {
            revision_id: "r1".into(),
            artifact,
            manifest_hash: "b".repeat(64),
            architecture: "x86_64".into(),
        };
        assert_eq!(
            availability_status(&runtime, &binding),
            sandbox_protocol::AvailabilityStatus::Present
        );
        binding.architecture = "aarch64".into();
        assert_eq!(
            availability_status(&runtime, &binding),
            sandbox_protocol::AvailabilityStatus::Rejected
        );
        binding.artifact = format!("sha256:{}", "e".repeat(64));
        assert_eq!(
            availability_status(&runtime, &binding),
            sandbox_protocol::AvailabilityStatus::Missing
        );
    }

    #[test]
    fn allowed_command_kind_is_not_rejected() {
        assert!(reject_unsupported_dispatch("command.run").is_none());
        assert!(reject_unsupported_dispatch("file.stat").is_none());
        assert!(reject_unsupported_dispatch("sandbox.create").is_none());
    }

    #[test]
    fn malicious_instance_names_are_rejected_before_runtime() {
        for (sandbox_id, supplied) in [
            ("../etc/passwd", None),
            ("sbx-1", Some("ubuntu")),
            ("sbx-1", Some("-wssp-sbx-sbx-1")),
            ("sbx-1", Some("wssp-sbx-foo/bar")),
            ("sbx-1", Some("wssp-sbx-foo%2Fbar")),
            ("foo%00", None),
        ] {
            let err = resolve_instance_name(sandbox_id, supplied).expect_err("rejected");
            assert_eq!(err.code, SandboxErrorCode::ProtocolError);
        }
        assert_eq!(
            resolve_instance_name("sbx-1", None).expect("derived"),
            "wssp-sbx-sbx-1"
        );
        assert_eq!(
            resolve_instance_name("sbx-1", Some("wssp-sbx-sbx-1")).expect("match"),
            "wssp-sbx-sbx-1"
        );
    }
    #[cfg(unix)]
    #[test]
    fn real_wire_rejects_stale_put_cancel_and_lifecycle_dispatch() {
        let shutdown = ShutdownSignal::default();
        let daemon_shutdown = shutdown.clone();
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        use sandbox_protocol::parse_daemon_control;
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let address = listener.local_addr().expect("address");
        let client = thread::spawn(move || {
            let state_dir = std::env::temp_dir().join(format!(
                "wssp-wire-{}-{}",
                std::process::id(),
                address.port()
            ));
            crate::sandbox_relay::test_support::run_fixture_connect(&ConnectOptions {
                host_terminal: None,
                server_url: format!("ws://{address}"),
                host_token: "test-only-token".into(),
                host_id: "host-1".into(),
                label: "test".into(),
                runtime: HostRuntimeKind::Fake,
                incus_project: None,
                state_dir: Some(state_dir),
                heartbeat: Duration::from_secs(30),
                sandbox_memory_mib: None,
                max_sandbox_cpu_count: None,
                sandbox_vcpu_budget: Some(4),
                max_concurrent_commands: 16,
                shutdown: daemon_shutdown,
            })
        });
        let (tcp, _) = listener.accept().expect("accept");
        tcp.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake).expect("handshake");
        assert!(
            matches!(parse_daemon_control(wire.read().expect("hello").to_text().expect("text")).expect("parse"), DaemonControlMessage::Hello { protocol_version, daemon, .. } if protocol_version == "1.0" && daemon.version.as_deref() == Some(env!("CARGO_PKG_VERSION")))
        );
        crate::sandbox_relay::test_support::send_sized_hello(
            &mut wire,
            &TransportBindingV11 {
                server: format!("ws://{address}/ws/sandbox-host"),
                host_owner_id: "owner-1".into(),
                host_id: "host-1".into(),
            },
        );
        crate::sandbox_relay::test_support::ack_registration(&mut wire);
        const FP: &str = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        fn dispatch(
            wire: &mut tungstenite::WebSocket<TcpStream>,
            id: &str,
            kind: &str,
            generation: u64,
            attempt: u64,
        ) {
            let mut payload = crate::sandbox_relay::test_support::current_control_fixture(
                json!({"sandboxOwnerId":"owner", "type":"operation.dispatch","operationId":id,"sandboxId":"sbx-1",
                "idempotencyKey":id,"bodyHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","kind":kind,"lease":sandbox_protocol::HostLease { revision: generation, ..sandbox_protocol::HostLease::for_test() },"generation":generation,"attempt":attempt,
                "path":"/tmp/probe","fileSize":7,"fileSha256":crate::sandbox_relay::journal::sha256_hex(b"CURRENT"),"argv":["true"],"templateDigest":FP,"incusFingerprint":FP,"architecture":"x86_64"}),
            );
            if matches!(kind, "sandbox.create" | "sandbox.reconnect") {
                payload["cpuCount"] = json!(1);
                payload["memoryMiB"] = json!(1024);
            }
            if matches!(
                kind,
                "sandbox.create" | "sandbox.reconnect" | "sandbox.kill" | "sandbox.stop"
            ) {
                payload["allocation"] =
                    serde_json::to_value(crate::sandbox_relay::test_support::allocation()).unwrap();
            }
            if sandbox_protocol::results::host::kind_from_dispatch(kind).is_some() {
                payload["resultVersion"] = json!(1);
            }
            if kind == "command.run" {
                payload["processId"] = json!(format!("proc-{id}"));
            }
            if sandbox_protocol::KEY_FREE_CLEANUP_KINDS.contains(&kind) {
                for key in ["path", "fileSize", "fileSha256", "argv"] {
                    payload.as_object_mut().unwrap().remove(key);
                }
            }
            wire.send(Message::Text(payload.to_string().into()))
                .expect("dispatch");
        }
        fn result(
            wire: &mut tungstenite::WebSocket<TcpStream>,
            id: &str,
            expected: OperationState,
        ) -> Option<SandboxErrorCode> {
            loop {
                let frame = wire.read().expect("result frame");
                match parse_daemon_control(frame.to_text().expect("text")).expect("parse") {
                    DaemonControlMessage::OperationProgress { .. }
                    | DaemonControlMessage::Heartbeat { .. }
                    | DaemonControlMessage::InventoryUpdate { .. }
                    | DaemonControlMessage::OperationReceipt { .. }
                    | DaemonControlMessage::ReconcileComplete { .. }
                    | DaemonControlMessage::FileChunkAck { .. } => continue,
                    DaemonControlMessage::OperationResult {
                        operation_id,
                        state,
                        error,
                        ..
                    } => {
                        assert_eq!(operation_id, id, "unexpected result from stale traffic");
                        assert_eq!(state, expected);
                        break error.and_then(|e| e.code.known());
                    }
                    // The 5 s egress lease renewal (§2.5) may interleave.
                    DaemonControlMessage::HostEgressState(_) => {}
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
        fn bytes(
            wire: &mut tungstenite::WebSocket<TcpStream>,
            generation: u64,
            attempt: u64,
            body: &[u8],
        ) {
            let frame = encode_binary_frame(
                &StreamBinaryMetadata {
                    r#type: StreamKind::End,
                    stream_id: "put".into(),
                    operation_id: "put".into(),
                    generation,
                    attempt,
                    offset: Some(0),
                    gap_start: None,
                    sequence: 0,
                    flags: Some(StreamChunkFlags {
                        file_upload: Some(true),
                        file_download: None,
                        stdin: None,
                        stdout: None,
                        stderr: None,
                    }),
                    final_chunk: Some(true),
                },
                body,
            )
            .expect("encode");
            wire.send(Message::Binary(frame.into())).expect("bytes");
        }
        dispatch(&mut wire, "create", "sandbox.create", 2, 1);
        result(&mut wire, "create", OperationState::Succeeded);
        // An unknown cancel must prevent both the later execution and its replay.
        wire.send(Message::Text(
            json!({"type":"operation.cancel","operationId":"early",
            "generation":2,"attempt":1,"reason":"cancelled"})
            .to_string()
            .into(),
        ))
        .expect("early cancel");
        for _ in 0..2 {
            dispatch(&mut wire, "early", "command.run", 2, 1);
            result(&mut wire, "early", OperationState::Failed);
        }
        dispatch(&mut wire, "put", "file.put", 2, 2);
        bytes(&mut wire, 1, 1, b"STALE_BYTES");
        wire.send(Message::Text(json!({"type":"operation.cancel","operationId":"put","generation":1,"attempt":1,"reason":"cancelled"}).to_string().into())).expect("stale cancel");
        dispatch(&mut wire, "stat-missing", "file.stat", 2, 1);
        // The strict session retains precise file/process errors.
        assert_eq!(
            result(&mut wire, "stat-missing", OperationState::Failed),
            Some(SandboxErrorCode::FsNotFound)
        );
        dispatch(&mut wire, "warm", "sandbox.reconnect", 2, 1);
        result(&mut wire, "warm", OperationState::Succeeded);
        bytes(&mut wire, 2, 2, b"CURRENT");
        result(&mut wire, "put", OperationState::Succeeded);
        dispatch(&mut wire, "get", "file.get", 2, 1);
        loop {
            match wire.read().expect("download") {
                Message::Binary(frame) => {
                    let (metadata, body) = parse_binary_frame(&frame).expect("binary");
                    assert_eq!((metadata.generation, metadata.attempt), (2, 1));
                    assert_eq!(body, b"CURRENT");
                    wire.send(Message::Text(json!({"type":"file.chunk.ack", "operationId": metadata.operation_id, "generation":metadata.generation, "attempt":metadata.attempt, "sequence":metadata.sequence, "offset":body.len()}).to_string().into())).unwrap();
                    break;
                }
                // The 5 s egress lease renewal (§2.5) may interleave here too
                // once the test has run that long (it does under load).
                Message::Text(text) => assert!(matches!(
                    parse_daemon_control(&text).expect("parse"),
                    DaemonControlMessage::OperationProgress { .. }
                        | DaemonControlMessage::Heartbeat { .. }
                        | DaemonControlMessage::InventoryUpdate { .. }
                        | DaemonControlMessage::OperationReceipt { .. }
                        | DaemonControlMessage::ReconcileComplete { .. }
                        | DaemonControlMessage::HostEgressState(_)
                )),
                other => panic!("unexpected {other:?}"),
            }
        }
        result(&mut wire, "get", OperationState::Succeeded);
        dispatch(&mut wire, "stop", "sandbox.stop", 3, 1);
        result(&mut wire, "stop", OperationState::Succeeded);
        dispatch(&mut wire, "stale-reconnect", "sandbox.reconnect", 1, 1);
        result(&mut wire, "stale-reconnect", OperationState::UnknownOutcome);
        dispatch(&mut wire, "stale-command", "command.run", 1, 1);
        result(&mut wire, "stale-command", OperationState::Failed);
        shutdown.request();
        client.join().expect("client thread").expect("connect loop");
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn stale_stdin_and_cancel_never_reach_runtime() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        use sandbox_runtime::*;
        use std::sync::Arc;
        #[derive(Default)]
        struct Calls {
            stdin: Vec<WriteStdinRequest>,
            cancel: Vec<String>,
            fail_stdin: bool,
        }
        struct Spy {
            fake: FakeRuntime,
            calls: Arc<Mutex<Calls>>,
        }
        macro_rules! delegate {
            (create_sandbox, $request:ty, $response:ty) => {
                fn create_sandbox_on_storage(
                    &self,
                    request: &$request,
                    root: &sandbox_runtime::RootDisk,
                ) -> $response {
                    self.fake.create_sandbox_on_storage(request, root)
                }
                fn default_storage_pool(&self) -> Result<String, sandbox_runtime::RuntimeError> {
                    self.fake.default_storage_pool()
                }
                fn initialize_storage_pool(
                    &self,
                    n: &str,
                    p: Option<&sandbox_runtime::StoragePoolIdentity>,
                ) -> Result<sandbox_runtime::StoragePoolIdentity, sandbox_runtime::RuntimeError> {
                    self.fake.initialize_storage_pool(n, p)
                }
                fn observe_storage_pool(
                    &self,
                    p: &sandbox_runtime::StoragePoolIdentity,
                ) -> Result<sandbox_runtime::StoragePoolObservation, sandbox_runtime::RuntimeError>
                {
                    self.fake.observe_storage_pool(p)
                }
                fn storage_root_census(
                    &self,
                    p: &sandbox_runtime::StoragePoolIdentity,
                ) -> Result<sandbox_runtime::StorageRootCensus, sandbox_runtime::RuntimeError> {
                    self.fake.storage_root_census(p)
                }
                fn storage_physical_usage(
                    &self,
                    p: &sandbox_runtime::StoragePoolIdentity,
                    roots: &[String],
                    c: u64,
                ) -> Result<sandbox_runtime::PhysicalUsage, sandbox_runtime::RuntimeError> {
                    self.fake.storage_physical_usage(p, roots, c)
                }
                fn prove_root_absent(
                    &self,
                    p: &sandbox_runtime::RootDisk,
                    n: &str,
                ) -> Result<sandbox_runtime::RootAbsenceProof, sandbox_runtime::RuntimeError> {
                    self.fake.prove_root_absent(p, n)
                }
            };
            (reconnect_sandbox, $request:ty, $response:ty) => {
                fn reconnect_sandbox_on_storage(
                    &self,
                    request: &$request,
                    root: &sandbox_runtime::RootDisk,
                ) -> $response {
                    self.fake.reconnect_sandbox_on_storage(request, root)
                }
            };
            (kill_sandbox, $request:ty, $response:ty) => {
                fn kill_sandbox_on_storage(
                    &self,
                    request: &$request,
                    root: &sandbox_runtime::RootDisk,
                ) -> $response {
                    self.fake.kill_sandbox_on_storage(request, root)
                }
            };
            ($method:ident, $request:ty, $response:ty) => {
                fn $method(&self, request: &$request) -> $response {
                    self.fake.$method(request)
                }
            };
        }
        impl SandboxRuntime for Spy {
            fn egress_guard_check(&self) -> Result<(), sandbox_runtime::RuntimeError> {
                self.fake.egress_guard_check()
            }
            fn with_cancellation(
                &self,
                _: Arc<sandbox_runtime::RuntimePermit>,
            ) -> Box<dyn SandboxRuntime> {
                Box::new(sandbox_runtime::FakeRuntime::new())
            }
            fn query_sandbox(
                &self,
                _: &str,
                _: Option<&str>,
                _template_fingerprint: Option<&str>,
            ) -> std::result::Result<
                Option<sandbox_protocol::SandboxLifecycleState>,
                sandbox_runtime::RuntimeError,
            > {
                Ok(None)
            }

            delegate!(
                create_sandbox,
                CreateSandboxRequest,
                sandbox_runtime::EffectOutcome<CreateSandboxResponse>
            );
            delegate!(
                kill_sandbox,
                KillSandboxRequest,
                sandbox_runtime::EffectOutcome<KillSandboxResponse>
            );
            delegate!(
                run_command,
                RunCommandRequest,
                sandbox_runtime::EffectOutcome<RunCommandResponse>
            );
            delegate!(read_file, ReadFileRequest, std::result::Result<ReadFileResponse, RuntimeError>);
            delegate!(
                write_file,
                WriteFileRequest,
                sandbox_runtime::EffectOutcome<WriteFileResponse>
            );
            delegate!(
                reconnect_sandbox,
                ReconnectSandboxRequest,
                sandbox_runtime::EffectOutcome<ReconnectSandboxResponse>
            );
            delegate!(
                stop_sandbox,
                StopSandboxRequest,
                sandbox_runtime::EffectOutcome<StopSandboxResponse>
            );
            delegate!(list_dir, ListDirRequest, std::result::Result<ListDirResponse, RuntimeError>);
            delegate!(stat_path, StatPathRequest, std::result::Result<EntryInfo, RuntimeError>);
            delegate!(
                mkdir,
                MkdirRequest,
                sandbox_runtime::EffectOutcome<MkdirResponse>
            );
            delegate!(
                remove_path,
                RemovePathRequest,
                sandbox_runtime::EffectOutcome<RemovePathResponse>
            );
            delegate!(
                move_path,
                MovePathRequest,
                sandbox_runtime::EffectOutcome<EntryInfo>
            );
            delegate!(list_processes, ListProcessesRequest, std::result::Result<ListProcessesResponse, RuntimeError>);
            delegate!(
                signal_process,
                SignalProcessRequest,
                sandbox_runtime::EffectOutcome<sandbox_runtime::SignalOutcome>
            );
            delegate!(
                create_snapshot,
                SnapshotRequest,
                sandbox_runtime::EffectOutcome<SnapshotResponse>
            );
            delegate!(
                restore_snapshot,
                SnapshotRequest,
                sandbox_runtime::EffectOutcome<SnapshotResponse>
            );
            delegate!(
                fork_sandbox,
                ForkSandboxRequest,
                sandbox_runtime::EffectOutcome<ForkSandboxResponse>
            );
            delegate!(
                probe_sandbox,
                ProbeSandboxRequest,
                std::result::Result<ProbeSandboxResponse, RuntimeError>
            );
            fn write_stdin(
                &self,
                request: &WriteStdinRequest,
            ) -> sandbox_runtime::EffectOutcome<()> {
                let mut calls = self.calls.lock().expect("lock");
                if calls.fail_stdin {
                    return Err(RuntimeError::new(
                        SandboxErrorCode::GuestOperationFailed,
                        "stdin write failed",
                    )
                    .into());
                }
                calls.stdin.push(request.clone());
                self.fake.write_stdin(request)
            }
            fn cancel_operation(&self, id: &str) -> sandbox_runtime::EffectOutcome<()> {
                self.calls.lock().expect("lock").cancel.push(id.into());
                self.fake.cancel_operation(id)
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let journal = crate::sandbox_relay::test_support::open_ready_journal(
            dir.path(),
            &TransportBindingV11 {
                server: "wss://test".into(),
                host_owner_id: "owner".into(),
                host_id: "host".into(),
            },
        )
        .unwrap();
        let calls = Arc::new(Mutex::new(Calls::default()));
        let runtime: Box<dyn SandboxRuntime> = Box::new(Spy {
            fake: FakeRuntime::new(),
            calls: calls.clone(),
        });
        let mut authority = HostAuthority::default();
        // Unknown stdin is still dropped. The server regression guarantees the
        // accepted frame is sent only after dispatch; that frame is then applied.
        apply_stdin_chunk(
            &journal,
            None,
            runtime.as_ref(),
            &authority,
            &chunk(2, 2, 0, b"EARLY", false),
        )
        .expect("unknown stdin dropped");
        assert!(calls.lock().expect("lock").stdin.is_empty());
        authority
            .accept_dispatch("cmd", "sbx-1", "command.run", 2, 2)
            .expect("admit");
        let mut puts = HashMap::new();
        fn frame(generation: u64, attempt: u64) -> Vec<u8> {
            chunk(generation, attempt, 0, b"input", true)
        }
        fn chunk(generation: u64, attempt: u64, sequence: u64, bytes: &[u8], eof: bool) -> Vec<u8> {
            encode_binary_frame(
                &StreamBinaryMetadata {
                    r#type: if eof {
                        StreamKind::End
                    } else {
                        StreamKind::Chunk
                    },
                    stream_id: "stdin".into(),
                    operation_id: "cmd".into(),
                    generation,
                    attempt,
                    offset: None,
                    gap_start: None,
                    sequence,
                    flags: Some(StreamChunkFlags {
                        stdin: Some(true),
                        stdout: None,
                        stderr: None,
                        file_upload: None,
                        file_download: None,
                    }),
                    final_chunk: Some(eof),
                },
                bytes,
            )
            .expect("frame")
        }
        for (generation, attempt) in [(1, 1), (2, 1), (3, 3)] {
            assert!(
                apply_stdin_chunk(
                    &journal,
                    None,
                    runtime.as_ref(),
                    &authority,
                    &frame(generation, attempt)
                )
                .expect("stdin")
            );
            apply_cancel(
                None,
                runtime.as_ref(),
                &mut authority,
                &mut puts,
                "cmd",
                generation,
                attempt,
            );
        }
        assert!(calls.lock().expect("lock").stdin.is_empty());
        assert!(calls.lock().expect("lock").cancel.is_empty());
        authority
            .accept_dispatch("warm", "sbx-1", "sandbox.reconnect", 2, 1)
            .expect("warm");
        // Q11 + Q1-expiry receiver: later B/EOF arrives before A, both replayed.
        let later = chunk(2, 2, 1, b"B", true);
        let earlier = chunk(2, 2, 0, b"A", false);
        apply_stdin_chunk(&journal, None, runtime.as_ref(), &authority, &later).expect("buffer B");
        apply_stdin_chunk(&journal, None, runtime.as_ref(), &authority, &later)
            .expect("duplicate B");
        assert!(calls.lock().expect("lock").stdin.is_empty());
        apply_stdin_chunk(&journal, None, runtime.as_ref(), &authority, &earlier)
            .expect("A then B");
        apply_stdin_chunk(&journal, None, runtime.as_ref(), &authority, &earlier)
            .expect("duplicate A");
        apply_stdin_chunk(&journal, None, runtime.as_ref(), &authority, &frame(2, 2))
            .expect("stdin");
        apply_stdin_chunk(&journal, None, runtime.as_ref(), &authority, &frame(2, 2))
            .expect("stdin"); // replay is ignored
        apply_cancel(
            None,
            runtime.as_ref(),
            &mut authority,
            &mut puts,
            "cmd",
            2,
            2,
        );
        apply_cancel(
            None,
            runtime.as_ref(),
            &mut authority,
            &mut puts,
            "cmd",
            2,
            2,
        );
        authority
            .accept_dispatch("stop", "sbx-1", "sandbox.stop", 3, 1)
            .expect("stop");
        apply_stdin_chunk(&journal, None, runtime.as_ref(), &authority, &frame(2, 2))
            .expect("stdin");
        apply_cancel(
            None,
            runtime.as_ref(),
            &mut authority,
            &mut puts,
            "cmd",
            2,
            2,
        );
        let observed = calls.lock().expect("lock");
        assert_eq!(observed.stdin.len(), 2);
        assert_eq!(observed.cancel, vec!["cmd"]);
        assert_eq!(
            (observed.stdin[0].generation, observed.stdin[0].attempt),
            (2, 2)
        );
        assert_eq!(observed.stdin[0].bytes, b"A");
        assert!(!observed.stdin[0].eof);
        assert_eq!(observed.stdin[1].bytes, b"B");
        assert!(observed.stdin[1].eof);
        drop(observed);
        // Separate current command exercises stream overflow through the production consumer.
        let authority = HostAuthority::default();
        authority
            .accept_dispatch("cmd", "sbx-1", "command.run", 2, 3)
            .expect("retry");
        for sequence in 1..=64 {
            apply_stdin_chunk(
                &journal,
                None,
                runtime.as_ref(),
                &authority,
                &chunk(2, 3, sequence, b"x", false),
            )
            .expect("bounded buffering");
        }
        let failure = apply_stdin_chunk(
            &journal,
            None,
            runtime.as_ref(),
            &authority,
            &chunk(2, 3, 65, b"x", true),
        )
        .expect_err("overflow closes stream");
        assert_eq!(
            failure.error.expect("typed error").code,
            SandboxErrorCode::RequestTooLarge
        );
        assert!(
            authority.pending("cmd").is_some(),
            "completion owner survives until publication"
        );
        apply_stdin_chunk(
            &journal,
            None,
            runtime.as_ref(),
            &authority,
            &chunk(2, 3, 0, b"late", false),
        )
        .expect("closed");
        let authority = HostAuthority::default();
        authority
            .accept_dispatch("cmd", "sbx-1", "command.run", 2, 4)
            .expect("current");
        calls.lock().expect("lock").fail_stdin = true;
        let failure = apply_stdin_chunk(
            &journal,
            None,
            runtime.as_ref(),
            &authority,
            &chunk(2, 4, 0, b"x", false),
        )
        .expect_err("IO failure closes stream");
        assert_eq!(
            failure.error.expect("typed IO error").code,
            SandboxErrorCode::GuestOperationFailed
        );
        assert!(
            authority.pending("cmd").is_some(),
            "completion owner survives until publication"
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn delayed_supervised_worker_cannot_execute_after_stop_and_cold_reconnect() {
        use std::sync::{Arc, Barrier};
        let dir = std::env::temp_dir().join(format!("wssp-c08-worker-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("directory");
        let shim = dir.join("incus-shim");
        let log = dir.join("exec.log");
        crate::sandbox_relay::test_support::install_executable(
            &shim,
            format!(
                "#!/bin/sh\nif [ \"$1\" = \"query\" ]; then echo '{{\"type\":\"sync\",\"metadata\":{{\"status\":\"Running\",\"status_code\":103,\"type\":\"virtual-machine\",\"config\":{{\"user.flycockpit.sandbox_id\":\"sbx\",\"user.flycockpit.template_digest\":\"sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\",\"volatile.base_image\":\"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\"}}}}}}'; exit 0; fi\nprintf 'exec started' >> '{}'\nexit 1\n",
                log.display()
            ),
            0o700,
        );
        let authority = HostAuthority::default();
        authority
            .accept_dispatch("cmd", "sbx", "command.run", 1, 1)
            .expect("command");
        let supervisor = ExecSupervisor::new(sandbox_runtime::IncusClient::new(
            shim.to_string_lossy(),
            "default",
        ));
        let dispatch: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
            "operationId":"cmd","sandboxId":"sbx","idempotencyKey":"cmd","kind":"command.run", "resultVersion":1, "processId":"proc-cmd","generation":1,"attempt":1,"argv":["true"],"incusFingerprint":sandbox_runtime::CreateSandboxRequest::for_test("sbx", "key").template_digest
        })).expect("dispatch");
        let entered = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        let (tx, rx) = mpsc::channel();
        let worker = spawn_supervised_run_after(
            supervisor,
            tx,
            &dispatch,
            "wssp-sbx-sbx".into(),
            authority.clone(),
            {
                let entered = entered.clone();
                let resume = resume.clone();
                move || {
                    entered.wait();
                    resume.wait();
                }
            },
        )
        .expect("worker");
        entered.wait();
        authority
            .accept_dispatch("stop", "sbx", "sandbox.stop", 2, 1)
            .expect("stop");
        authority.complete("stop");
        authority
            .accept_dispatch("cold", "sbx", "sandbox.reconnect", 3, 1)
            .expect("cold reconnect");
        authority.complete("cold");
        resume.wait();
        worker.join().expect("join");
        assert_eq!(rx.recv().expect("result").state, OperationState::Failed);
        assert!(!log.exists(), "obsolete worker must never spawn the shim");
        std::fs::remove_file(shim).expect("remove shim");
        std::fs::remove_dir(dir).expect("remove directory");
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn shutdown_kills_descendant_holding_pipes_and_bounds_worker_join() {
        use std::time::Instant;
        let dir = std::env::temp_dir().join(format!("wssp-c08-pipes-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("directory");
        let shim = dir.join("incus-shim");
        let ready = dir.join("ready");
        let release = dir.join("release");
        // Parent exits after its child has inherited the pipes. The descendant cannot
        // close them before the test release file, unless group-killed by shutdown.
        crate::sandbox_relay::test_support::install_executable(
            &shim,
            format!(
                "#!/bin/sh\nif [ \"$1\" = \"query\" ]; then echo '{{\"type\":\"sync\",\"metadata\":{{\"status\":\"Running\",\"status_code\":103,\"type\":\"virtual-machine\",\"config\":{{\"user.flycockpit.sandbox_id\":\"sbx\",\"user.flycockpit.template_digest\":\"sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\",\"volatile.base_image\":\"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\"}}}}}}'; exit 0; fi\n( echo $$ > '{}'; while [ ! -e '{}' ]; do sleep 0.05; done ) &\nexit 0\n",
                ready.display(),
                release.display()
            ),
            0o700,
        );
        let supervisor = ExecSupervisor::new(sandbox_runtime::IncusClient::new(
            shim.to_string_lossy(),
            "default",
        ));
        let authority = HostAuthority::default();
        authority
            .accept_dispatch("cmd", "sbx", "command.run", 1, 1)
            .expect("admit");
        let dispatch: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
            "operationId":"cmd","sandboxId":"sbx","idempotencyKey":"cmd","kind":"command.run", "resultVersion":1, "processId":"proc-cmd","generation":1,"attempt":1,"argv":["true"],"incusFingerprint":sandbox_runtime::CreateSandboxRequest::for_test("sbx", "key").template_digest
        })).expect("dispatch");
        let (tx, rx) = mpsc::channel();
        let worker = spawn_supervised_run(
            supervisor.clone(),
            tx,
            &dispatch,
            "wssp-sbx-sbx".into(),
            authority.clone(),
        )
        .expect("worker");
        let until = Instant::now() + Duration::from_secs(3);
        while !ready.exists() && Instant::now() < until {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.exists(), "descendant must hold output pipes");
        let parent_pid = std::fs::read_to_string(&ready).expect("parent pid");
        let parent_path = std::path::PathBuf::from(format!("/proc/{}", parent_pid.trim()));
        while parent_path.exists() && Instant::now() < until {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !parent_path.exists(),
            "worker must have reaped the exited parent while pipes remain held"
        );
        assert!(!worker.is_finished());
        let workers = RelayWorkers {
            authority,
            handles: vec![worker],
            supervisor: Some(supervisor),
        };
        let (done_tx, done_rx) = mpsc::channel();
        let shutdown = thread::spawn(move || {
            drop(workers);
            done_tx.send(()).expect("done");
        });
        let bounded = done_rx.recv_timeout(Duration::from_secs(6));
        // Always release the shim even if the regression fails; no stranded process.
        std::fs::write(&release, b"release").expect("release");
        shutdown.join().expect("shutdown");
        assert!(bounded.is_ok(), "shutdown must finish before pipe release");
        let finished = rx
            .recv_timeout(Duration::from_secs(1))
            .expect("worker joined after kill");
        assert_eq!(
            finished.error.expect("cancelled").code,
            SandboxErrorCode::UnknownOutcome
        );
        std::fs::remove_dir_all(dir).expect("test cleanup");
    }
    #[test]
    fn shutdown_detaches_unresponsive_worker_at_deadline() {
        let authority = HostAuthority::default();
        let (release_tx, release_rx) = mpsc::channel();
        let (exited_tx, exited_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            release_rx.recv().expect("release");
            exited_tx.send(()).expect("exited");
        });
        let workers = RelayWorkers {
            authority: authority.clone(),
            handles: vec![worker],
            supervisor: None,
        };
        let (done_tx, done_rx) = mpsc::channel();
        let shutdown = thread::spawn(move || {
            drop(workers);
            done_tx.send(()).expect("done");
        });
        let bounded = done_rx.recv_timeout(Duration::from_secs(6));
        release_tx.send(()).expect("cleanup release");
        exited_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("detached worker cleaned up");
        shutdown.join().expect("shutdown");
        assert!(bounded.is_ok());
        assert!(
            authority
                .accept_dispatch("late", "sbx", "command.run", 1, 1)
                .is_err()
        );
    }
    #[cfg(unix)]
    #[test]
    fn t1_host_policy_raise_persists_then_reports_on_current_epoch_only() {
        let dir = tempfile::tempdir().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut config = crate::config::Config::default();
        config.set_host_terminal(true).unwrap();
        config.set_host_terminal_totp(false).unwrap();
        std::fs::write(
            dir.path().join("config.toml"),
            toml::to_string(&config).unwrap(),
        )
        .unwrap();
        let shutdown = ShutdownSignal::default();
        let options = ConnectOptions {
            host_terminal: None,
            server_url: format!("ws://{address}"),
            host_token: "test-only-token".into(),
            host_id: "host".into(),
            label: "test".into(),
            runtime: HostRuntimeKind::Fake,
            incus_project: None,
            state_dir: Some(dir.path().into()),
            heartbeat: Duration::from_secs(1),
            sandbox_memory_mib: None,
            max_sandbox_cpu_count: None,
            sandbox_vcpu_budget: Some(4),
            max_concurrent_commands: 16,
            shutdown: shutdown.clone(),
        };
        let client = thread::spawn(move || {
            crate::sandbox_relay::test_support::run_fixture_connect(&options)
        });
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake).unwrap();
        wire.read().unwrap();
        let binding = TransportBindingV11 {
            server: format!("ws://{address}/ws/sandbox-host"),
            host_owner_id: "owner-1".into(),
            host_id: "host".into(),
        };
        crate::sandbox_relay::test_support::send_sized_hello(&mut wire, &binding);
        let (_, initial) =
            crate::sandbox_relay::test_support::ack_reconciliation_with_policy(&mut wire);
        let next_policy = |wire: &mut tungstenite::WebSocket<std::net::TcpStream>| loop {
            if let Message::Text(text) = wire.read().unwrap()
                && let DaemonControlMessage::HostTerminalPolicy(policy) =
                    sandbox_protocol::parse_daemon_control(&text).unwrap()
            {
                break policy;
            }
        };
        assert_eq!(initial.connection_epoch, 1);
        assert!(!initial.require_host_terminal_totp);
        // Old epoch is ignored; the next heartbeat proves the socket handled it.
        wire.send(Message::Text(json!({"type":"host.terminal-policy.raise", "connectionEpoch":2,"requestId":"old-raise"}).to_string().into())).unwrap();
        loop {
            if let Message::Text(text) = wire.read().unwrap()
                && matches!(
                    sandbox_protocol::parse_daemon_control(&text).unwrap(),
                    DaemonControlMessage::Heartbeat { .. }
                )
            {
                break;
            }
        }
        assert!(
            !crate::config::Config::read(&dir.path().join("config.toml"))
                .unwrap()
                .host_terminal_require_totp
        );
        wire.send(Message::Text(json!({"type":"host.terminal-policy.raise", "connectionEpoch":1,"requestId":"current-raise"}).to_string().into())).unwrap();
        let raised = next_policy(&mut wire);
        assert!(raised.require_host_terminal_totp);
        assert!(raised.policy_revision > initial.policy_revision);
        let persisted = crate::config::Config::read(&dir.path().join("config.toml")).unwrap();
        assert!(persisted.host_terminal_require_totp);
        assert!(persisted.allow_host_terminal);
        // Fake runtime never advertises or starts a real host shell.
        assert!(!raised.host_terminal);
        shutdown.request();
        while wire.read().is_ok_and(|f| !matches!(f, Message::Close(_))) {}
        client.join().unwrap().unwrap();
    }

    /// The hello carries the live host lease ceiling from local config; a
    /// later local change is reported on the current link as
    /// `host.lease-policy` without touching the terminal policy revision.
    #[cfg(unix)]
    #[test]
    fn host_lease_ceiling_rides_the_hello_and_hot_reload_reports_it() {
        let dir = tempfile::tempdir().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut config = crate::config::Config::default();
        config.set_max_lease(crate::config::MaxLease::Finite(21_600_000));
        let config_path = dir.path().join("config.toml");
        std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
        let shutdown = ShutdownSignal::default();
        let options = ConnectOptions {
            host_terminal: None,
            server_url: format!("ws://{address}"),
            host_token: "test-only-token".into(),
            host_id: "host".into(),
            label: "test".into(),
            runtime: HostRuntimeKind::Fake,
            incus_project: None,
            state_dir: Some(dir.path().into()),
            heartbeat: Duration::from_secs(1),
            sandbox_memory_mib: None,
            max_sandbox_cpu_count: None,
            sandbox_vcpu_budget: Some(4),
            max_concurrent_commands: 16,
            shutdown: shutdown.clone(),
        };
        let client = thread::spawn(move || {
            crate::sandbox_relay::test_support::run_fixture_connect(&options)
        });
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake).unwrap();
        let hello = wire.read().unwrap();
        match sandbox_protocol::parse_daemon_control(hello.to_text().unwrap()).unwrap() {
            DaemonControlMessage::Hello { daemon, .. } => {
                assert_eq!(daemon.capabilities.max_lease_ms, Some(21_600_000));
            }
            other => panic!("unexpected {other:?}"),
        }
        let binding = TransportBindingV11 {
            server: format!("ws://{address}/ws/sandbox-host"),
            host_owner_id: "owner-1".into(),
            host_id: "host".into(),
        };
        crate::sandbox_relay::test_support::send_sized_hello(&mut wire, &binding);
        let (_, initial) =
            crate::sandbox_relay::test_support::ack_reconciliation_with_policy(&mut wire);
        config.set_max_lease(crate::config::MaxLease::Unlimited);
        std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
        let report = loop {
            if let Message::Text(text) = wire.read().unwrap() {
                match sandbox_protocol::parse_daemon_control(&text).unwrap() {
                    DaemonControlMessage::HostLeasePolicy(report) => break report,
                    DaemonControlMessage::HostTerminalPolicy(policy) => {
                        panic!("terminal policy must not change: {policy:?}")
                    }
                    _ => {}
                }
            }
        };
        assert_eq!(
            report,
            sandbox_protocol::HostLeasePolicyV11 {
                connection_epoch: initial.connection_epoch,
                sequence: 1,
                max_lease_ms: None,
            }
        );
        shutdown.request();
        while wire.read().is_ok_and(|f| !matches!(f, Message::Close(_))) {}
        client.join().unwrap().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn credential_revocation_close_is_terminal() {
        use std::net::TcpListener;
        use tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};
        let dir = tempfile::tempdir().expect("dir");
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let address = listener.local_addr().expect("address");
        let options = ConnectOptions {
            host_terminal: None,
            server_url: format!("ws://{address}"),
            host_token: "test-only-token".into(),
            host_id: "host".into(),
            label: "test".into(),
            runtime: HostRuntimeKind::Fake,
            incus_project: None,
            state_dir: Some(dir.path().into()),
            heartbeat: Duration::from_secs(5),
            sandbox_memory_mib: None,
            max_sandbox_cpu_count: None,
            sandbox_vcpu_budget: Some(4),
            max_concurrent_commands: 16,
            shutdown: Default::default(),
        };
        let client = thread::spawn(move || {
            crate::sandbox_relay::test_support::run_fixture_connect(&options)
        });
        let (tcp, _) = listener.accept().expect("accept");
        tcp.set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake).expect("handshake");
        wire.read().expect("hello");
        wire.close(Some(CloseFrame {
            code: CloseCode::Library(4003),
            reason: "credential_inactive".into(),
        }))
        .expect("close");
        let error = client
            .join()
            .expect("join")
            .expect_err("terminal revocation");
        assert_eq!(
            crate::exit::code_for(&error),
            crate::exit::ExitCode::CredentialInactive
        );
        assert!(crate::exit::message_for(&error).contains("host credential is inactive"));
        assert!(!error.to_string().contains("test-only-token"));
    }

    /// Review round 2 #2: a definitive revocation (ban → close 4003) leaves
    /// the server no way to stop this host's VMs, so the daemon stops every
    /// one itself, durably: disks kept, nothing destroyed; a restart re-applies
    /// the stop before anything else; a registered session (unban /
    /// re-enrollment) lifts it, and the VM can be started again.
    #[cfg(unix)]
    #[test]
    fn authority_revocation_stops_every_vm_durably_and_registration_lifts_it() {
        use crate::sandbox_relay::test_support::FixtureRuntime;
        use std::net::TcpListener;
        use tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};
        let dir = tempfile::tempdir().expect("dir");
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let address = listener.local_addr().unwrap();
        let binding = TransportBindingV11 {
            server: format!("ws://{address}/ws/sandbox-host"),
            host_owner_id: "owner-1".into(),
            host_id: "host".into(),
        };
        // A running sandbox with a durable lease, exactly as a create leaves it.
        let runtime = sandbox_runtime::FakeRuntime::new();
        runtime.fixture_root().expect("fixture root");
        let create = sandbox_runtime::CreateSandboxRequest::for_test("revoked-vm", "create");
        {
            let journal =
                crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                    .unwrap();
            let dispatch: OperationDispatch = serde_json::from_value(json!({
                "sandboxOwnerId": "owner", "operationId": "create", "sandboxId": "revoked-vm",
                "kind": "sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(),
                "cpuCount": 1, "memoryMiB": 1024, "idempotencyKey": "create", "generation": 1,
                "attempt": 1, "bodyHash": "a".repeat(64),
                // A destroy lease (the default): only its timer may destroy it,
                // never the revocation.
                "lease": sandbox_protocol::HostLease {
                    action: sandbox_protocol::LeaseAction::Destroy,
                    ..sandbox_protocol::HostLease::for_test()
                },
                "architecture": "x86_64", "templateDigest": create.template_digest,
                "incusFingerprint": create.incus_fingerprint,
            }))
            .unwrap();
            journal
                .record_fixture_intent(&super::super::journal::intent_from_dispatch(
                    &journal, &binding, &dispatch,
                ))
                .unwrap();
            journal.accept_fixture_lease(&dispatch).unwrap();
            runtime.create_fixture(&create).expect("running VM");
        }
        let state = |runtime: &sandbox_runtime::FakeRuntime| {
            runtime
                .sandbox_inventory()
                .expect("inventory")
                .into_iter()
                .find(|entry| entry.sandbox_id == "revoked-vm")
                .map(|entry| entry.state)
        };
        assert_eq!(
            state(&runtime),
            Some(sandbox_protocol::SandboxLifecycleState::Ready)
        );
        let options = |shutdown: ShutdownSignal, state: &std::path::Path| ConnectOptions {
            host_terminal: None,
            server_url: format!("ws://{address}"),
            host_token: "test-only-token".into(),
            host_id: "host".into(),
            label: "test".into(),
            runtime: HostRuntimeKind::Fake,
            incus_project: None,
            state_dir: Some(state.into()),
            heartbeat: Duration::from_secs(1),
            sandbox_memory_mib: None,
            max_sandbox_cpu_count: None,
            sandbox_vcpu_budget: Some(4),
            max_concurrent_commands: 16,
            shutdown,
        };
        // A restart reopens the same journal files in a new process. In this
        // process, detached relay/expiry threads of the finished run can keep
        // the old journal's lock, so each "restart" reopens a byte copy of
        // the state directory (same records, same marker, fresh lock).
        let restart_dir = |from: &std::path::Path| {
            let to = tempfile::tempdir().expect("restart dir");
            for entry in walk(from) {
                let target = to.path().join(entry.strip_prefix(from).unwrap());
                if entry.is_dir() {
                    std::fs::create_dir_all(&target).unwrap();
                } else if entry.file_name().is_some_and(|n| n != "LOCK") {
                    std::fs::copy(&entry, &target).unwrap();
                }
            }
            to
        };
        fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
            let mut out = Vec::new();
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                out.push(path.clone());
                if path.is_dir() {
                    out.extend(walk(&path));
                }
            }
            out
        }
        let connect = |options: ConnectOptions, runtime: sandbox_runtime::FakeRuntime| {
            thread::spawn(move || {
                super::run_connect_with(&options, move |_| Ok((Box::new(runtime), None)))
            })
        };
        let accept = || {
            let (tcp, _) = listener.accept().expect("accept");
            tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake).expect("handshake");
            wire.read().expect("hello");
            wire
        };
        let revoke = |mut wire: tungstenite::WebSocket<std::net::TcpStream>| {
            // The server's explicit verdict for a banned owner.
            wire.close(Some(CloseFrame {
                code: CloseCode::Library(4003),
                reason: "owner_unavailable".into(),
            }))
            .expect("close");
            while wire.read().is_ok() {}
        };
        // The relay is gone after a revocation; the daemon keeps its journal
        // lock while the destroy lease's timer is pending, until shut down.
        let wait_stopped = |runtime: &sandbox_runtime::FakeRuntime| {
            let until = std::time::Instant::now() + Duration::from_secs(20);
            while state(runtime) != Some(sandbox_protocol::SandboxLifecycleState::Stopped) {
                assert!(std::time::Instant::now() < until, "VM was not stopped");
                thread::sleep(Duration::from_millis(20));
            }
        };
        // Ban: the server closes the relay with 4003.
        let shutdown = ShutdownSignal::default();
        let client = connect(options(shutdown.clone(), dir.path()), runtime.clone());
        revoke(accept());
        wait_stopped(&runtime);
        shutdown.request();
        let error = client.join().expect("join").expect_err("revoked");
        assert_eq!(
            crate::exit::code_for(&error),
            crate::exit::ExitCode::CredentialInactive
        );
        // Stopped, not destroyed (the VM and its disk remain), durably recorded.
        assert_eq!(
            state(&runtime),
            Some(sandbox_protocol::SandboxLifecycleState::Stopped)
        );
        assert!(
            dir.path().join("AUTHORITY-REVOKED").exists(),
            "durable marker"
        );
        // The VM comes back (e.g. a host reboot autostarts it); a daemon
        // restart stops it again BEFORE it even dials the server.
        let reconnect = sandbox_runtime::ReconnectSandboxRequest {
            vm_size: sandbox_protocol::VmSize::defaults().unwrap(),
            lease: sandbox_protocol::HostLease::for_test(),
            template_fingerprint: create.template_digest.clone(),
            architecture: create.architecture.clone(),
            guest: create.guest.clone(),
            sandbox_id: create.sandbox_id.clone(),
            instance_name: create.instance_name.clone(),
            operation_id: "restart".into(),
            idempotency_key: "restart".into(),
            egress_policy: None,
            egress_policy_hash: None,
            egress_admission: sandbox_runtime::egress::EgressAdmission::PERMITTED,
            guest_sudo: false,
        };
        runtime.reconnect_fixture(&reconnect).expect("restarted");
        assert_eq!(
            state(&runtime),
            Some(sandbox_protocol::SandboxLifecycleState::Ready)
        );
        let second = restart_dir(dir.path());
        let shutdown = ShutdownSignal::default();
        let client = connect(options(shutdown.clone(), second.path()), runtime.clone());
        let wire = accept();
        assert_eq!(
            state(&runtime),
            Some(sandbox_protocol::SandboxLifecycleState::Stopped),
            "stopped before the hello"
        );
        revoke(wire);
        wait_stopped(&runtime);
        shutdown.request();
        client.join().expect("join").expect_err("still revoked");
        // Unban / re-enrollment: a registered session lifts the revocation.
        let third = restart_dir(second.path());
        assert!(
            third.path().join("AUTHORITY-REVOKED").exists(),
            "still revoked"
        );
        let shutdown = ShutdownSignal::default();
        let client = connect(options(shutdown.clone(), third.path()), runtime.clone());
        let mut wire = accept();
        crate::sandbox_relay::test_support::send_sized_hello(&mut wire, &binding);
        crate::sandbox_relay::test_support::ack_reconciliation_with_policy(&mut wire);
        let until = std::time::Instant::now() + Duration::from_secs(10);
        while third.path().join("AUTHORITY-REVOKED").exists() {
            assert!(std::time::Instant::now() < until, "lifted on registration");
            thread::sleep(Duration::from_millis(20));
        }
        shutdown.request();
        while wire.read().is_ok_and(|f| !matches!(f, Message::Close(_))) {}
        client.join().expect("join").expect("clean shutdown");
        // The disk was kept: the original VM starts again.
        runtime
            .reconnect_fixture(&reconnect)
            .expect("cold start after unban");
        assert_eq!(
            state(&runtime),
            Some(sandbox_protocol::SandboxLifecycleState::Ready)
        );
    }

    /// Only an explicit server verdict about THIS enrolled credential stops
    /// VMs: a wrong/unknown token (plain 401/403) or an ambiguous 4003 never
    /// does; `credential_revoked` / `owner_unavailable` (close reason or upgrade
    /// refusal code) always does.
    #[cfg(unix)]
    #[test]
    fn only_an_explicit_revocation_verdict_stops_vms() {
        use crate::sandbox_relay::test_support::FixtureRuntime;
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};
        enum Server {
            Upgrade(&'static str, &'static str),
            Close(&'static str),
        }
        for (case, server, stops) in [
            (
                "wrong token",
                Server::Upgrade("401 Unauthorized", ""),
                false,
            ),
            (
                "unknown credential",
                Server::Upgrade("403 Forbidden", r#"{"error":"x"}"#),
                false,
            ),
            (
                "ambiguous 4003",
                Server::Close("credential_inactive"),
                false,
            ),
            (
                "revoked credential",
                Server::Upgrade(
                    "401 Unauthorized",
                    r#"{"error":"x","code":"credential_revoked"}"#,
                ),
                true,
            ),
            ("banned owner", Server::Close("owner_unavailable"), true),
            (
                "banned owner at upgrade (body only)",
                Server::Upgrade("403 Forbidden", r#"{"code":"owner_unavailable"}"#),
                true,
            ),
            (
                "revoked mid-session",
                Server::Close("credential_revoked"),
                true,
            ),
        ] {
            let dir = tempfile::tempdir().expect("dir");
            let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
            let address = listener.local_addr().unwrap();
            let binding = TransportBindingV11 {
                server: format!("ws://{address}/ws/sandbox-host"),
                host_owner_id: "owner-1".into(),
                host_id: "host".into(),
            };
            let runtime = sandbox_runtime::FakeRuntime::new();
            runtime.fixture_root().expect("fixture root");
            let create = sandbox_runtime::CreateSandboxRequest::for_test("vm", "create");
            {
                let journal =
                    crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                        .unwrap();
                let dispatch: OperationDispatch = serde_json::from_value(json!({
                    "sandboxOwnerId": "owner", "operationId": "create", "sandboxId": "vm",
                    "kind": "sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(),
                    "cpuCount": 1, "memoryMiB": 1024, "idempotencyKey": "create", "generation": 1,
                    "attempt": 1, "bodyHash": "a".repeat(64),
                    "lease": sandbox_protocol::HostLease {
                        action: sandbox_protocol::LeaseAction::Destroy,
                        ..sandbox_protocol::HostLease::for_test()
                    },
                    "architecture": "x86_64", "templateDigest": create.template_digest,
                    "incusFingerprint": create.incus_fingerprint,
                }))
                .unwrap();
                journal
                    .record_fixture_intent(&super::super::journal::intent_from_dispatch(
                        &journal, &binding, &dispatch,
                    ))
                    .unwrap();
                journal.accept_fixture_lease(&dispatch).unwrap();
                runtime.create_fixture(&create).expect("running VM");
            }
            let shutdown = ShutdownSignal::default();
            let options = ConnectOptions {
                host_terminal: None,
                server_url: format!("ws://{address}"),
                host_token: "test-only-token".into(),
                host_id: "host".into(),
                label: "test".into(),
                runtime: HostRuntimeKind::Fake,
                incus_project: None,
                state_dir: Some(dir.path().into()),
                heartbeat: Duration::from_secs(5),
                sandbox_memory_mib: None,
                max_sandbox_cpu_count: None,
                sandbox_vcpu_budget: Some(4),
                max_concurrent_commands: 16,
                shutdown: shutdown.clone(),
            };
            let shared = runtime.clone();
            let client = thread::spawn(move || {
                super::run_connect_with(&options, move |_| Ok((Box::new(shared), None)))
            });
            let (mut tcp, _) = listener.accept().expect("accept");
            tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            match server {
                Server::Upgrade(status, body) => {
                    let mut request = [0_u8; 4096];
                    let _ = tcp.read(&mut request).expect("upgrade request");
                    // One write: tungstenite keeps only the bytes read with the headers.
                    tcp.write_all(
                        format!(
                            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .expect("respond");
                }
                Server::Close(reason) => {
                    let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake).expect("handshake");
                    wire.read().expect("hello");
                    wire.close(Some(CloseFrame {
                        code: CloseCode::Library(4003),
                        reason: reason.into(),
                    }))
                    .expect("close");
                    while wire.read().is_ok() {}
                }
            }
            let state = || {
                runtime
                    .sandbox_inventory()
                    .unwrap()
                    .into_iter()
                    .find(|entry| entry.sandbox_id == "vm")
                    .map(|entry| entry.state)
            };
            let until = std::time::Instant::now() + Duration::from_secs(3);
            while std::time::Instant::now() < until
                && state() != Some(sandbox_protocol::SandboxLifecycleState::Stopped)
            {
                thread::sleep(Duration::from_millis(20));
            }
            // The daemon keeps its journal lock while the lease is pending.
            shutdown.request();
            let error = client.join().expect("join").expect_err(case);
            assert_eq!(
                crate::exit::code_for(&error),
                crate::exit::ExitCode::CredentialInactive,
                "{case}"
            );
            assert_eq!(
                state(),
                Some(if stops {
                    sandbox_protocol::SandboxLifecycleState::Stopped
                } else {
                    sandbox_protocol::SandboxLifecycleState::Ready
                }),
                "{case}"
            );
            assert_eq!(
                dir.path().join("AUTHORITY-REVOKED").exists(),
                stops,
                "{case}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn upgrade_unauthorized_is_terminal_credential_exit() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        for status in ["401 Unauthorized", "403 Forbidden"] {
            let dir = tempfile::tempdir().expect("dir");
            let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
            let address = listener.local_addr().expect("address");
            let options = ConnectOptions {
                host_terminal: None,
                server_url: format!("ws://{address}"),
                host_token: "test-only-token".into(),
                host_id: "host".into(),
                label: "test".into(),
                runtime: HostRuntimeKind::Fake,
                incus_project: None,
                state_dir: Some(dir.path().into()),
                heartbeat: Duration::from_secs(5),
                sandbox_memory_mib: None,
                max_sandbox_cpu_count: None,
                sandbox_vcpu_budget: Some(4),
                max_concurrent_commands: 16,
                shutdown: Default::default(),
            };
            let client = thread::spawn(move || {
                crate::sandbox_relay::test_support::run_fixture_connect(&options)
            });
            let (mut tcp, _) = listener.accept().expect("accept");
            tcp.set_read_timeout(Some(Duration::from_secs(3)))
                .expect("timeout");
            let mut request = [0_u8; 4096];
            let _ = tcp.read(&mut request).expect("upgrade request");
            write!(
                tcp,
                "HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            )
            .expect("respond");
            let error = client.join().expect("join").expect_err("rejected upgrade");
            assert_eq!(
                crate::exit::code_for(&error),
                crate::exit::ExitCode::CredentialInactive,
                "{status}"
            );
            assert!(!format!("{error:#}").contains("test-only-token"));
        }
    }

    /// The first connect reports a temporary server outage without exposing credentials.
    #[cfg(unix)]
    #[test]
    fn upgrade_503_reports_service_unavailable() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let dir = tempfile::tempdir().expect("dir");
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let address = listener.local_addr().expect("address");
        let options = ConnectOptions {
            host_terminal: None,
            server_url: format!("ws://{address}"),
            host_token: "test-only-token".into(),
            host_id: "host".into(),
            label: "test".into(),
            runtime: HostRuntimeKind::Fake,
            incus_project: None,
            state_dir: Some(dir.path().into()),
            heartbeat: Duration::from_secs(5),
            sandbox_memory_mib: None,
            max_sandbox_cpu_count: None,
            sandbox_vcpu_budget: Some(4),
            max_concurrent_commands: 16,
            shutdown: Default::default(),
        };
        let client = thread::spawn(move || {
            crate::sandbox_relay::test_support::run_fixture_connect(&options)
        });
        let (mut tcp, _) = listener.accept().expect("accept");
        tcp.set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        let mut request = [0_u8; 4096];
        let _ = tcp.read(&mut request).expect("upgrade request");
        let body = r#"{"error":"Service unavailable."}"#;
        write!(
            tcp,
            "HTTP/1.1 503 Service Unavailable\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .expect("respond");
        let error = client
            .join()
            .expect("join")
            .expect_err("service unavailable");
        let message = format!("{error:#}");
        assert!(message.contains("temporarily unavailable"), "{message}");
        assert!(message.contains("503"), "{message}");
        assert_ne!(
            crate::exit::code_for(&error),
            crate::exit::ExitCode::CredentialInactive
        );
        assert!(!message.contains("test-only-token"));
    }

    /// C32: a transient relay failure reconnects while leases and the journal
    /// lock stay held; the new session must serve dispatches long before the
    /// existing lease expires.
    #[cfg(unix)]
    #[test]
    fn transient_close_reconnects_and_keeps_serving_before_lease_expiry() {
        use std::net::TcpListener;
        use tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};
        let dir = tempfile::tempdir().expect("dir");
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let address = listener.local_addr().expect("address");
        let options = ConnectOptions {
            host_terminal: None,
            server_url: format!("ws://{address}"),
            host_token: "test-only-token".into(),
            host_id: "host".into(),
            label: "test".into(),
            runtime: HostRuntimeKind::Fake,
            incus_project: None,
            state_dir: Some(dir.path().into()),
            heartbeat: Duration::from_secs(5),
            sandbox_memory_mib: None,
            max_sandbox_cpu_count: None,
            sandbox_vcpu_budget: Some(4),
            max_concurrent_commands: 16,
            shutdown: Default::default(),
        };
        let fake = sandbox_runtime::FakeRuntime::new();
        fake.create_fixture(&sandbox_runtime::CreateSandboxRequest::for_test(
            "sbx", "create",
        ))
        .unwrap();
        {
            let binding = TransportBindingV11 {
                server: format!("ws://{address}/ws/sandbox-host"),
                host_owner_id: "owner-1".into(),
                host_id: "host".into(),
            };
            let journal =
                crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                    .unwrap();
            let d: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":"create", "sandboxId":"sbx", "kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(), "cpuCount": 1, "memoryMiB": 1024, "generation":1, "attempt":1, "idempotencyKey":"create", "bodyHash":"a".repeat(64), "lease":sandbox_protocol::HostLease::for_test()})).unwrap();
            journal
                .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
                .unwrap();
            journal.accept_fixture_lease(&d).unwrap();
            journal
                .record_result(
                    "create",
                    OperationState::Succeeded,
                    Some(json!({"state":"ready","lease":d.lease})),
                    None,
                    None,
                )
                .unwrap();
        }
        let daemon_fake = fake.clone();
        let shutdown = options.shutdown.clone();
        let client = thread::spawn(move || {
            run_connect_with(&options, |_| Ok((Box::new(daemon_fake), None)))
        });
        let (tcp, _) = listener.accept().expect("accept");
        tcp.set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake).expect("handshake");
        wire.read().expect("hello");
        let dropped = Instant::now();
        wire.close(Some(CloseFrame {
            code: CloseCode::Library(1011),
            reason: "internal_error".into(),
        }))
        .expect("close");
        drop(wire);
        // The daemon must reconnect on its own; the lease deadline is an hour out.
        let (tcp, _) = listener.accept().expect("reconnect");
        assert!(
            dropped.elapsed() < Duration::from_secs(10),
            "reconnection must not wait for leases to settle"
        );
        tcp.set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake).expect("handshake");
        wire.read().expect("hello");
        crate::sandbox_relay::test_support::send_ready_hello_value(
            &mut wire,
            serde_json::from_str(include_str!(
                "../../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
            ))
            .unwrap(),
            "host",
        );
        crate::sandbox_relay::test_support::ack_registration(&mut wire);
        wire.send(Message::Text(crate::sandbox_relay::test_support::current_control_fixture(json!({"sandboxOwnerId":"owner", "type":"operation.dispatch", "operationId":"cmd", "sandboxId":"sbx", "kind":"command.run", "resultVersion":1, "processId":"proc-cmd", "incusFingerprint":sandbox_runtime::CreateSandboxRequest::for_test("sbx", "key").template_digest, "generation":1, "attempt":1, "idempotencyKey":"cmd", "bodyHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "argv":["true"]})).to_string().into())).expect("dispatch");
        loop {
            match wire.read().expect("frame") {
                Message::Text(text) => {
                    match sandbox_protocol::parse_daemon_control(&text).expect("control") {
                        DaemonControlMessage::OperationResult {
                            operation_id,
                            state,
                            result,
                            error,
                            ..
                        } => {
                            assert_eq!(
                                (operation_id.as_str(), state),
                                ("cmd", OperationState::Succeeded),
                                "result={result:?} error={error:?}"
                            );
                            break;
                        }
                        DaemonControlMessage::OperationProgress { .. }
                        | DaemonControlMessage::ProcessStarted { .. } => {}
                        // The 5 s egress lease renewal (§2.5) may interleave.
                        DaemonControlMessage::HostEgressState(_) => {}
                        other => panic!("unexpected {other:?}"),
                    }
                }
                Message::Binary(data) => wire
                    .send(crate::sandbox_relay::test_support::command_output_ack(
                        &data,
                    ))
                    .expect("output ack"),
                other => panic!("unexpected {other:?}"),
            }
        }
        fake.stop_sandbox(&sandbox_runtime::StopSandboxRequest {
            sandbox_id: "sbx".into(),
            instance_name: "wssp-sbx-sbx".into(),
            operation_id: "cleanup".into(),
            idempotency_key: "cleanup".into(),
            template_fingerprint: String::new(),
        })
        .unwrap();
        shutdown.request();
        client.join().expect("join").expect("connect");
    }

    #[cfg(unix)]
    #[test]
    fn slow_fake_command_keeps_real_socket_heartbeats_and_ping_alive() {
        fake_output_wire(false);
    }
    #[cfg(unix)]
    #[test]
    fn unacknowledged_output_does_not_deadlock_wire_cancellation() {
        fake_output_wire(true);
    }
    #[cfg(unix)]
    fn fake_output_wire(cancel: bool) {
        use sandbox_protocol::parse_daemon_control;
        use std::net::TcpListener;
        let dir = tempfile::tempdir().expect("dir");
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let address = listener.local_addr().expect("address");
        let options = ConnectOptions {
            host_terminal: None,
            server_url: format!("ws://{address}"),
            host_token: "test-only-token".into(),
            host_id: "host".into(),
            label: "test".into(),
            runtime: HostRuntimeKind::Fake,
            incus_project: None,
            state_dir: Some(dir.path().into()),
            heartbeat: Duration::from_millis(30),
            sandbox_memory_mib: None,
            max_sandbox_cpu_count: None,
            sandbox_vcpu_budget: Some(4),
            max_concurrent_commands: 16,
            shutdown: Default::default(),
        };
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let release_rx = std::sync::Mutex::new(release_rx);
        let fake = sandbox_runtime::FakeRuntime::with_command_delay(if cancel {
            Duration::from_secs(10)
        } else {
            Duration::from_millis(600)
        })
        .with_lifecycle_hook(move |stage| {
            if stage == "command-output" {
                entered_tx.send(()).expect("command entered");
                release_rx.lock().unwrap().recv().expect("release command");
            }
            Ok(())
        });
        fake.create_fixture(&sandbox_runtime::CreateSandboxRequest::for_test(
            "sbx", "create",
        ))
        .unwrap();
        {
            let binding = TransportBindingV11 {
                server: format!("ws://{address}/ws/sandbox-host"),
                host_owner_id: "owner-1".into(),
                host_id: "host".into(),
            };
            let journal =
                crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                    .unwrap();
            let d: OperationDispatch=serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":"create", "sandboxId":"sbx", "kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(), "cpuCount": 1, "memoryMiB": 1024, "generation":1, "attempt":1, "idempotencyKey":"create", "bodyHash":"a".repeat(64), "lease":sandbox_protocol::HostLease::for_test()})).unwrap();
            journal
                .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
                .unwrap();
            journal.accept_fixture_lease(&d).unwrap();
            journal
                .record_result(
                    "create",
                    OperationState::Succeeded,
                    Some(json!({"state":"ready","lease":d.lease})),
                    None,
                    None,
                )
                .unwrap();
        }
        let daemon_fake = fake.clone();
        let shutdown = options.shutdown.clone();
        let client = thread::spawn(move || {
            run_connect_with(&options, |_| Ok((Box::new(daemon_fake), None)))
        });
        let (tcp, _) = listener.accept().expect("accept");
        tcp.set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake).expect("handshake");
        wire.read().expect("hello");
        crate::sandbox_relay::test_support::send_ready_hello_value(
            &mut wire,
            serde_json::from_str(include_str!(
                "../../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
            ))
            .unwrap(),
            "host",
        );
        crate::sandbox_relay::test_support::ack_registration(&mut wire);
        wire.send(Message::Text(crate::sandbox_relay::test_support::current_control_fixture(json!({"sandboxOwnerId":"owner", "type":"operation.dispatch", "operationId":"slow", "sandboxId":"sbx", "kind":"command.run", "resultVersion":1, "processId":"proc-slow", "timeoutMs":300000, "incusFingerprint":sandbox_runtime::CreateSandboxRequest::for_test("sbx", "key").template_digest, "generation":1, "attempt":1, "idempotencyKey":"slow", "bodyHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "argv":["true"]})).to_string().into())).expect("dispatch");
        let mut heartbeats = 0;
        let mut pong = false;
        let mut first_output = false;
        let mut pending_action = None;
        let mut released = false;
        loop {
            match wire.read().expect("frame") {
                Message::Text(text) => match parse_daemon_control(&text).expect("control") {
                    DaemonControlMessage::Heartbeat { .. } => {
                        if first_output {
                            heartbeats += 1;
                        }
                    }
                    DaemonControlMessage::OperationResult { state, .. } => {
                        assert_eq!(
                            state,
                            if cancel {
                                OperationState::UnknownOutcome
                            } else {
                                OperationState::Succeeded
                            }
                        );
                        assert!(released, "completion must follow the worker barrier");
                        break;
                    }
                    DaemonControlMessage::OperationProgress { .. }
                    | DaemonControlMessage::ProcessStarted { .. } => {}
                    // The 5 s egress lease renewal (§2.5) may interleave.
                    DaemonControlMessage::HostEgressState(_) => {}
                    // Unacknowledged output holds the cancelled result for
                    // `DRAIN_IDLE`, across a 5 s storage observation.
                    DaemonControlMessage::InventoryUpdate { .. } if cancel => {}
                    other => panic!("unexpected {other:?}"),
                },
                Message::Binary(data) => {
                    let (metadata, body) = parse_binary_frame(&data).expect("binary output");
                    if !first_output {
                        entered_rx
                            .recv_timeout(Duration::from_secs(10))
                            .expect("worker barrier");
                        wire.send(Message::Ping(vec![1].into()))
                            .expect("ping during blocked work");
                    }
                    first_output = true;
                    assert_eq!(body, b"exec:true\n");
                    pending_action = Some(if cancel {
                        json!({"type":"operation.cancel", "operationId":metadata.operation_id, "generation":metadata.generation, "attempt":metadata.attempt, "reason":"cancelled"})
                    } else {
                        json!({"type":"command.output.ack", "operationId":metadata.operation_id, "generation":metadata.generation, "attempt":metadata.attempt, "sequence":metadata.sequence, "offset":metadata.offset.unwrap() + body.len() as u64})
                    });
                }
                Message::Pong(_) => pong = true,
                other => panic!("unexpected {other:?}"),
            }
            // Prove socket progress while runtime work is STILL held, then
            // release it. Admission/fsync latency is outside this ordering.
            if heartbeats >= 2 && pong && !released {
                let action = pending_action.take().expect("output before release");
                wire.send(Message::Text(action.to_string().into())).unwrap();
                release_tx.send(()).expect("release worker");
                released = true;
            }
        }
        assert!(
            heartbeats >= 2 && pong && first_output,
            "reader must run throughout slow runtime work"
        );
        fake.stop_sandbox(&sandbox_runtime::StopSandboxRequest {
            sandbox_id: "sbx".into(),
            instance_name: "wssp-sbx-sbx".into(),
            operation_id: "cleanup".into(),
            idempotency_key: "cleanup".into(),
            template_fingerprint: String::new(),
        })
        .unwrap();
        shutdown.request();
        client.join().expect("join").expect("connect");
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn failed_lifecycle_intent_cannot_revoke_a_live_exec_permit() {
        use super::super::journal::CrashPoint;
        use std::net::{TcpListener, TcpStream};
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().expect("dir");
        let binding = TransportBindingV11 {
            server: "wss://example".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let journal = Arc::new(
            crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                .expect("journal"),
        );
        let mut authority = HostAuthority::default();
        authority
            .accept_dispatch("old", "sbx", "command.run", 1, 1)
            .expect("old");
        let (permit, guard) = authority.register_exec("old", 1, 1).expect("permit");
        drop(guard);
        let relay = RelaySupervisor::start(
            Arc::new(sandbox_runtime::FakeRuntime::new()),
            journal.clone(),
            authority.clone(),
            None,
        );
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let tcp = TcpStream::connect(listener.local_addr().expect("address")).expect("connect");
        let _peer = listener.accept().expect("accept");
        let mut socket = tungstenite::WebSocket::from_raw_socket(
            tungstenite::stream::MaybeTlsStream::Plain(tcp),
            tungstenite::protocol::Role::Client,
            None,
        );
        let dispatch: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":"stop", "sandboxId":"sbx", "generation":2, "attempt":1, "kind":"sandbox.stop", "allocation": crate::sandbox_relay::test_support::allocation(), "idempotencyKey":"stop", "bodyHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})).expect("dispatch");
        journal.inject_crash(CrashPoint::AfterIntent);
        let dispatch = crate::sandbox_relay::test_support::pinned_dispatch(&dispatch);
        assert!(
            handle_dispatch(
                &mut socket,
                sandbox_protocol::WireCodes::CURRENT,
                &mut authority,
                &mut crate::sandbox_relay::test_support::admission(
                    64,
                    crate::sandbox_relay::live_admission::test_capacity()
                ),
                (&journal, &binding),
                &relay,
                &None,
                &mut HashMap::new(),
                &dispatch
            )
            .is_err()
        );
        assert!(!permit.load(Ordering::Acquire));
        assert!(authority.accept_stream("old", 1, 1).is_ok());
        assert!(journal.lookup("stop").is_some());
    }
    /// A graceful server shutdown closes a registered session with 1001
    /// (going away): the client reconnects and keeps serving instead of
    /// stranding the host until its leases settle.
    #[test]
    fn server_going_away_reconnects_a_registered_session() {
        use std::net::TcpListener;
        use tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};
        let dir = tempfile::tempdir().expect("dir");
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let address = listener.local_addr().expect("address");
        let options = ConnectOptions {
            host_terminal: None,
            server_url: format!("ws://{address}"),
            host_token: "test-only-token".into(),
            host_id: "host".into(),
            label: "test".into(),
            runtime: HostRuntimeKind::Fake,
            incus_project: None,
            state_dir: Some(dir.path().into()),
            heartbeat: Duration::from_secs(5),
            sandbox_memory_mib: None,
            max_sandbox_cpu_count: None,
            sandbox_vcpu_budget: Some(4),
            max_concurrent_commands: 16,
            shutdown: Default::default(),
        };
        let fake = sandbox_runtime::FakeRuntime::new();
        fake.create_fixture(&sandbox_runtime::CreateSandboxRequest::for_test(
            "sbx", "create",
        ))
        .unwrap();
        {
            let binding = TransportBindingV11 {
                server: format!("ws://{address}/ws/sandbox-host"),
                host_owner_id: "owner-1".into(),
                host_id: "host".into(),
            };
            let journal =
                crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                    .unwrap();
            let d: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":"create", "sandboxId":"sbx", "kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(), "cpuCount": 1, "memoryMiB": 1024, "generation":1, "attempt":1, "idempotencyKey":"create", "bodyHash":"a".repeat(64), "lease":sandbox_protocol::HostLease::for_test()})).unwrap();
            journal
                .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
                .unwrap();
            journal.accept_fixture_lease(&d).unwrap();
            journal
                .record_result(
                    "create",
                    OperationState::Succeeded,
                    Some(json!({"state":"ready","lease":d.lease})),
                    None,
                    None,
                )
                .unwrap();
        }
        let daemon_fake = fake.clone();
        let shutdown = options.shutdown.clone();
        let client = thread::spawn(move || {
            run_connect_with(&options, |_| Ok((Box::new(daemon_fake), None)))
        });
        fn register(wire: &mut tungstenite::WebSocket<std::net::TcpStream>) {
            crate::sandbox_relay::test_support::send_ready_hello_value(
                wire,
                serde_json::from_str(include_str!(
                    "../../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
                ))
                .unwrap(),
                "host",
            );
            crate::sandbox_relay::test_support::ack_reconciliation(wire);
        }
        let (tcp, _) = listener.accept().expect("accept");
        tcp.set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake).expect("handshake");
        wire.read().expect("hello");
        register(&mut wire);
        let dropped = Instant::now();
        // Server going away on a registered session: reconnect, not exit.
        wire.close(Some(CloseFrame {
            code: CloseCode::Away,
            reason: "server_shutdown".into(),
        }))
        .expect("close");
        drop(wire);
        let (tcp, _) = listener.accept().expect("reconnect after going away");
        assert!(
            dropped.elapsed() < Duration::from_secs(10),
            "a 1001 close is retryable, not a clean exit"
        );
        tcp.set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake).expect("handshake");
        wire.read().expect("hello");
        register(&mut wire);
        shutdown.request();
        client.join().expect("client").expect("clean exit");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shutdown_revokes_startup_io_and_reaps_the_inflight_child() {
        let dir = tempfile::tempdir().unwrap();
        let shim = dir.path().join("incus");
        let started = dir.path().join("started");
        crate::sandbox_relay::test_support::install_executable(
            &shim,
            format!(
                "#!/bin/sh\nprintf '%s' \"$$\" > '{}'\nexec sleep 30\n",
                started.display()
            ),
            0o700,
        );
        let mut client =
            sandbox_runtime::IncusClient::new(shim.to_string_lossy().into_owned(), "default");
        let shutdown = ShutdownSignal::default();
        let guard = RuntimeIoGuard::census(&shutdown).unwrap();
        client.cancelled = Some(guard.permit.clone());
        let (tx, rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            tx.send(client.host_resources()).unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(3);
        while !started.exists() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        let pid = std::fs::read_to_string(started).unwrap();
        shutdown.request();
        assert!(
            rx.recv_timeout(Duration::from_secs(2))
                .expect("shutdown interrupts census IO")
                .is_err()
        );
        worker.join().unwrap();
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "owned child must be reaped"
        );
    }

    /// A first-connect failure (redirect, refusal) fails fast: the operator's
    /// command line must not hang in a reconnect loop. Only after a session
    /// existed does a dropped server earn retries.
    #[test]
    fn first_connect_failure_is_terminal_not_retried() {
        let dir = tempfile::tempdir().expect("dir");
        // Reserve a port, then drop it: nothing is listening.
        let address = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind")
            .local_addr()
            .expect("address");
        let options = ConnectOptions {
            host_terminal: None,
            server_url: format!("ws://{address}"),
            host_token: "test-only-token".into(),
            host_id: "host".into(),
            label: "test".into(),
            runtime: HostRuntimeKind::Fake,
            incus_project: None,
            state_dir: Some(dir.path().into()),
            heartbeat: Duration::from_secs(5),
            sandbox_memory_mib: None,
            max_sandbox_cpu_count: None,
            sandbox_vcpu_budget: Some(4),
            max_concurrent_commands: 16,
            shutdown: Default::default(),
        };
        let started = Instant::now();
        let error = run_connect_with(&options, |_| {
            Ok((Box::new(sandbox_runtime::FakeRuntime::new()), None))
        })
        .expect_err("first connect fails");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "first connect failure must not enter the reconnect loop"
        );
        assert!(format!("{error:#}").contains("websocket connect failed"));
    }

    /// A startup census still registers when ACL writer contention outlasts
    /// the old 30 s aggregate census deadline.
    #[test]
    #[ignore = "slow (31 s): run with --ignored in CI"]
    fn census_registers_after_more_than_thirty_seconds_of_acl_writer_contention() {
        use std::net::TcpListener;
        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        // Model five ACL owners contending with startup inventory. The first
        // writer holds its lane past the old aggregate census deadline; work
        // still makes progress, and a fresh scope must reach hello/registration.
        let locks: Vec<_> = (0..5)
            .map(|_| Arc::new(std::sync::Mutex::new(())))
            .collect();
        let writer_locks = locks.clone();
        let (ready, waiting) = mpsc::channel();
        let writer = thread::spawn(move || {
            let _guards: Vec<_> = writer_locks
                .iter()
                .map(|lock| lock.lock().unwrap())
                .collect();
            ready.send(()).unwrap();
            thread::sleep(Duration::from_secs(31));
        });
        waiting.recv_timeout(Duration::from_secs(2)).unwrap();
        let fake = sandbox_runtime::FakeRuntime::new().with_inventory_hook(move |_| {
            for lock in &locks {
                drop(lock.lock().unwrap());
            }
            Ok(())
        });
        let shutdown = ShutdownSignal::default();
        let options = ConnectOptions {
            server_url: format!("ws://{address}"),
            host_token: "test-only-token".into(),
            host_id: "host".into(),
            label: "test".into(),
            runtime: HostRuntimeKind::Fake,
            incus_project: None,
            state_dir: Some(dir.path().into()),
            heartbeat: Duration::from_secs(5),
            sandbox_memory_mib: None,
            max_sandbox_cpu_count: None,
            sandbox_vcpu_budget: Some(4),
            max_concurrent_commands: 16,
            shutdown: shutdown.clone(),
            host_terminal: None,
        };
        let began = Instant::now();
        let client =
            thread::spawn(move || run_connect_with(&options, |_| Ok((Box::new(fake), None))));
        let registered: Result<()> = (|| {
            let deadline = Instant::now() + Duration::from_secs(50);
            let tcp = loop {
                match listener.accept() {
                    Ok((tcp, _)) => break tcp,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        anyhow::ensure!(Instant::now() < deadline, "census never registered");
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            tcp.set_read_timeout(Some(Duration::from_secs(3)))?;
            let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake)?;
            wire.read()?;
            wire.send(Message::Text(
                include_str!(
                    "../../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
                )
                .into(),
            ))?;
            crate::sandbox_relay::test_support::ack_registration(&mut wire);
            shutdown.request();
            Ok(())
        })();
        shutdown.request();
        writer.join().unwrap();
        let result = client.join().unwrap();
        registered.expect("registration after a progressing census");
        result.expect("shutdown joined the daemon");
        assert!(began.elapsed() > Duration::from_secs(30));
    }

    /// The hello handler's admission inventory
    /// blocks on the host daemon (here: until the node has received the
    /// blocklist, or 5 s). A blocklist the server sends right after
    /// `hello.ok` is applied (persisted by the node egress state) while that
    /// inventory is still running, not after it and reconciliation.
    #[test]
    fn a_blocklist_reaches_the_guard_while_the_hello_inventory_runs() {
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        const BLOCKLIST_FRAME: &str = r#"{"type":"egress.blocklist","configured":false,"entries":[],"digest":"sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"}"#;
        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stored = dir
            .path()
            .join(super::super::egress_state::DEPLOYMENT_BLOCKLIST_FILE);
        let armed = Arc::new(AtomicBool::new(false));
        // The first inventory after hello: whether the list was applied
        // before it returned.
        let first = Arc::new(std::sync::Mutex::new(None::<bool>));
        let (hook_armed, hook_first, hook_stored) = (armed.clone(), first.clone(), stored.clone());
        let fake = sandbox_runtime::FakeRuntime::new().with_inventory_hook(move |_| {
            if !hook_armed.load(Ordering::Acquire) {
                return Ok(());
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            while !hook_stored.exists() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            hook_first
                .lock()
                .unwrap()
                .get_or_insert(hook_stored.exists());
            Ok(())
        });
        let shutdown = ShutdownSignal::default();
        let options = ConnectOptions {
            server_url: format!("ws://{address}"),
            host_token: "test-only-token".into(),
            host_id: "host".into(),
            label: "test".into(),
            runtime: HostRuntimeKind::Fake,
            incus_project: None,
            state_dir: Some(dir.path().into()),
            heartbeat: Duration::from_secs(5),
            sandbox_memory_mib: None,
            max_sandbox_cpu_count: None,
            sandbox_vcpu_budget: Some(4),
            max_concurrent_commands: 16,
            shutdown: shutdown.clone(),
            host_terminal: None,
        };
        let client =
            thread::spawn(move || run_connect_with(&options, |_| Ok((Box::new(fake), None))));
        let registered: Result<()> = (|| {
            let deadline = Instant::now() + Duration::from_secs(20);
            let tcp = loop {
                match listener.accept() {
                    Ok((tcp, _)) => break tcp,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        anyhow::ensure!(Instant::now() < deadline, "never connected");
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
            let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake)?;
            wire.read()?;
            armed.store(true, Ordering::Release);
            wire.send(Message::Text(
                include_str!(
                    "../../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
                )
                .into(),
            ))?;
            wire.send(Message::Text(BLOCKLIST_FRAME.into()))?;
            crate::sandbox_relay::test_support::ack_registration(&mut wire);
            shutdown.request();
            Ok(())
        })();
        shutdown.request();
        let result = client.join().unwrap();
        registered.expect("registration");
        result.expect("shutdown joined the daemon");
        assert_eq!(
            *first.lock().unwrap(),
            Some(true),
            "the blocklist was applied while the hello inventory ran"
        );
    }

    /// A transport loss while the hello
    /// inventory blocks on the host daemon ends the session at once (the
    /// obsolete worker is fenced, not awaited), the reconnect dials without
    /// a synchronous census, and the blocklist the restarted server sends
    /// reaches the guard while the old inventory is still running.
    #[test]
    fn a_transport_loss_mid_inventory_reconnects_and_applies_the_blocklist_first() {
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        const BLOCKLIST_FRAME: &str = r#"{"type":"egress.blocklist","configured":false,"entries":[],"digest":"sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"}"#;
        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stored = dir
            .path()
            .join(super::super::egress_state::DEPLOYMENT_BLOCKLIST_FILE);
        let armed = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        // 0: no armed call yet; 1: the old inventory is held; 2: it returned.
        let old_inventory = Arc::new(AtomicUsize::new(0));
        let (hook_armed, hook_release, hook_old) =
            (armed.clone(), release.clone(), old_inventory.clone());
        let fake = sandbox_runtime::FakeRuntime::new().with_inventory_hook(move |_| {
            if !hook_armed.load(Ordering::Acquire)
                || hook_old
                    .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
            {
                return Ok(());
            }
            // Held until the test releases it (or 30 s, so a regression
            // fails the assertions below instead of hanging).
            let deadline = Instant::now() + Duration::from_secs(30);
            while !hook_release.load(Ordering::Acquire) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            hook_old.store(2, Ordering::Release);
            Ok(())
        });
        let shutdown = ShutdownSignal::default();
        let options = ConnectOptions {
            server_url: format!("ws://{address}"),
            host_token: "test-only-token".into(),
            host_id: "host".into(),
            label: "test".into(),
            runtime: HostRuntimeKind::Fake,
            incus_project: None,
            state_dir: Some(dir.path().into()),
            heartbeat: Duration::from_secs(5),
            sandbox_memory_mib: None,
            max_sandbox_cpu_count: None,
            sandbox_vcpu_budget: Some(4),
            max_concurrent_commands: 16,
            shutdown: shutdown.clone(),
            host_terminal: None,
        };
        let client =
            thread::spawn(move || run_connect_with(&options, |_| Ok((Box::new(fake), None))));
        let accept = |within: Duration| -> Result<tungstenite::WebSocket<std::net::TcpStream>> {
            let deadline = Instant::now() + within;
            let tcp = loop {
                match listener.accept() {
                    Ok((tcp, _)) => break tcp,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        anyhow::ensure!(Instant::now() < deadline, "never connected");
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => return Err(error.into()),
                }
            };
            tcp.set_nonblocking(false)?;
            tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
            Ok(tungstenite::accept_hdr(tcp, RelayHandshake)?)
        };
        let hello_ok = include_str!(
            "../../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
        );
        let outcome: Result<()> = (|| {
            let mut first = accept(Duration::from_secs(20))?;
            first.read()?;
            armed.store(true, Ordering::Release);
            first.send(Message::Text(hello_ok.into()))?;
            let deadline = Instant::now() + Duration::from_secs(10);
            while old_inventory.load(Ordering::Acquire) != 1 {
                anyhow::ensure!(Instant::now() < deadline, "the hello inventory never ran");
                thread::sleep(Duration::from_millis(10));
            }
            // The server goes away (restart) while the inventory is held.
            drop(first);
            let mut second = accept(Duration::from_secs(5))?;
            anyhow::ensure!(
                old_inventory.load(Ordering::Acquire) == 1,
                "the reconnect waited for the old inventory"
            );
            second.read()?;
            second.send(Message::Text(hello_ok.into()))?;
            second.send(Message::Text(BLOCKLIST_FRAME.into()))?;
            let deadline = Instant::now() + Duration::from_secs(5);
            while !stored.exists() {
                anyhow::ensure!(
                    Instant::now() < deadline,
                    "the new session's blocklist never reached the guard"
                );
                thread::sleep(Duration::from_millis(10));
            }
            anyhow::ensure!(
                old_inventory.load(Ordering::Acquire) == 1,
                "the blocklist waited for the old inventory"
            );
            release.store(true, Ordering::Release);
            crate::sandbox_relay::test_support::ack_registration(&mut second);
            shutdown.request();
            Ok(())
        })();
        release.store(true, Ordering::Release);
        shutdown.request();
        let result = client.join().unwrap();
        outcome.expect("reconnect and blocklist before the old inventory finished");
        result.expect("shutdown joined the daemon");
    }

    /// Once a session existed, a connect failure (the server is still
    /// restarting after going away) is retryable: the client rides out the
    /// refusal and completes a later session.
    #[test]
    fn connect_and_census_refusals_after_a_session_retry_until_recovery() {
        use std::net::TcpListener;
        use tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};
        let dir = tempfile::tempdir().expect("dir");
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let address = listener.local_addr().expect("address");
        let options = ConnectOptions {
            host_terminal: None,
            server_url: format!("ws://{address}"),
            host_token: "test-only-token".into(),
            host_id: "host".into(),
            label: "test".into(),
            runtime: HostRuntimeKind::Fake,
            incus_project: None,
            state_dir: Some(dir.path().into()),
            heartbeat: Duration::from_secs(5),
            sandbox_memory_mib: None,
            max_sandbox_cpu_count: None,
            sandbox_vcpu_budget: Some(4),
            max_concurrent_commands: 16,
            shutdown: Default::default(),
        };
        let census_failures = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let failures = census_failures.clone();
        let fake = sandbox_runtime::FakeRuntime::new().with_inventory_hook(move |_| {
            if failures
                .try_update(
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                    |left| left.checked_sub(1),
                )
                .is_ok()
            {
                return Err(sandbox_runtime::RuntimeError::new(
                    SandboxErrorCode::Internal,
                    "DNS startup recovery failed closed: transient ACL drift",
                ));
            }
            Ok(())
        });
        fake.create_fixture(&sandbox_runtime::CreateSandboxRequest::for_test(
            "sbx", "create",
        ))
        .unwrap();
        {
            let binding = TransportBindingV11 {
                server: format!("ws://{address}/ws/sandbox-host"),
                host_owner_id: "owner-1".into(),
                host_id: "host".into(),
            };
            let journal =
                crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                    .unwrap();
            let d: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":"create", "sandboxId":"sbx", "kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(), "cpuCount": 1, "memoryMiB": 1024, "generation":1, "attempt":1, "idempotencyKey":"create", "bodyHash":"a".repeat(64), "lease":sandbox_protocol::HostLease::for_test()})).unwrap();
            journal
                .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
                .unwrap();
            journal.accept_fixture_lease(&d).unwrap();
            journal
                .record_result(
                    "create",
                    OperationState::Succeeded,
                    Some(json!({"state":"ready","lease":d.lease})),
                    None,
                    None,
                )
                .unwrap();
        }
        let daemon_fake = fake.clone();
        let shutdown = options.shutdown.clone();
        let exited = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let exited2 = exited.clone();
        let client = thread::spawn(move || {
            let result = run_connect_with(&options, |_| Ok((Box::new(daemon_fake), None)));
            exited2.store(true, std::sync::atomic::Ordering::SeqCst);
            result
        });
        let (tcp, _) = listener.accept().expect("accept");
        tcp.set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake).expect("handshake");
        wire.read().expect("hello");
        crate::sandbox_relay::test_support::send_ready_hello_value(
            &mut wire,
            serde_json::from_str(include_str!(
                "../../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
            ))
            .unwrap(),
            "host",
        );
        crate::sandbox_relay::test_support::ack_registration(&mut wire);
        census_failures.store(3, std::sync::atomic::Ordering::SeqCst);
        wire.close(Some(CloseFrame {
            code: CloseCode::Away,
            reason: "server_shutdown".into(),
        }))
        .expect("close");
        drop(wire);
        // The server is gone entirely: reconnect attempts hit refusal.
        drop(listener);
        thread::sleep(Duration::from_millis(600));
        assert!(
            !exited.load(std::sync::atomic::Ordering::SeqCst),
            "post-session connect refusal is retryable, not terminal"
        );
        // The server comes back; the client reconnects and exits cleanly.
        let listener = {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match TcpListener::bind(address) {
                    Ok(listener) => break listener,
                    Err(_) => {
                        assert!(Instant::now() < deadline, "rebind the server port");
                        thread::sleep(Duration::from_millis(20));
                    }
                }
            }
        };
        listener.set_nonblocking(true).unwrap();
        // A reconnect dials before its census (the census runs
        // after `hello.ok`), so each refused census ends a registered-less
        // session and the daemon dials again, until the census recovers.
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut wire = loop {
            let tcp = match listener.accept() {
                Ok((tcp, _)) => tcp,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "census refusal stranded reconnect"
                    );
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(error) => panic!("accept: {error}"),
            };
            tcp.set_nonblocking(false).expect("blocking");
            tcp.set_read_timeout(Some(Duration::from_secs(3)))
                .expect("timeout");
            let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake).expect("handshake");
            wire.read().expect("hello");
            // Only this daemon's census consumes refusals, after hello.ok.
            let refused = census_failures.load(std::sync::atomic::Ordering::SeqCst) > 0;
            crate::sandbox_relay::test_support::send_ready_hello_value(
                &mut wire,
                serde_json::from_str(include_str!(
                    "../../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
                ))
                .unwrap(),
                "host",
            );
            if !refused {
                break wire;
            }
            // The refused census ends this session before any admission.
            loop {
                match wire.read() {
                    Ok(Message::Text(text)) => assert!(
                        !text.contains("host.admission"),
                        "admission before a successful census: {text}"
                    ),
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        };
        assert_eq!(census_failures.load(std::sync::atomic::Ordering::SeqCst), 0);
        crate::sandbox_relay::test_support::ack_registration(&mut wire);
        // Only a local shutdown ends the process (P0-1).
        shutdown.request();
        client.join().expect("client").expect("clean exit");
    }

    #[test]
    fn reconciliation_pruned_ack_retires_exact_tombstone() {
        reconciliation_with_tombstone();
    }

    fn reconciliation_with_tombstone() {
        let version = sandbox_protocol::SANDBOX_RELAY_PROTOCOL_VERSION;
        use std::net::TcpListener;
        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let binding = TransportBindingV11 {
            server: format!("ws://{address}/ws/sandbox-host"),
            host_owner_id: "owner-1".into(),
            host_id: "host".into(),
        };
        {
            let journal =
                crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                    .unwrap();
            let d: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
                "operationId":"pruned", "sandboxId":"sbx", "kind":"command.run", "resultVersion":1, "processId":"proc-pruned",
                "generation":1, "attempt":1, "idempotencyKey":"key", "bodyHash":"a".repeat(64)
            }))
            .unwrap();
            journal
                .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
                .unwrap();
            journal
                .record_result("pruned", OperationState::Succeeded, None, None, None)
                .unwrap();
            journal.seed_pruned_receipt_for_test("pruned");
            let normal = OperationDispatch {
                cpu_count: None,
                memory_mi_b: None,
                operation_id: "normal".into(),
                sandbox_id: "other".into(),
                idempotency_key: "normal".into(),
                ..d
            };
            journal
                .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &normal))
                .unwrap();
            journal
                .record_result("normal", OperationState::Succeeded, None, None, None)
                .unwrap();
            for id in ["kill", "stop"] {
                let create: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
                    "operationId":format!("create-{id}"), "sandboxId":id, "kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(), "cpuCount": 1, "memoryMiB": 1024,
                    "generation":1, "attempt":1, "idempotencyKey":format!("create-{id}"),
                    "bodyHash":"b".repeat(64), "lease":sandbox_protocol::HostLease::for_test()
                }))
                .unwrap();
                journal
                    .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &create))
                    .unwrap();
                journal.accept_fixture_lease(&create).unwrap();
                journal
                    .record_result(
                        &create.operation_id,
                        OperationState::Succeeded,
                        Some(json!({"state":"ready", "lease":create.lease})),
                        None,
                        None,
                    )
                    .unwrap();
            }
        }
        let options = ConnectOptions {
            host_terminal: None,
            server_url: format!("ws://{address}"),
            host_token: "test-only-token".into(),
            host_id: "host".into(),
            label: "test".into(),
            runtime: HostRuntimeKind::Fake,
            incus_project: None,
            state_dir: Some(dir.path().into()),
            heartbeat: Duration::from_secs(5),
            sandbox_memory_mib: None,
            max_sandbox_cpu_count: None,
            sandbox_vcpu_budget: Some(4),
            max_concurrent_commands: 16,
            shutdown: Default::default(),
        };
        let fake = sandbox_runtime::FakeRuntime::new();
        for id in ["kill", "stop"] {
            fake.create_fixture(&sandbox_runtime::CreateSandboxRequest::for_test(id, id))
                .unwrap();
        }
        let daemon_runtime = fake.clone();
        let shutdown = options.shutdown.clone();
        let client = thread::spawn(move || {
            run_connect_with(&options, |_| Ok((Box::new(daemon_runtime), None)))
        });
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let (tcp, _) = loop {
            match listener.accept() {
                Ok(pair) => break pair,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    if client.is_finished() {
                        panic!("client exited before handshake: {:?}", client.join());
                    }
                    assert!(Instant::now() < deadline, "client did not connect");
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept: {error}"),
            }
        };
        tcp.set_nonblocking(false).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake).unwrap();
        wire.read().unwrap();
        let mut hello: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
        ))
        .unwrap();
        hello["protocolVersion"] = json!(version);
        hello["capabilities"]["protocolVersion"] = json!(version);
        hello["supportedProtocolVersions"] = json!([version]);
        if sandbox_protocol::known_protocol_version(version) {
            hello["connectionEpoch"] = json!(1);
        } else {
            hello.as_object_mut().unwrap().remove("connectionEpoch");
        }
        wire.send(Message::Text(hello.to_string().into())).unwrap();
        let mut reports = 0;
        let mut normal_reports = 0;
        loop {
            let frame = wire.read().unwrap();
            let Ok(text) = frame.to_text() else { continue };
            let frame: serde_json::Value = serde_json::from_str(text).unwrap();
            match frame["type"].as_str().unwrap() {
                "operation.receipt.pruned" => {
                    assert_eq!(version, "1.0", "current peer receives pruned receipts");
                    reports += 1;
                    assert_eq!(frame["operationId"], "pruned");
                    assert!(frame.get("bodyHash").is_none());
                    let mut ack = frame;
                    ack["type"] = json!("receipt.pruned.ack");
                    ack["connectionEpoch"] = json!(1);
                    wire.send(Message::Text(ack.to_string().into())).unwrap();
                    wire.send(Message::Text(
                        json!({"type":"receipt.ack", "operationId":"pruned"})
                            .to_string()
                            .into(),
                    ))
                    .unwrap();
                }
                "operation.receipt" => {
                    assert!(
                        ["normal", "create-kill", "create-stop"]
                            .contains(&frame["operationId"].as_str().unwrap())
                    );
                    normal_reports += 1;
                    wire.send(Message::Text(
                        json!({"type":"receipt.ack", "operationId":frame["operationId"]})
                            .to_string()
                            .into(),
                    ))
                    .unwrap();
                }
                "sandbox.inventory" => wire
                    .send(Message::Text(
                        json!({"type":"inventory.ack", "page":frame["page"], "entryResults":frame["entries"].as_array().unwrap().iter().map(|entry| json!({"sandboxId":entry["sandboxId"],"outcome":"converged"})).collect::<Vec<_>>()})
                            .to_string()
                            .into(),
                    ))
                    .unwrap(),
                "reconcile.complete" => break,
                _ => {}
            }
        }
        assert_eq!(reports, 1);
        assert_eq!(normal_reports, 3, "ordinary receipts still reconcile");
        // Exact cleanup operations remain usable without a journal key.
        for (kind, id) in [("sandbox.kill", "kill"), ("sandbox.stop", "stop")] {
            wire.send(Message::Text(
                json!({"sandboxOwnerId":"owner", "type":"operation.dispatch", "operationId":id, "sandboxId":id,
                "kind":kind, "generation":2, "attempt":1, "idempotencyKey":id,
                "bodyHash":"a".repeat(64), "digestScheme":"sha256-env-free-v1", "allocation": crate::sandbox_relay::test_support::allocation()})
                .to_string().into(),
            )).unwrap();
            loop {
                let frame = wire.read().unwrap();
                let Ok(text) = frame.to_text() else { continue };
                match sandbox_protocol::parse_daemon_control(text).unwrap() {
                    DaemonControlMessage::OperationReceiptPruned { .. } => {
                        panic!("unexpected pruned frame")
                    }
                    DaemonControlMessage::OperationResult {
                        operation_id,
                        state,
                        result,
                        ..
                    } if operation_id == id => {
                        assert_eq!(state, OperationState::Succeeded, "{text}");
                        assert_eq!(
                            result.unwrap()["state"],
                            if kind == "sandbox.kill" {
                                "deleted"
                            } else {
                                "stopped"
                            }
                        );
                        break;
                    }
                    _ => {}
                }
            }
        }
        shutdown.request();
        client.join().unwrap().unwrap();
        // Assert the durable receipt file directly; the retained fake runtime
        // can still own completion permits while this fixture unwinds.
        let path = dir.path().join("receipts/pruned.json");
        assert!(!path.exists());
        assert_eq!(
            fake.sandbox_inventory()
                .unwrap()
                .into_iter()
                .map(|entry| (entry.sandbox_id, entry.state))
                .collect::<Vec<_>>(),
            vec![(
                "stop".into(),
                sandbox_protocol::SandboxLifecycleState::Stopped
            )]
        );
    }

    /// A close frame that arrives while the client awaits a reconciliation
    /// acknowledgement keeps its classification end to end: 4003 terminates
    /// with CredentialInactive, and every other close (1001, 1000, None)
    /// reconnects (P0-1); only a local shutdown then ends the process.
    #[test]
    fn close_during_reconciliation_keeps_its_outcome() {
        use std::net::TcpListener;
        use tungstenite::protocol::{CloseFrame, frame::coding::CloseCode};
        for variant in ["credential", "going-away", "clean", "clean-no-code"] {
            let dir = tempfile::tempdir().expect("dir");
            let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
            let address = listener.local_addr().expect("address");
            let options = ConnectOptions {
                host_terminal: None,
                server_url: format!("ws://{address}"),
                host_token: "test-only-token".into(),
                host_id: "host".into(),
                label: "test".into(),
                runtime: HostRuntimeKind::Fake,
                incus_project: None,
                state_dir: Some(dir.path().into()),
                heartbeat: Duration::from_secs(5),
                sandbox_memory_mib: None,
                max_sandbox_cpu_count: None,
                sandbox_vcpu_budget: Some(4),
                max_concurrent_commands: 16,
                shutdown: Default::default(),
            };
            let fake = sandbox_runtime::FakeRuntime::new();
            fake.create_fixture(&sandbox_runtime::CreateSandboxRequest::for_test(
                "sbx", "create",
            ))
            .unwrap();
            {
                let binding = TransportBindingV11 {
                    server: format!("ws://{address}/ws/sandbox-host"),
                    host_owner_id: "owner-1".into(),
                    host_id: "host".into(),
                };
                let journal =
                    crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                        .unwrap();
                let d: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":"create", "sandboxId":"sbx", "kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(), "cpuCount": 1, "memoryMiB": 1024, "generation":1, "attempt":1, "idempotencyKey":"create", "bodyHash":"a".repeat(64), "lease":sandbox_protocol::HostLease::for_test()})).unwrap();
                journal
                    .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
                    .unwrap();
                journal.accept_fixture_lease(&d).unwrap();
                journal
                    .record_result(
                        "create",
                        OperationState::Succeeded,
                        Some(json!({"state":"ready","lease":d.lease})),
                        None,
                        None,
                    )
                    .unwrap();
            }
            let daemon_fake = fake.clone();
            let shutdown = options.shutdown.clone();
            let client = thread::spawn(move || {
                run_connect_with(&options, |_| Ok((Box::new(daemon_fake), None)))
            });
            let (accepted_tx, accepted_rx) = mpsc::channel();
            let (stop_tx, stop_rx) = mpsc::channel::<()>();
            listener.set_nonblocking(true).expect("nonblocking");
            let acceptor = thread::spawn(move || {
                loop {
                    match listener.accept() {
                        Ok(pair) => {
                            if accepted_tx.send(pair).is_err() {
                                return;
                            }
                        }
                        Err(_) => {
                            if stop_rx.try_recv().is_ok() {
                                return;
                            }
                            thread::sleep(Duration::from_millis(5));
                        }
                    }
                }
            });
            let (tcp, _) = accepted_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("accept");
            tcp.set_read_timeout(Some(Duration::from_secs(3)))
                .expect("timeout");
            let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake).expect("handshake");
            wire.read().expect("hello");
            crate::sandbox_relay::test_support::send_ready_hello_value(
                &mut wire,
                serde_json::from_str(include_str!(
                    "../../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
                ))
                .unwrap(),
                "host",
            );
            // Wait for the actual receipt; key acknowledgements and host
            // reports may arrive before this reconciliation phase.
            loop {
                let frame = wire.read().expect("receipt frame");
                if let Ok(text) = frame.to_text()
                    && matches!(
                        sandbox_protocol::parse_daemon_control(text).unwrap(),
                        DaemonControlMessage::OperationReceipt { .. }
                    )
                {
                    break;
                }
            }
            let frame = match variant {
                "credential" => Some(CloseFrame {
                    code: CloseCode::Library(4003),
                    reason: "credential_inactive".into(),
                }),
                "going-away" => Some(CloseFrame {
                    code: CloseCode::Away,
                    reason: "server_shutdown".into(),
                }),
                "clean" => Some(CloseFrame {
                    code: CloseCode::Normal,
                    reason: "bye".into(),
                }),
                _ => None,
            };
            wire.close(frame).expect("close");
            drop(wire);
            if variant != "credential" {
                // Any close but 4003 during reconciliation is retryable: the
                // host reconnects.
                let (tcp, _) = accepted_rx
                    .recv_timeout(Duration::from_secs(10))
                    .expect("reconnect after a server close");
                tcp.set_read_timeout(Some(Duration::from_secs(3)))
                    .expect("timeout");
                let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake).expect("handshake");
                wire.read().expect("hello");
                crate::sandbox_relay::test_support::send_ready_hello_value(
                    &mut wire,
                    serde_json::from_str(include_str!(
                        "../../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
                    ))
                    .unwrap(),
                    "host",
                );
                crate::sandbox_relay::test_support::ack_registration(&mut wire);
                // Only a local shutdown ends the process.
                shutdown.request();
                client.join().expect("client").expect("clean exit");
            } else {
                // 4003 terminates; it never reconnects.
                assert!(
                    accepted_rx.recv_timeout(Duration::from_secs(2)).is_err(),
                    "{variant}: no reconnection follows a terminal close"
                );
                fake.stop_sandbox(&sandbox_runtime::StopSandboxRequest {
                    template_fingerprint: sandbox_runtime::CreateSandboxRequest::for_test(
                        "sbx", "create",
                    )
                    .template_digest,
                    sandbox_id: "sbx".into(),
                    instance_name: "wssp-sbx-sbx".into(),
                    operation_id: "stop".into(),
                    idempotency_key: "stop".into(),
                })
                .unwrap();
                let error = client
                    .join()
                    .expect("client")
                    .expect_err("credential close terminates");
                assert_eq!(
                    crate::exit::code_for(&error),
                    ExitCode::CredentialInactive,
                    "4003 during reconciliation is terminal"
                );
            }
            drop(accepted_rx);
            let _ = stop_tx.send(());
            acceptor.join().expect("acceptor");
        }
    }

    /// C25: a cancellation that arrives after the terminal receipt is durable
    /// but before the output window drains must not publish the receipt ahead
    /// of the retained frames. The receipt goes through the same drain owner
    /// as an uncancelled completion.
    #[cfg(unix)]
    #[test]
    fn cancelled_command_completion_publishes_only_after_output_drains() {
        use sandbox_protocol::parse_daemon_control;
        use std::net::TcpListener;
        let dir = tempfile::tempdir().expect("dir");
        let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
        let address = listener.local_addr().expect("address");
        let options = ConnectOptions {
            host_terminal: None,
            server_url: format!("ws://{address}"),
            host_token: "test-only-token".into(),
            host_id: "host".into(),
            label: "test".into(),
            runtime: HostRuntimeKind::Fake,
            incus_project: None,
            state_dir: Some(dir.path().into()),
            heartbeat: Duration::from_millis(30),
            sandbox_memory_mib: None,
            max_sandbox_cpu_count: None,
            sandbox_vcpu_budget: Some(4),
            max_concurrent_commands: 16,
            shutdown: Default::default(),
        };
        let fake = sandbox_runtime::FakeRuntime::with_command_delay(Duration::ZERO);
        fake.create_fixture(&sandbox_runtime::CreateSandboxRequest::for_test(
            "sbx", "create",
        ))
        .unwrap();
        {
            let binding = TransportBindingV11 {
                server: format!("ws://{address}/ws/sandbox-host"),
                host_owner_id: "owner-1".into(),
                host_id: "host".into(),
            };
            let journal =
                crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                    .unwrap();
            let d: OperationDispatch=serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":"create", "sandboxId":"sbx", "kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(), "cpuCount": 1, "memoryMiB": 1024, "generation":1, "attempt":1, "idempotencyKey":"create", "bodyHash":"a".repeat(64), "lease":sandbox_protocol::HostLease::for_test()})).unwrap();
            journal
                .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
                .unwrap();
            journal.accept_fixture_lease(&d).unwrap();
            journal
                .record_result(
                    "create",
                    OperationState::Succeeded,
                    Some(json!({"state":"ready","lease":d.lease})),
                    None,
                    None,
                )
                .unwrap();
        }
        let daemon_fake = fake.clone();
        let shutdown = options.shutdown.clone();
        let client = thread::spawn(move || {
            run_connect_with(&options, |_| Ok((Box::new(daemon_fake), None)))
        });
        let (tcp, _) = listener.accept().expect("accept");
        tcp.set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        let mut wire = tungstenite::accept_hdr(tcp, RelayHandshake).expect("handshake");
        wire.read().expect("hello");
        crate::sandbox_relay::test_support::send_ready_hello_value(
            &mut wire,
            serde_json::from_str(include_str!(
                "../../../../crates/sandbox-protocol/fixtures/control_hello_ok_server.json"
            ))
            .unwrap(),
            "host",
        );
        crate::sandbox_relay::test_support::ack_registration(&mut wire);
        wire.send(Message::Text(crate::sandbox_relay::test_support::current_control_fixture(json!({"sandboxOwnerId":"owner", "type":"operation.dispatch", "operationId":"cmd", "sandboxId":"sbx", "kind":"command.run", "resultVersion":1, "processId":"proc-cmd", "incusFingerprint":sandbox_runtime::CreateSandboxRequest::for_test("sbx", "key").template_digest, "generation":1, "attempt":1, "idempotencyKey":"cmd", "bodyHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "argv":["true"]})).to_string().into())).expect("dispatch");
        // Wait for the first output frame but withhold its ACK; with a zero
        // command delay the terminal receipt is durable well before the cancel.
        let mut held = None;
        let wait = Instant::now();
        while held.is_none() {
            match wire.read().expect("frame") {
                Message::Binary(data) => {
                    let (metadata, body) = parse_binary_frame(&data).expect("binary output");
                    held = Some((metadata, body));
                }
                Message::Text(text) => match parse_daemon_control(&text).expect("control") {
                    DaemonControlMessage::Heartbeat { .. }
                    | DaemonControlMessage::OperationProgress { .. } => {}
                    // The 5 s egress lease renewal (§2.5) may interleave.
                    DaemonControlMessage::HostEgressState(_) => {}
                    other => panic!("unexpected {other:?} before output"),
                },
                _ => {}
            }
            assert!(wait.elapsed() < Duration::from_secs(3), "no output frame");
        }
        let (metadata, body) = held.expect("frame");
        thread::sleep(Duration::from_millis(300));
        wire.send(Message::Text(json!({"type":"operation.cancel", "operationId":metadata.operation_id, "generation":metadata.generation, "attempt":metadata.attempt, "reason":"cancelled"}).to_string().into())).unwrap();
        // The window is undrained: no result or receipt may publish yet, even
        // though the cancel arrived after the receipt was persisted.
        let silence = Instant::now();
        while silence.elapsed() < Duration::from_millis(400) {
            match wire.read().expect("frame") {
                Message::Text(text) => match parse_daemon_control(&text).expect("control") {
                    DaemonControlMessage::Heartbeat { .. }
                    | DaemonControlMessage::OperationProgress { .. }
                    | DaemonControlMessage::ProcessStarted { .. } => {}
                    other => panic!("completion published before output drained: {other:?}"),
                },
                Message::Binary(_) => {}
                _ => {}
            }
        }
        wire.send(Message::Text(json!({"type":"command.output.ack", "operationId":metadata.operation_id, "generation":metadata.generation, "attempt":metadata.attempt, "sequence":metadata.sequence, "offset":metadata.offset.unwrap() + body.len() as u64}).to_string().into())).unwrap();
        let mut result = false;
        let mut receipt = false;
        let deadline = Instant::now() + Duration::from_secs(3);
        while !(result && receipt) {
            match wire.read().expect("frame") {
                Message::Text(text) => match parse_daemon_control(&text).expect("control") {
                    DaemonControlMessage::OperationResult { state, .. } => {
                        assert_eq!(state, OperationState::Succeeded);
                        result = true;
                    }
                    DaemonControlMessage::OperationReceipt { state, .. } => {
                        assert_eq!(state, OperationState::Succeeded);
                        receipt = true;
                    }
                    DaemonControlMessage::Heartbeat { .. } => {}
                    other => panic!("unexpected {other:?}"),
                },
                Message::Binary(_) => {}
                _ => {}
            }
            assert!(Instant::now() < deadline, "completion never published");
        }
        fake.stop_sandbox(&sandbox_runtime::StopSandboxRequest {
            sandbox_id: "sbx".into(),
            instance_name: "wssp-sbx-sbx".into(),
            operation_id: "cleanup".into(),
            idempotency_key: "cleanup".into(),
            template_fingerprint: String::new(),
        })
        .unwrap();
        shutdown.request();
        client.join().expect("join").expect("connect");
    }
    #[test]
    fn equivalent_server_urls_have_the_same_binding() {
        let canonical =
            canonical_server_binding(&Url::parse("wss://api.example/ws/sandbox-host").unwrap());
        for url in [
            "wss://API.EXAMPLE:443/ws/sandbox-host",
            "wss://api.example/ws/sandbox-host?ignored=yes#fragment",
        ] {
            assert_eq!(
                canonical_server_binding(&Url::parse(url).unwrap()),
                canonical
            );
        }
        assert_ne!(
            canonical_server_binding(&Url::parse("wss://api.example:444/ws/sandbox-host").unwrap()),
            canonical
        );
        assert_ne!(
            canonical_server_binding(&Url::parse("wss://api.example/other").unwrap()),
            canonical
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn stdin_65_chunk_failure_is_journaled_and_published_by_completion_owner() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        use std::net::{TcpListener, TcpStream};
        let dir = tempfile::tempdir().unwrap();
        let binding = TransportBindingV11 {
            server: "wss://example".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let journal = Arc::new(
            crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding).unwrap(),
        );
        let runtime: Arc<dyn SandboxRuntime> = Arc::new(sandbox_runtime::FakeRuntime::new());
        let authority = HostAuthority::default();
        let relay =
            RelaySupervisor::start(runtime.clone(), journal.clone(), authority.clone(), None);
        let dispatch: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":"stdin", "sandboxId":"sbx", "kind":"command.run", "resultVersion":1, "processId":"proc-stdin", "generation":1, "attempt":1, "idempotencyKey":"stdin", "bodyHash":"a".repeat(64)})).unwrap();
        journal
            .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &dispatch))
            .unwrap();
        journal.record_effect("stdin").unwrap();
        authority
            .accept_dispatch("stdin", "sbx", "command.run", 1, 1)
            .unwrap();
        authority.start_stdin("stdin", 0);
        let mut outcome = None;
        for sequence in 1..=65 {
            let frame = encode_binary_frame(
                &StreamBinaryMetadata {
                    r#type: StreamKind::Chunk,
                    stream_id: "stdin-stream".into(),
                    operation_id: "stdin".into(),
                    generation: 1,
                    attempt: 1,
                    offset: None,
                    gap_start: None,
                    sequence,
                    flags: Some(StreamChunkFlags {
                        stdin: Some(true),
                        stdout: None,
                        stderr: None,
                        file_upload: None,
                        file_download: None,
                    }),
                    final_chunk: None,
                },
                b"x",
            )
            .unwrap();
            if let Err(result) =
                apply_stdin_chunk(&journal, None, runtime.as_ref(), &authority, &frame)
            {
                outcome = Some(*result);
            }
        }
        let result = outcome.expect("reorder overflow");
        assert!(journal.lookup("stdin").unwrap().cancel_requested);
        assert_eq!(
            result.error.as_ref().unwrap().code,
            SandboxErrorCode::RequestTooLarge
        );
        assert!(
            authority.pending("stdin").is_some(),
            "producer must retain completion owner"
        );
        relay
            .finished_sender()
            .send(persist_finished(&journal, result))
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut socket = tungstenite::WebSocket::from_raw_socket(
            tungstenite::stream::MaybeTlsStream::Plain(tcp),
            tungstenite::protocol::Role::Client,
            None,
        );
        let mut wire = tungstenite::WebSocket::from_raw_socket(
            peer,
            tungstenite::protocol::Role::Server,
            None,
        );
        let mut live_admission = crate::sandbox_relay::test_support::admission(
            64,
            crate::sandbox_relay::live_admission::test_capacity(),
        );
        drain_finished(
            &mut socket,
            sandbox_protocol::WireCodes::CURRENT,
            &authority,
            &mut live_admission,
            &relay,
            &journal,
            &mut HashMap::new(),
            None,
        )
        .unwrap();
        assert!(matches!(
            sandbox_protocol::parse_daemon_control(wire.read().unwrap().to_text().unwrap())
                .unwrap(),
            DaemonControlMessage::OperationResult {
                state: OperationState::UnknownOutcome,
                ..
            }
        ));
        assert!(authority.pending("stdin").is_some());
        assert_eq!(
            journal.lookup("stdin").unwrap().phase,
            super::super::journal::ReceiptPhase::Effect
        );
        // A later positive command completion may resolve an unknown receipt.
        assert_eq!(
            journal
                .record_result("stdin", OperationState::Succeeded, None, None, None)
                .unwrap()
                .state,
            OperationState::Succeeded
        );
        drop(relay);
        drop(journal);
        let reopened =
            crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding).unwrap();
        assert_eq!(reopened.lookup("stdin").unwrap().error_code, None);
    }
    /// Exercise ingress, journal admission and supervisor request construction
    /// together, including explicit 1/1024 allocations on fresh launches.
    #[cfg(unix)]
    #[test]
    fn sized_dispatch_reaches_supervisor_create_and_reconnect_runtime_requests() {
        use std::net::{TcpListener, TcpStream};
        for (version, size) in [("1.0", Some((2, 2048))), ("1.0", Some((1, 1024)))] {
            let dir = tempfile::tempdir().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let tcp = TcpStream::connect(address).unwrap();
            let (_peer, _) = listener.accept().unwrap();
            let binding = TransportBindingV11 {
                server: format!("ws://{address}/ws/sandbox-host"),
                host_owner_id: "owner".into(),
                host_id: "host".into(),
            };
            let journal = Arc::new(
                crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                    .unwrap(),
            );
            let fake = Arc::new(sandbox_runtime::FakeRuntime::new());
            fake.fixture_root().unwrap();
            let mut authority = HostAuthority::default();
            let relay = RelaySupervisor::start(
                fake.clone(),
                journal.clone(),
                authority.clone(),
                #[cfg(target_os = "linux")]
                None,
            );
            let mut socket = tungstenite::WebSocket::from_raw_socket(
                tungstenite::stream::MaybeTlsStream::Plain(tcp),
                tungstenite::protocol::Role::Client,
                None,
            );
            let mut admission = crate::sandbox_relay::test_support::admission(
                4,
                super::super::live_admission::test_capacity(),
            );
            let expected = size.map_or_else(
                || sandbox_protocol::VmSize::defaults().unwrap(),
                |(cpu, memory)| sandbox_protocol::VmSize::new(cpu, memory).unwrap(),
            );
            let seed = sandbox_runtime::CreateSandboxRequest::for_test("sbx", "create");
            for (operation, kind, generation) in [
                ("create", "sandbox.create", 1),
                ("reconnect", "sandbox.reconnect", 2),
            ] {
                let mut dispatch: OperationDispatch =
                    serde_json::from_value(json!({"sandboxOwnerId":"owner",
                        "operationId":operation, "sandboxId":"sbx", "kind":kind,
                        "generation":generation, "attempt":1, "idempotencyKey":operation,
                        "bodyHash":"a".repeat(64), "lease":sandbox_protocol::HostLease::for_test(),
                        "architecture":seed.architecture, "templateDigest":seed.template_digest,
                        "incusFingerprint":seed.incus_fingerprint,
                    }))
                    .unwrap();
                dispatch.lease.as_mut().unwrap().revision = generation;
                if let Some((cpu, memory)) = size {
                    dispatch.cpu_count = Some(cpu);
                    dispatch.memory_mi_b = Some(memory);
                }
                let dispatch = crate::sandbox_relay::test_support::pinned_dispatch(&dispatch);
                handle_dispatch(
                    &mut socket,
                    WireCodes::negotiated(version),
                    &mut authority,
                    &mut admission,
                    (&journal, &binding),
                    &relay,
                    &None,
                    &mut HashMap::new(),
                    &dispatch,
                )
                .unwrap();
                let deadline = Instant::now() + Duration::from_secs(5);
                let completed = loop {
                    if let Some(done) = relay
                        .poll_finished()
                        .into_iter()
                        .find(|done| done.operation_id == operation)
                    {
                        break done;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "supervisor did not finish {version} {operation}"
                    );
                    thread::sleep(Duration::from_millis(2));
                };
                assert_eq!(
                    completed.state,
                    OperationState::Succeeded,
                    "{version} {operation}: {:?}",
                    completed.error
                );
                let inventory = fake.sandbox_inventory().unwrap();
                assert_eq!(inventory.len(), 1);
                assert_eq!(
                    inventory[0].configured_size,
                    sandbox_runtime::ConfiguredSize::Configured(expected),
                    "{version} {operation}"
                );
                assert_eq!(
                    inventory[0].state,
                    sandbox_protocol::SandboxLifecycleState::Ready
                );
                if operation == "create" {
                    fake.stop_sandbox(&sandbox_runtime::StopSandboxRequest {
                        template_fingerprint: seed.template_digest.clone(),
                        sandbox_id: "sbx".into(),
                        instance_name: "wssp-sbx-sbx".into(),
                        operation_id: "stop".into(),
                        idempotency_key: "stop".into(),
                    })
                    .unwrap();
                }
            }
        }
    }

    /// A lost first create result may leave a live VM. Refusing its retry
    /// must preserve uncertainty all the way through the server-facing frame.
    #[cfg(target_os = "linux")]
    #[test]
    fn existing_vm_refusals_report_unknown_outcome_to_server() {
        use std::net::{TcpListener, TcpStream};
        for stopped in [false, true] {
            for identity_drift in [false, true] {
                for kind in ["sandbox.create", "sandbox.reconnect"] {
                    let dir = tempfile::tempdir().unwrap();
                    let shim = dir.path().join("incus");
                    crate::sandbox_relay::test_support::install_executable(
                        &shim,
                        r#"#!/bin/sh
root=$(dirname "$0")
[ "$1" = "--project" ] && shift 2
printf '%s\n' "$*" >> "$root/calls"
case "$1" in
 version) exit 0 ;;
 storage) printf 'wssp-storage-v1\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n'; exit 0 ;;
 profile) printf '[{"name":"default","devices":{"root":{"type":"disk","path":"/","pool":"test"},"eth0":{"type":"nic","network":"test"}}}]'; exit 0 ;;
 query)
   case "$3" in
     /1.0/storage-pools/default/volumes/custom/*) printf '{"name":"wssp-pool-marker","type":"custom","content_type":"filesystem","config":{"user.wssp.storage-id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}'; exit 0 ;;
     /1.0/storage-pools/default/resources*) printf '{"space":{"total":1099511627776,"used":68719476736}}'; exit 0 ;;
     /1.0/storage-pools/default/volumes/virtual-machine/*/state*) printf '{"usage":{"total":34359738368}}'; exit 0 ;;
     /1.0/storage-pools/default/volumes/virtual-machine/*) printf '{"name":"wssp-sbx-sbx","type":"virtual-machine","content_type":"block","config":{"size":"32GiB"}}'; exit 0 ;;
     /1.0/storage-pools/default*) printf '{"driver":"dir","status":"Created"}'; exit 0 ;;
     /1.0/projects/*) printf '{"name":"default","config":{}}'; exit 0 ;;
     /1.0/images/*) printf '{"properties":{}}'; exit 0 ;;
     /1.0/instances/*) cat "$root/instance.json"; exit 0 ;;
   esac ;;
esac
exit 1
"#,
                        0o700,
                    );
                    let seed = sandbox_runtime::CreateSandboxRequest::for_test("sbx", "create");
                    // Same pinned request size as the lost first attempt;
                    // allocation drift is in the daemon, not the retry.
                    std::fs::write(dir.path().join("instance.json"), json!({
                        "status": if stopped { "Stopped" } else { "Running" },
                        "status_code": if stopped { 102 } else { 103 },
                        "type":"virtual-machine",
                        "devices": {"root":{"type":"disk","path":"/","pool":"default","size":"32GiB"}},
                        "expanded_devices": {"root":{"type":"disk","path":"/","pool":"default","size":"32GiB"}},
                        "config": {
                            "user.flycockpit.sandbox_id": if identity_drift { "foreign" } else { "sbx" },
                            "user.flycockpit.create_idempotency_key":"create",
                            "user.flycockpit.template_digest":seed.template_digest,
                            "volatile.base_image":seed.template_digest.strip_prefix("sha256:").unwrap(),
                            "limits.cpu":"2", "limits.memory": if identity_drift { "2048MiB" } else { "4096MiB" }
                        }
                    }).to_string()).unwrap();
                    let mut runtime = IncusKvmRuntime::new(IncusConfig {
                        binary: shim.to_string_lossy().into_owned(),
                        project: "default".into(),
                    })
                    .unwrap();
                    // Shim host: a synthetic healthy egress guard, so the
                    // refusal under test is the existing-VM one.
                    runtime.set_guard_probe(Arc::new(
                        sandbox_runtime::guard::probe::FakeGuardProbe::healthy(),
                    ));
                    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                    let address = listener.local_addr().unwrap();
                    let tcp = TcpStream::connect(address).unwrap();
                    let (peer, _) = listener.accept().unwrap();
                    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    let binding = TransportBindingV11 {
                        server: format!("ws://{address}/ws/sandbox-host"),
                        host_owner_id: "owner".into(),
                        host_id: "host".into(),
                    };
                    let journal = Arc::new(
                        crate::sandbox_relay::test_support::open_ready_journal(
                            dir.path().join("journal"),
                            &binding,
                        )
                        .unwrap(),
                    );
                    let mut authority = HostAuthority::default();
                    let relay = RelaySupervisor::start(
                        Arc::new(runtime),
                        journal.clone(),
                        authority.clone(),
                        None,
                    );
                    let mut socket = tungstenite::WebSocket::from_raw_socket(
                        tungstenite::stream::MaybeTlsStream::Plain(tcp),
                        tungstenite::protocol::Role::Client,
                        None,
                    );
                    let mut wire = tungstenite::WebSocket::from_raw_socket(
                        peer,
                        tungstenite::protocol::Role::Server,
                        None,
                    );
                    let mut dispatch: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
                        "operationId":"create", "sandboxId":"sbx", "kind":kind,
                        "generation":1, "attempt":2, "idempotencyKey":"create",
                        "bodyHash":"a".repeat(64), "lease":sandbox_protocol::HostLease::for_test(),
                        "architecture":seed.architecture, "templateDigest":seed.template_digest,
                        "incusFingerprint":seed.incus_fingerprint,
                    }))
                    .unwrap();
                    dispatch.cpu_count = Some(2);
                    dispatch.memory_mi_b = Some(2048);
                    let mut admission = crate::sandbox_relay::test_support::admission(
                        4,
                        crate::sandbox_relay::live_admission::test_capacity(),
                    );
                    let dispatch = crate::sandbox_relay::test_support::pinned_dispatch(&dispatch);
                    if kind == "sandbox.reconnect" {
                        journal
                            .seed_fixture_root(
                                &dispatch.sandbox_id,
                                dispatch.allocation.as_ref().unwrap(),
                                0,
                            )
                            .unwrap();
                        admission.rebuild(&[], &journal, &binding).unwrap();
                    }
                    handle_dispatch(
                        &mut socket,
                        WireCodes::negotiated("1.0"),
                        &mut authority,
                        &mut admission,
                        (&journal, &binding),
                        &relay,
                        &None,
                        &mut HashMap::new(),
                        &dispatch,
                    )
                    .unwrap();
                    let deadline = Instant::now() + Duration::from_secs(10);
                    let finished = loop {
                        if let Some(finished) = relay.poll_finished().pop() {
                            break finished;
                        }
                        assert!(Instant::now() < deadline, "runtime refusal did not finish");
                        thread::sleep(Duration::from_millis(2));
                    };
                    relay.finished_sender().send(finished).unwrap();
                    drain_finished(
                        &mut socket,
                        WireCodes::negotiated("1.0"),
                        &authority,
                        &mut admission,
                        &relay,
                        &journal,
                        &mut HashMap::new(),
                        None,
                    )
                    .unwrap();
                    loop {
                        let frame = sandbox_protocol::parse_daemon_control(
                            wire.read().unwrap().to_text().unwrap(),
                        )
                        .unwrap();
                        if let DaemonControlMessage::OperationResult {
                            state,
                            error,
                            result,
                            ..
                        } = frame
                        {
                            assert_eq!(
                                state,
                                OperationState::UnknownOutcome,
                                "{kind}, stopped={stopped}, identity_drift={identity_drift}"
                            );
                            assert_eq!(
                                error.unwrap().code,
                                if identity_drift {
                                    SandboxErrorCode::IdempotencyConflict
                                } else {
                                    SandboxErrorCode::VmSizeMismatch
                                },
                                "{kind}, stopped={stopped}, identity_drift={identity_drift}"
                            );
                            assert!(result.is_none(), "lifecycle refusal has no success body");
                            break;
                        }
                    }
                    assert_eq!(
                        journal.lookup("create").unwrap().state,
                        OperationState::UnknownOutcome
                    );
                    assert!(
                        authority.pending("create").is_some(),
                        "unknown retains completion authority"
                    );
                    let calls = std::fs::read_to_string(dir.path().join("calls")).unwrap();
                    assert!(
                        calls.lines().all(|line| line
                            == "storage volume file pull default wssp-pool-marker/storage-id -"
                            || matches!(
                                line.split_whitespace().next(),
                                Some("version" | "query" | "profile")
                            )),
                        "refusal mutated the VM: {calls}"
                    );
                    assert!(
                        !dir.path()
                            .join("host-state/network-cleanups/sbx.json")
                            .exists()
                    );
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn strict_size_refusal_precedes_live_dispatch_journal_admission() {
        use std::net::{TcpListener, TcpStream};
        for (version, size) in [("1.0", Some((2, 2048))), ("1.0", None), ("1.0", None)] {
            let dir = tempfile::tempdir().unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let tcp = TcpStream::connect(address).unwrap();
            let (peer, _) = listener.accept().unwrap();
            let binding = TransportBindingV11 {
                server: format!("ws://{address}/ws/sandbox-host"),
                host_owner_id: "owner".into(),
                host_id: "host".into(),
            };
            let journal = Arc::new(
                crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                    .unwrap(),
            );
            let fake = Arc::new(sandbox_runtime::FakeRuntime::new());
            let mut authority = HostAuthority::default();
            let relay = RelaySupervisor::start(
                fake.clone(),
                journal.clone(),
                authority.clone(),
                #[cfg(target_os = "linux")]
                None,
            );
            let mut socket = tungstenite::WebSocket::from_raw_socket(
                tungstenite::stream::MaybeTlsStream::Plain(tcp),
                tungstenite::protocol::Role::Client,
                None,
            );
            let mut dispatch: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":"sized", "sandboxId":"sbx", "kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(), "generation":1, "attempt":1, "idempotencyKey":"sized", "bodyHash":"a".repeat(64)})).unwrap();
            if let Some((cpu, memory)) = size {
                dispatch.cpu_count = Some(cpu);
                dispatch.memory_mi_b = Some(memory);
            }
            let result = handle_dispatch(
                &mut socket,
                WireCodes::negotiated(version),
                &mut authority,
                &mut crate::sandbox_relay::test_support::admission(
                    4,
                    crate::sandbox_relay::live_admission::test_capacity(),
                ),
                (&journal, &binding),
                &relay,
                &None,
                &mut HashMap::new(),
                &dispatch,
            );
            // E4-01: refused as this one operation; the session continues.
            result.unwrap();
            let mut server = tungstenite::WebSocket::from_raw_socket(
                peer,
                tungstenite::protocol::Role::Server,
                None,
            );
            let refusal: serde_json::Value =
                serde_json::from_str(server.read().unwrap().to_text().unwrap()).unwrap();
            assert_eq!(refusal["type"], "operation.result", "{version}");
            assert_eq!(refusal["operationId"], "sized");
            assert_eq!(refusal["error"]["code"], "protocol_error");
            assert_eq!(
                refusal["error"]["message"],
                "invalid dispatch sizing fields"
            );
            assert!(
                journal.lookup("sized").is_none(),
                "no journal intent before wire acceptance"
            );
            assert!(
                fake.sandbox_inventory().unwrap().is_empty(),
                "no runtime effect"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn actual_server_expiry_fixture_passes_host_admission_and_stops() {
        use std::net::{TcpListener, TcpStream};
        let dir = tempfile::tempdir().unwrap();
        let binding = TransportBindingV11 {
            server: "wss://example".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let journal = Arc::new(
            crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding).unwrap(),
        );
        let mut authority = HostAuthority::default();
        let fake = Arc::new(sandbox_runtime::FakeRuntime::new());
        fake.create_fixture(&sandbox_runtime::CreateSandboxRequest::for_test(
            "sbx-1", "create",
        ))
        .unwrap();
        let relay = RelaySupervisor::start(
            fake.clone(),
            journal.clone(),
            authority.clone(),
            #[cfg(target_os = "linux")]
            None,
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut socket = tungstenite::WebSocket::from_raw_socket(
            tungstenite::stream::MaybeTlsStream::Plain(tcp),
            tungstenite::protocol::Role::Client,
            None,
        );
        let mut wire = tungstenite::WebSocket::from_raw_socket(
            peer,
            tungstenite::protocol::Role::Server,
            None,
        );
        let ServerControlMessage::OperationDispatch(dispatch) =
            sandbox_protocol::parse_server_control(include_str!(
                "../../../../crates/sandbox-protocol/fixtures/control_expiry_stop_dispatch.json"
            ))
            .unwrap()
        else {
            panic!("dispatch fixture")
        };
        let dispatch = crate::sandbox_relay::test_support::pinned_dispatch(&dispatch);
        handle_dispatch(
            &mut socket,
            sandbox_protocol::WireCodes::CURRENT,
            &mut authority,
            &mut crate::sandbox_relay::test_support::admission(
                64,
                crate::sandbox_relay::live_admission::test_capacity(),
            ),
            (&journal, &binding),
            &relay,
            &None,
            &mut HashMap::new(),
            &dispatch,
        )
        .unwrap();
        assert!(matches!(
            sandbox_protocol::parse_daemon_control(wire.read().unwrap().to_text().unwrap())
                .unwrap(),
            DaemonControlMessage::OperationProgress {
                state: OperationState::Accepted,
                ..
            }
        ));
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(finished) = relay.poll_finished().pop() {
                assert_eq!(finished.state, OperationState::Succeeded);
                break;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(
            journal.lookup(&dispatch.operation_id).unwrap().state,
            OperationState::Succeeded
        );
        assert_eq!(
            fake.query_sandbox("sbx-1", None, None).unwrap(),
            Some(sandbox_protocol::SandboxLifecycleState::Stopped)
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn c15_long_script_dispatch_replays_after_restart_without_another_exec() {
        use std::net::{TcpListener, TcpStream};
        let dir = tempfile::tempdir().unwrap();
        let shim = dir.path().join("incus");
        crate::sandbox_relay::test_support::install_executable(
            &shim,
            r#"#!/bin/sh
root=$(dirname "$0")
[ "$1" = "--project" ] && shift 2
case "$1" in
 version) exit 0 ;;
 profile) echo '[{"name":"default","devices":{"root":{"type":"disk","path":"/","pool":"default"},"eth0":{"type":"nic","network":"incusbr0"}}}]'; exit 0 ;;
 query) echo '{"type":"sync","metadata":{"status":"Running","status_code":103,"type":"virtual-machine","config":{"user.flycockpit.sandbox_id":"sbx","user.flycockpit.template_digest":"sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789","volatile.base_image":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}}}'; exit 0 ;;
 exec)
   printf 'exec\n' >> "$root/executions"
   printf '%s\000' "$@" > "$root/argv"
   while [ "$1" != "--" ]; do shift; done
   shift
   # Simulate the guest scope; preserve the inner helper/command argv.
   if [ "${1:-}" = /usr/bin/systemd-run ]; then
     [ "${2:-}" = --scope ] && [ "${3:-}" = --quiet ] && [ "${4:-}" = --collect ] &&
       [ "${5:-}" = --no-ask-password ] && [ "${6:-}" = --description=wssp-command ] &&
       [ "${7:-}" = --property=OOMPolicy=continue ] && [ "${8:-}" = --expand-environment=no ] &&
       [ "${10:-}" = --slice=wssp.slice ] && [ "${11:-}" = -- ] || exit 1
     case "${9:-}" in --unit=wssp-cmd-*.scope) ;; *) exit 1 ;; esac
     shift 11
   fi
   # The launcher: python3 -I -S -c <helper> <unit> <uid> <gid> <command...>.
   if [ "${2:-}" = -I ] && [ "${3:-}" = -S ] && [ "${4:-}" = -c ]; then shift 8; fi
   wrapper=$5
   rest=${wrapper#*WSSP_EXIT }
   nonce=${rest%% *}
   for arg in "$@"; do body=$arg; done
   printf '%s' "$body"
   printf 'WSSP_PID %s 4242\n\nWSSP_EXIT %s 0\n' "$nonce" "$nonce" >&2
   exit 0 ;;
esac
exit 1
"#,
            0o700,
        );
        let binding = TransportBindingV11 {
            server: "wss://example".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let sandbox_protocol::ServerControlMessage::OperationDispatch(mut dispatch) = sandbox_protocol::parse_server_control(include_str!(
            "../../../../crates/sandbox-protocol/fixtures/control_operation_dispatch_script.json"
        )).unwrap() else { panic!("expected dispatch") };
        dispatch.sandbox_id = "sbx".into();
        dispatch.guest_uid = Some(1234);
        dispatch.guest_gid = Some(2345);
        dispatch.guest_home = Some("/home/declared".into());
        let script = dispatch.script.clone().unwrap();
        assert!(script.len() > 512);
        for restart in [false, true] {
            let journal = Arc::new(
                crate::sandbox_relay::test_support::open_ready_journal(
                    dir.path().join("journal"),
                    &binding,
                )
                .unwrap(),
            );
            let runtime = IncusKvmRuntime::new(IncusConfig {
                binary: shim.to_string_lossy().into_owned(),
                project: "default".into(),
            })
            .unwrap();
            let exec = runtime.exec_supervisor();
            let mut authority = HostAuthority::default();
            let relay = RelaySupervisor::start(
                Arc::new(runtime),
                journal.clone(),
                authority.clone(),
                Some(exec.clone()),
            );
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (peer, _) = listener.accept().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut socket = tungstenite::WebSocket::from_raw_socket(
                tungstenite::stream::MaybeTlsStream::Plain(tcp),
                tungstenite::protocol::Role::Client,
                None,
            );
            let mut wire = tungstenite::WebSocket::from_raw_socket(
                peer,
                tungstenite::protocol::Role::Server,
                None,
            );
            let mut live = crate::sandbox_relay::test_support::admission(
                1,
                crate::sandbox_relay::live_admission::test_capacity(),
            );
            let dispatch = crate::sandbox_relay::test_support::pinned_dispatch(&dispatch);
            handle_dispatch(
                &mut socket,
                sandbox_protocol::WireCodes::CURRENT,
                &mut authority,
                &mut live,
                (&journal, &binding),
                &relay,
                &Some(exec),
                &mut HashMap::new(),
                &dispatch,
            )
            .unwrap();
            if !restart {
                let deadline = Instant::now() + Duration::from_secs(3);
                let mut output = Vec::new();
                let finished = loop {
                    for frame in relay.poll_output().expect("encode output") {
                        output.extend_from_slice(frame.body());
                        relay.ack_output(
                            frame.metadata.operation_id.clone(),
                            frame.metadata.generation,
                            frame.metadata.attempt,
                            frame.metadata.sequence,
                            frame.metadata.offset.unwrap() + frame.body_len() as u64,
                        );
                    }
                    if let Some(finished) = relay.poll_finished().pop() {
                        break finished;
                    }
                    assert!(Instant::now() < deadline, "command did not finish");
                    thread::sleep(Duration::from_millis(5));
                };
                assert_eq!(output, script.as_bytes());
                assert_eq!(finished.state, OperationState::Succeeded);
                send_finished(
                    &mut socket,
                    sandbox_protocol::WireCodes::CURRENT,
                    None,
                    finished,
                )
                .unwrap();
            }
            loop {
                let message =
                    sandbox_protocol::parse_daemon_control(wire.read().unwrap().to_text().unwrap())
                        .unwrap();
                if let DaemonControlMessage::OperationResult { state, result, .. } = message {
                    assert_eq!(state, OperationState::Succeeded);
                    let result = result.unwrap();
                    assert!(result.get("stdout").is_none());
                    assert_eq!(result["outputBytes"], script.len());
                    break;
                }
            }
            assert_eq!(
                std::fs::read_to_string(dir.path().join("executions")).unwrap(),
                "exec\n"
            );
            let argv = std::fs::read(dir.path().join("argv")).unwrap();
            let args: Vec<_> = argv.split(|b| *b == 0).collect();
            assert_eq!(args[args.len() - 2], script.as_bytes());
            assert!(args.windows(3).any(|a| a
                == [
                    b"/bin/bash".as_slice(),
                    b"-lc".as_slice(),
                    script.as_bytes()
                ]));
            assert!(
                args.windows(2)
                    .any(|a| a == [b"--user".as_slice(), b"0".as_slice()])
            );
            assert!(
                args.windows(2)
                    .any(|a| a == [b"--group".as_slice(), b"0".as_slice()])
            );
            assert!(
                args.windows(2)
                    .any(|a| a == [b"1234".as_slice(), b"2345".as_slice()])
            );
            drop(relay);
        }
    }

    #[cfg(unix)]
    #[test]
    fn live_capacity_refusal_logs_counts_without_workload_content() {
        use std::net::{TcpListener, TcpStream};
        let (_, captured) = crate::logging::with_subscriber(
            crate::logging::LogFormat::Json,
            tracing_subscriber::EnvFilter::new("trace"),
            || {
                let dir = tempfile::tempdir().unwrap();
                let binding = TransportBindingV11 {
                    server: "wss://example".into(),
                    host_owner_id: "owner".into(),
                    host_id: "host".into(),
                };
                let journal = Arc::new(
                    crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                        .unwrap(),
                );
                let mut authority = HostAuthority::default();
                let mut slots = crate::sandbox_relay::test_support::admission(
                    1,
                    crate::sandbox_relay::live_admission::test_capacity(),
                );
                slots
                    .try_acquire(
                        "held",
                        "earlier",
                        1,
                        sandbox_protocol::VmSize::defaults().unwrap(),
                    )
                    .unwrap();
                slots.finish_allocation("held", "earlier", OperationState::UnknownOutcome);
                let relay = RelaySupervisor::start(
                    Arc::new(sandbox_runtime::FakeRuntime::new()),
                    journal.clone(),
                    authority.clone(),
                    #[cfg(target_os = "linux")]
                    None,
                );
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
                let (peer, _) = listener.accept().unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut socket = tungstenite::WebSocket::from_raw_socket(
                    tungstenite::stream::MaybeTlsStream::Plain(tcp),
                    tungstenite::protocol::Role::Client,
                    None,
                );
                let mut wire = tungstenite::WebSocket::from_raw_socket(
                    peer,
                    tungstenite::protocol::Role::Server,
                    None,
                );
                let d =
                    serde_json::from_value(json!({"sandboxOwnerId":"owner",  "operationId":"refused", "sandboxId":"fresh",
                "kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(), "cpuCount": 1, "memoryMiB": 1024, "generation":1, "attempt":1, "idempotencyKey":"refused",
                "bodyHash":"a".repeat(64), "script":"PRIVATE_VALUE", "argv":["PRIVATE_NAME"] }))
                    .unwrap();
                let d = crate::sandbox_relay::test_support::pinned_dispatch(&d);
                handle_dispatch(
                    &mut socket,
                    sandbox_protocol::WireCodes::negotiated(
                        sandbox_protocol::SANDBOX_RELAY_PROTOCOL_VERSION,
                    ),
                    &mut authority,
                    &mut slots,
                    (&journal, &binding),
                    &relay,
                    &None,
                    &mut HashMap::new(),
                    &d,
                )
                .unwrap();
                let until = Instant::now() + Duration::from_secs(3);
                let finished = loop {
                    if let Some(finished) = relay.poll_finished().pop() {
                        break finished;
                    }
                    assert!(Instant::now() < until);
                    thread::sleep(Duration::from_millis(2));
                };
                send_finished(
                    &mut socket,
                    sandbox_protocol::WireCodes::negotiated(
                        sandbox_protocol::SANDBOX_RELAY_PROTOCOL_VERSION,
                    ),
                    Some("sandbox.create"),
                    finished,
                )
                .unwrap();
                let result: serde_json::Value =
                    serde_json::from_str(wire.read().unwrap().to_text().unwrap()).unwrap();
                assert_eq!(result["error"]["code"], "host_capacity");
                assert_eq!(slots.held(), 1);
            },
        );
        let captured = String::from_utf8(captured).unwrap();
        assert!(captured.contains("live_reservations"), "{captured}");
        assert!(captured.contains("\"held\":1"), "{captured}");
        assert!(captured.contains("\"vcpu_budget\":1"), "{captured}");
        assert!(!captured.contains("PRIVATE_NAME"));
        assert!(!captured.contains("PRIVATE_VALUE"));
    }

    #[cfg(unix)]
    #[test]
    fn invalid_command_description_is_protocol_error_not_host_capacity() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        use std::net::{TcpListener, TcpStream};
        let dir = crate::sandbox_relay::test_support::journal_capacity_dir();
        let binding = TransportBindingV11 {
            server: "wss://example".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let journal = Arc::new(
            crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding).unwrap(),
        );
        let mut authority = HostAuthority::default();
        let mut live_admission = crate::sandbox_relay::test_support::admission(
            1,
            crate::sandbox_relay::live_admission::test_capacity(),
        );
        let relay = RelaySupervisor::start(
            Arc::new(sandbox_runtime::FakeRuntime::new()),
            journal.clone(),
            authority.clone(),
            #[cfg(target_os = "linux")]
            None,
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut socket = tungstenite::WebSocket::from_raw_socket(
            tungstenite::stream::MaybeTlsStream::Plain(tcp),
            tungstenite::protocol::Role::Client,
            None,
        );
        let mut wire = tungstenite::WebSocket::from_raw_socket(
            peer,
            tungstenite::protocol::Role::Server,
            None,
        );
        let dispatch: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
            "operationId":"empty-command", "sandboxId":"sbx", "kind":"command.run",
            "generation":1, "attempt":1, "idempotencyKey":"empty-command",
            "bodyHash":"a".repeat(64), "argv":[""], "processId":"process", "resultVersion":1,
            "incusFingerprint":format!("sha256:{}", "a".repeat(64))
        }))
        .unwrap();
        let dispatch = crate::sandbox_relay::test_support::pinned_dispatch(&dispatch);
        handle_dispatch(
            &mut socket,
            sandbox_protocol::WireCodes::negotiated(
                sandbox_protocol::SANDBOX_RELAY_PROTOCOL_VERSION,
            ),
            &mut authority,
            &mut live_admission,
            (&journal, &binding),
            &relay,
            &None,
            &mut HashMap::new(),
            &dispatch,
        )
        .unwrap();
        let mut terminal = None;
        // The durable acceptance may precede the deterministic refusal.
        for _ in 0..2 {
            let frame =
                sandbox_protocol::parse_daemon_control(wire.read().unwrap().to_text().unwrap())
                    .unwrap();
            if let DaemonControlMessage::OperationResult { state, error, .. } = frame {
                let error = error.unwrap();
                terminal = Some((state, error.code, error.message));
                break;
            }
        }
        assert_eq!(
            terminal,
            Some((
                OperationState::Failed,
                SandboxErrorCode::ProtocolError.into(),
                "invalid command description".into()
            ))
        );
        assert!(relay.poll_finished().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn connection_refusals_require_journal_first_attempt_and_runtime_evidence() {
        use std::net::{TcpListener, TcpStream};
        for kind in ["sandbox.create", "sandbox.reconnect"] {
            for refusal in ["journal-full", "authority"] {
                for history in ["fresh", "retry", "ambiguous"] {
                    for observation in ["absent", "present", "stopped", "error"] {
                        let dir = crate::sandbox_relay::test_support::journal_capacity_dir();
                        let binding = TransportBindingV11 {
                            server: "wss://example".into(),
                            host_owner_id: "owner".into(),
                            host_id: "host".into(),
                        };
                        let journal = Arc::new(
                            crate::sandbox_relay::test_support::open_ready_journal(
                                dir.path(),
                                &binding,
                            )
                            .unwrap(),
                        );
                        let mut d: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":"refusal", "sandboxId":"fresh", "kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(), "cpuCount":1, "memoryMiB":1024, "generation":1, "attempt":1, "idempotencyKey":"refusal", "bodyHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})).unwrap();
                        d.kind = kind.into();
                        if kind == "sandbox.reconnect" {
                            journal
                                .seed_fixture_root(&d.sandbox_id, d.allocation.as_ref().unwrap(), 0)
                                .unwrap();
                        }
                        d.attempt = if history == "retry" { 2 } else { 1 };
                        if history == "ambiguous" {
                            let mut old = d.clone();
                            old.operation_id = "old".into();
                            old.idempotency_key = "old".into();
                            journal
                                .record_fixture_intent(&intent_from_dispatch(
                                    &journal, &binding, &old,
                                ))
                                .unwrap();
                            journal.record_effect("old").unwrap();
                        }
                        if refusal == "journal-full" {
                            for i in 0..4096 {
                                let mut filler = d.clone();
                                filler.operation_id = format!("filler-{i}");
                                filler.idempotency_key = filler.operation_id.clone();
                                filler.sandbox_id = "unrelated".into();
                                filler.kind = "command.run".into();
                                journal
                                    .record_fixture_intent(&intent_from_dispatch(
                                        &journal, &binding, &filler,
                                    ))
                                    .unwrap();
                            }
                        }
                        let mut fake = sandbox_runtime::FakeRuntime::new();
                        fake.fixture_root().unwrap();
                        if matches!(observation, "present" | "stopped") {
                            fake.create_fixture(&sandbox_runtime::CreateSandboxRequest::for_test(
                                &d.sandbox_id,
                                "existing",
                            ))
                            .unwrap();
                            if observation == "stopped" {
                                fake.stop_sandbox(&sandbox_runtime::StopSandboxRequest {
                                    template_fingerprint:
                                        sandbox_runtime::CreateSandboxRequest::for_test(
                                            &d.sandbox_id,
                                            "existing",
                                        )
                                        .template_digest,
                                    sandbox_id: d.sandbox_id.clone(),
                                    instance_name: sandbox_runtime::default_incus_instance_name(
                                        &d.sandbox_id,
                                    ),
                                    operation_id: "stop".into(),
                                    idempotency_key: "stop".into(),
                                })
                                .unwrap();
                            }
                        }
                        if observation == "error" {
                            fake = fake.with_inventory_hook(move |stage| {
                                assert_eq!(
                                    stage,
                                    if kind == "sandbox.create" {
                                        "exists"
                                    } else {
                                        "running"
                                    }
                                );
                                Err(sandbox_runtime::RuntimeError::new(
                                    SandboxErrorCode::Internal,
                                    "existence unavailable",
                                ))
                            });
                        }
                        let mut authority = HostAuthority::default();
                        if refusal == "authority" {
                            authority.shutdown();
                        }
                        let relay = RelaySupervisor::start(
                            Arc::new(fake),
                            journal.clone(),
                            authority.clone(),
                            #[cfg(target_os = "linux")]
                            None,
                        );
                        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                        let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
                        let (peer, _) = listener.accept().unwrap();
                        peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                        let mut socket = tungstenite::WebSocket::from_raw_socket(
                            tungstenite::stream::MaybeTlsStream::Plain(tcp),
                            tungstenite::protocol::Role::Client,
                            None,
                        );
                        let mut wire = tungstenite::WebSocket::from_raw_socket(
                            peer,
                            tungstenite::protocol::Role::Server,
                            None,
                        );
                        let d = crate::sandbox_relay::test_support::pinned_dispatch(&d);
                        handle_dispatch(
                            &mut socket,
                            WireCodes::negotiated("1.0"),
                            &mut authority,
                            &mut crate::sandbox_relay::test_support::admission(
                                4,
                                crate::sandbox_relay::live_admission::test_capacity(),
                            ),
                            (&journal, &binding),
                            &relay,
                            &None,
                            &mut HashMap::new(),
                            &d,
                        )
                        .unwrap();
                        let until = Instant::now() + Duration::from_secs(3);
                        loop {
                            let completed = relay.poll_refusals();
                            if !completed.is_empty() {
                                for (kind, finished) in completed {
                                    send_finished(
                                        &mut socket,
                                        WireCodes::negotiated("1.0"),
                                        Some(&kind),
                                        finished,
                                    )
                                    .unwrap();
                                }
                                break;
                            }
                            assert!(Instant::now() < until);
                            thread::sleep(Duration::from_millis(2));
                        }
                        let frame = sandbox_protocol::parse_daemon_control(
                            wire.read().unwrap().to_text().unwrap(),
                        )
                        .unwrap();
                        let DaemonControlMessage::OperationResult {
                            operation_id,
                            sandbox_id,
                            generation,
                            attempt,
                            state,
                            error,
                            ..
                        } = frame
                        else {
                            panic!("expected refusal result")
                        };
                        assert_eq!(
                            (operation_id, sandbox_id, generation, attempt),
                            (
                                d.operation_id.clone(),
                                d.sandbox_id.clone(),
                                d.generation,
                                d.attempt
                            )
                        );
                        let expected = if history == "fresh"
                            && (observation == "absent"
                                || (kind == "sandbox.reconnect" && observation == "stopped"))
                        {
                            OperationState::Failed
                        } else {
                            OperationState::UnknownOutcome
                        };
                        assert_eq!(
                            state, expected,
                            "{kind}, {refusal}, {history}, {observation}"
                        );
                        let code = if refusal == "authority" {
                            if history == "fresh" {
                                SandboxErrorCode::HostEffectNotIssued
                            } else {
                                SandboxErrorCode::ProtocolError
                            }
                        } else {
                            SandboxErrorCode::HostCapacity
                        };
                        assert_eq!(error.unwrap().code, code);
                    }
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn authority_refusal_replays_and_teardowns_keep_previous_error_code() {
        use std::net::{TcpListener, TcpStream};
        for kind in [
            "sandbox.create",
            "sandbox.reconnect",
            "sandbox.stop",
            "sandbox.kill",
        ] {
            for history in ["fresh", "intent", "effect", "replay"] {
                // Fresh allocation refusals are covered by the evidence matrix.
                if history == "fresh" && matches!(kind, "sandbox.create" | "sandbox.reconnect") {
                    continue;
                }
                let dir = crate::sandbox_relay::test_support::journal_capacity_dir();
                let binding = TransportBindingV11 {
                    server: "wss://example".into(),
                    host_owner_id: "owner".into(),
                    host_id: "host".into(),
                };
                let journal = Arc::new(
                    crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding)
                        .unwrap(),
                );
                let mut dispatch: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner",
                    "operationId":"refused", "sandboxId":"sbx", "kind":"sandbox.create", "allocation": crate::sandbox_relay::test_support::allocation(),
                    "cpuCount":1, "memoryMiB":1024, "generation":1, "attempt":1,
                    "idempotencyKey":"refused", "bodyHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                })).unwrap();
                dispatch.kind = kind.into();
                if matches!(kind, "sandbox.stop" | "sandbox.kill") {
                    dispatch.cpu_count = None;
                    dispatch.memory_mi_b = None;
                }
                if history != "fresh" {
                    journal
                        .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &dispatch))
                        .unwrap();
                    if matches!(history, "effect" | "replay") {
                        journal.record_effect(&dispatch.operation_id).unwrap();
                    }
                    if history == "replay" {
                        journal
                            .record_result(
                                &dispatch.operation_id,
                                OperationState::Failed,
                                None,
                                Some(SandboxErrorCode::Internal),
                                Some("prior failure".into()),
                            )
                            .unwrap();
                    }
                }
                let before = journal.lookup(&dispatch.operation_id);
                let mut authority = HostAuthority::default();
                authority.shutdown();
                let relay = RelaySupervisor::start(
                    Arc::new(
                        sandbox_runtime::FakeRuntime::new().with_inventory_hook(|_| {
                            panic!("replays and teardown refusals must not query the runtime")
                        }),
                    ),
                    journal.clone(),
                    authority.clone(),
                    #[cfg(target_os = "linux")]
                    None,
                );
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
                let (peer, _) = listener.accept().unwrap();
                peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                let mut socket = tungstenite::WebSocket::from_raw_socket(
                    tungstenite::stream::MaybeTlsStream::Plain(tcp),
                    tungstenite::protocol::Role::Client,
                    None,
                );
                let mut wire = tungstenite::WebSocket::from_raw_socket(
                    peer,
                    tungstenite::protocol::Role::Server,
                    None,
                );
                let dispatch = crate::sandbox_relay::test_support::pinned_dispatch(&dispatch);
                handle_dispatch(
                    &mut socket,
                    WireCodes::negotiated("1.0"),
                    &mut authority,
                    &mut crate::sandbox_relay::test_support::admission(
                        4,
                        crate::sandbox_relay::live_admission::test_capacity(),
                    ),
                    (&journal, &binding),
                    &relay,
                    &None,
                    &mut HashMap::new(),
                    &dispatch,
                )
                .unwrap();
                let frame =
                    sandbox_protocol::parse_daemon_control(wire.read().unwrap().to_text().unwrap())
                        .unwrap();
                let DaemonControlMessage::OperationResult { error, .. } = frame else {
                    panic!("expected refusal result")
                };
                assert_eq!(
                    error.unwrap().code,
                    SandboxErrorCode::ProtocolError,
                    "{kind}, {history}"
                );
                if history != "fresh" {
                    assert_eq!(
                        journal.lookup(&dispatch.operation_id),
                        before,
                        "receipt must be unchanged"
                    );
                }
                assert!(relay.poll_refusals().is_empty());
                assert!(authority.pending(&dispatch.operation_id).is_none());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn malformed_dispatch_is_rejected_without_persistence_or_socket_loss() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        use std::net::{TcpListener, TcpStream};
        let dir = crate::sandbox_relay::test_support::journal_capacity_dir();
        let binding = TransportBindingV11 {
            server: "wss://example".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let journal = Arc::new(
            crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding).unwrap(),
        );
        let mut authority = HostAuthority::default();
        let mut live_admission = crate::sandbox_relay::test_support::admission(
            1,
            crate::sandbox_relay::live_admission::test_capacity(),
        );
        let relay = RelaySupervisor::start(
            Arc::new(sandbox_runtime::FakeRuntime::new()),
            journal.clone(),
            authority.clone(),
            #[cfg(target_os = "linux")]
            None,
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (peer, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut socket = tungstenite::WebSocket::from_raw_socket(
            tungstenite::stream::MaybeTlsStream::Plain(tcp),
            tungstenite::protocol::Role::Client,
            None,
        );
        let mut wire = tungstenite::WebSocket::from_raw_socket(
            peer,
            tungstenite::protocol::Role::Server,
            None,
        );
        for field in ["bodyHash", "kind", "idempotencyKey"] {
            let mut value = json!({"sandboxOwnerId":"owner", "operationId":"oversized", "sandboxId":"sbx", "kind":"command.run", "resultVersion":1, "processId":"proc-oversized", "generation":1, "attempt":1, "idempotencyKey":"key", "bodyHash":"a".repeat(64)});
            value[field] = json!("x".repeat(60 * 1024));
            let dispatch = serde_json::from_value(value).unwrap();
            let dispatch = crate::sandbox_relay::test_support::pinned_dispatch(&dispatch);
            handle_dispatch(
                &mut socket,
                sandbox_protocol::WireCodes::negotiated(
                    sandbox_protocol::SANDBOX_RELAY_PROTOCOL_VERSION,
                ),
                &mut authority,
                &mut live_admission,
                (&journal, &binding),
                &relay,
                &None,
                &mut HashMap::new(),
                &dispatch,
            )
            .unwrap();
            assert!(matches!(
                sandbox_protocol::parse_daemon_control(wire.read().unwrap().to_text().unwrap())
                    .unwrap(),
                DaemonControlMessage::OperationResult {
                    state: OperationState::Failed,
                    error: Some(ProtocolErrorDetail {
                        reason: None,
                        code: sandbox_protocol::WireErrorCode::Known(
                            SandboxErrorCode::ProtocolError
                        ),
                        ..
                    }),
                    ..
                }
            ));
            assert!(journal.lookup("oversized").is_none());
        }
        for index in 0..4096 {
            let d: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":format!("fill-{index}"), "sandboxId":"sbx", "kind":"command.run", "resultVersion":1, "processId":"proc-x", "generation":1, "attempt":1, "idempotencyKey":format!("fill-{index}"), "bodyHash":"a".repeat(64)})).unwrap();
            journal
                .record_fixture_intent(&intent_from_dispatch(&journal, &binding, &d))
                .unwrap();
        }
        let full: OperationDispatch = serde_json::from_value(json!({"sandboxOwnerId":"owner", "operationId":"full", "sandboxId":"sbx", "kind":"sandbox.create", "lease":sandbox_protocol::HostLease::for_test(), "allocation": crate::sandbox_relay::test_support::allocation(), "cpuCount": 1, "memoryMiB": 1024, "generation":1, "attempt":1, "idempotencyKey":"full", "bodyHash":"a".repeat(64)})).unwrap();
        let full = crate::sandbox_relay::test_support::pinned_dispatch(&full);
        handle_dispatch(
            &mut socket,
            sandbox_protocol::WireCodes::negotiated(
                sandbox_protocol::SANDBOX_RELAY_PROTOCOL_VERSION,
            ),
            &mut authority,
            &mut live_admission,
            (&journal, &binding),
            &relay,
            &None,
            &mut HashMap::new(),
            &full,
        )
        .unwrap();
        let until = Instant::now() + Duration::from_secs(3);
        loop {
            let refusals = relay.poll_refusals();
            if !refusals.is_empty() {
                for (kind, finished) in refusals {
                    send_finished(
                        &mut socket,
                        WireCodes::negotiated("1.0"),
                        Some(&kind),
                        finished,
                    )
                    .unwrap();
                }
                break;
            }
            assert!(Instant::now() < until);
            thread::sleep(Duration::from_millis(2));
        }
        assert!(matches!(
            sandbox_protocol::parse_daemon_control(wire.read().unwrap().to_text().unwrap())
                .unwrap(),
            DaemonControlMessage::OperationResult {
                state: OperationState::UnknownOutcome,
                error: Some(ProtocolErrorDetail {
                    reason: None,
                    code: sandbox_protocol::WireErrorCode::Known(SandboxErrorCode::HostCapacity),
                    ..
                }),
                ..
            }
        ));
        assert!(journal.lookup("full").is_none());
        assert_eq!(
            live_admission.held(),
            0,
            "journal refusal precedes live reservation"
        );
        let mut stop = full;
        stop.kind = "sandbox.stop".into();
        stop.lease = None;
        stop.digest_scheme = Some("sha256-env-free-v1".into());
        stop.digest_key_id = None;
        stop.cpu_count = None;
        stop.memory_mi_b = None;
        stop.operation_id = "stop".into();
        stop.idempotency_key = "stop".into();
        stop.generation = 2;
        let stop = crate::sandbox_relay::test_support::pinned_dispatch(&stop);
        handle_dispatch(
            &mut socket,
            sandbox_protocol::WireCodes::negotiated(
                sandbox_protocol::SANDBOX_RELAY_PROTOCOL_VERSION,
            ),
            &mut authority,
            &mut live_admission,
            (&journal, &binding),
            &relay,
            &None,
            &mut HashMap::new(),
            &stop,
        )
        .unwrap();
        assert!(matches!(
            sandbox_protocol::parse_daemon_control(wire.read().unwrap().to_text().unwrap())
                .unwrap(),
            DaemonControlMessage::OperationProgress {
                state: OperationState::Accepted,
                ..
            }
        ));
        assert!(journal.lookup("stop").is_some());
        socket.send(Message::Ping(vec![7].into())).unwrap();
        assert!(matches!(wire.read().unwrap(), Message::Ping(_)));
    }
}

#[cfg(all(test, unix))]
#[path = "connect_capacity_tests.rs"]
mod capacity_tests;

#[cfg(test)]
mod transfer_settlement_tests {
    use super::*;
    use sandbox_runtime::FileContent;

    fn dispatch(id: &str, kind: &str, sandbox: &str) -> OperationDispatch {
        serde_json::from_value(serde_json::json!({"sandboxOwnerId": if sandbox == "sbx-2" { "other-owner" } else { "owner" },
            "operationId": id, "sandboxId": sandbox, "kind": kind, "idempotencyKey": id,
            "generation": 1, "attempt": 1, "path": "/home/user/f", "fileSize": 4,
            "fileSha256": "a".repeat(64),
            "bodyHash": "a".repeat(64)
        }))
        .unwrap()
    }
    fn put(dispatch: OperationDispatch, age: Duration) -> PendingFilePut {
        let spool =
            sandbox_runtime::FileStaging::for_creator(4, &dispatch.sandbox_owner_id).unwrap();
        PendingFilePut {
            reservation: super::super::supervisor::UploadReservation::for_test(
                &dispatch.sandbox_id,
                &dispatch.sandbox_owner_id,
            ),
            dispatch,
            instance_name: "wssp-sbx-sbx-1".into(),
            spool,
            next: 0,
            last: None,
            started: Instant::now() - age,
            touched: Instant::now() - age,
        }
    }
    fn finished(id: &str) -> FinishedOp {
        FinishedOp {
            operation_id: id.into(),
            sandbox_id: "sbx-1".into(),
            generation: 1,
            attempt: 1,
            state: OperationState::Succeeded,
            payload: Some(serde_json::json!({"path": "/home/user/f", "size": 3})),
            error: None,
            download: None,
            interim: false,
            readiness_detail: None,
            owner: None,
        }
    }

    /// G3: expiry settles every kind of host transfer state with a terminal
    /// outcome and completes exactly the authority it owns. Superseded state
    /// never completes its successor's authority; live state is untouched.
    #[test]
    fn expiry_delivers_terminal_outcomes_and_completes_only_owned_authority() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        let dir = tempfile::tempdir().unwrap();
        let binding = TransportBindingV11 {
            server: "wss://test".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
        };
        let journal =
            crate::sandbox_relay::test_support::open_ready_journal(dir.path(), &binding).unwrap();
        let authority = HostAuthority::default();
        let idle = TRANSFER_IDLE + Duration::from_secs(1);
        let mut pending_puts = HashMap::new();
        let mut downloads = Downloads::new();
        for (id, kind, sandbox) in [
            ("put-expired", "file.put", "sbx-1"),
            ("put-live", "file.put", "sbx-1"),
            ("put-old", "file.put", "sbx-2"),
            ("get-expired", "file.get", "sbx-1"),
            ("get-drained", "file.get", "sbx-1"),
            ("get-live", "file.get", "sbx-1"),
        ] {
            journal
                .record_fixture_intent(&intent_from_dispatch(
                    &journal,
                    &binding,
                    &dispatch(id, kind, sandbox),
                ))
                .unwrap();
            authority.accept_dispatch(id, sandbox, kind, 1, 1).unwrap();
        }
        pending_puts.insert(
            "put-expired".into(),
            put(dispatch("put-expired", "file.put", "sbx-1"), idle),
        );
        pending_puts.insert(
            "put-live".into(),
            put(dispatch("put-live", "file.put", "sbx-1"), Duration::ZERO),
        );
        pending_puts.insert(
            "put-old".into(),
            put(dispatch("put-old", "file.put", "sbx-2"), Duration::ZERO),
        );
        // A lifecycle stop revokes `put-old`; its stale pending entry must go
        // without completing the successor's authority.
        authority
            .accept_dispatch("stop", "sbx-2", "sandbox.stop", 1, 1)
            .unwrap();
        let bytes = FileContent::from_bytes(b"abc").unwrap();
        let mut expired = super::super::files::DownloadWindow::new(bytes.clone());
        expired.backdate(idle);
        let mut drained = super::super::files::DownloadWindow::new(bytes.clone());
        let frame = drained
            .poll("get-drained", 1, 1, Instant::now())
            .unwrap()
            .unwrap();
        drained.ack(frame.metadata.sequence, frame.body_len() as u64);
        assert!(drained.drained());
        let mut live = super::super::files::DownloadWindow::new(bytes);
        live.poll("get-live", 1, 1, Instant::now())
            .unwrap()
            .unwrap();
        downloads.insert("get-expired".into(), (finished("get-expired"), expired));
        downloads.insert("get-drained".into(), (finished("get-drained"), drained));
        downloads.insert("get-live".into(), (finished("get-live"), live));

        let mut delivered = settle_transfers(
            Instant::now(),
            &mut pending_puts,
            &mut downloads,
            &authority,
            &journal,
        )
        .unwrap();
        delivered.sort_by(|a, b| a.operation_id.cmp(&b.operation_id));
        let summary: Vec<_> = delivered
            .iter()
            .map(|item| {
                (
                    item.operation_id.as_str(),
                    item.state,
                    item.error.as_ref().and_then(|error| error.code.known()),
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                ("get-drained", OperationState::Succeeded, None),
                (
                    "get-expired",
                    OperationState::Failed,
                    Some(SandboxErrorCode::Timeout)
                ),
                (
                    "put-expired",
                    OperationState::Failed,
                    Some(SandboxErrorCode::Timeout)
                ),
            ]
        );
        assert!(delivered[1].payload.is_none(), "no bytes, no size claim");
        let receipt = journal.lookup("put-expired").unwrap();
        assert!(receipt.is_terminal());
        assert_eq!(receipt.state, OperationState::Failed);
        for id in ["put-expired", "get-expired", "get-drained"] {
            assert!(authority.pending(id).is_none(), "{id} authority completed");
        }
        assert!(authority.pending("put-old").is_none());
        assert!(authority.pending("stop").is_some(), "successor untouched");
        let revoked = journal.lookup("put-old").unwrap();
        assert_eq!(
            (revoked.state, revoked.error_code),
            (
                OperationState::Failed,
                Some(SandboxErrorCode::Cancelled.into())
            )
        );
        assert!(authority.pending("put-live").is_some());
        assert!(authority.pending("get-live").is_some());
        let mut remaining: Vec<_> = pending_puts.keys().chain(downloads.keys()).collect();
        remaining.sort();
        assert_eq!(remaining, ["get-live", "put-live"]);
        // Settlement is exactly-once: a second pass delivers nothing new.
        assert!(
            settle_transfers(
                Instant::now(),
                &mut pending_puts,
                &mut downloads,
                &authority,
                &journal,
            )
            .unwrap()
            .is_empty()
        );
    }

    /// Bad upload frames settle their own operation instead of tearing down
    /// the relay: gap, conflicting replay, oversize and manifest mismatch.
    #[test]
    fn refused_upload_frames_fail_only_their_operation() {
        let _staging = crate::sandbox_relay::test_support::staging_quota();
        let authority = HostAuthority::default();
        let frame = |id: &str, sequence: u64, offset: u64, end: bool| StreamBinaryMetadata {
            r#type: if end {
                StreamKind::End
            } else {
                StreamKind::Chunk
            },
            stream_id: format!("file-{id}"),
            operation_id: id.into(),
            generation: 1,
            attempt: 1,
            offset: Some(offset),
            gap_start: None,
            sequence,
            flags: Some(StreamChunkFlags {
                stdout: None,
                stderr: None,
                file_upload: Some(true),
                file_download: None,
                stdin: None,
            }),
            final_chunk: Some(end),
        };
        let mut pending = HashMap::new();
        for id in ["gap", "replay", "oversize", "mismatch"] {
            let sandbox = if id == "mismatch" { "sbx-2" } else { "sbx-1" };
            authority
                .accept_dispatch(id, sandbox, "file.put", 1, 1)
                .unwrap();
            pending.insert(
                id.to_string(),
                put(dispatch(id, "file.put", sandbox), Duration::ZERO),
            );
        }
        let code = |chunk: PutChunk| match chunk {
            PutChunk::Failed(_, code, _) => Some(code),
            PutChunk::Accepted => None,
            _ => panic!("unexpected outcome"),
        };
        assert_eq!(
            code(apply_file_put_chunk(
                &mut pending,
                &authority,
                &frame("gap", 1, 0, false),
                b"ab"
            )),
            Some(SandboxErrorCode::ProtocolError)
        );
        assert_eq!(
            code(apply_file_put_chunk(
                &mut pending,
                &authority,
                &frame("replay", 0, 0, false),
                b"ab"
            )),
            None
        );
        assert_eq!(
            code(apply_file_put_chunk(
                &mut pending,
                &authority,
                &frame("replay", 0, 0, false),
                b"ab"
            )),
            None,
            "identical replay is idempotent"
        );
        assert_eq!(
            code(apply_file_put_chunk(
                &mut pending,
                &authority,
                &frame("replay", 0, 0, false),
                b"zz"
            )),
            Some(SandboxErrorCode::ProtocolError)
        );
        assert_eq!(
            code(apply_file_put_chunk(
                &mut pending,
                &authority,
                &frame("oversize", 0, 0, true),
                b"12345"
            )),
            Some(SandboxErrorCode::RequestTooLarge)
        );
        assert_eq!(
            code(apply_file_put_chunk(
                &mut pending,
                &authority,
                &frame("mismatch", 0, 0, true),
                b"1234"
            )),
            Some(SandboxErrorCode::ProtocolError)
        );
        assert!(
            pending.is_empty(),
            "every refused upload left pending state"
        );
    }
}

#[cfg(all(test, unix))]
#[path = "connect_expiry_tests.rs"]
mod expiry_tests;

#[cfg(all(test, unix))]
#[path = "lifecycle_conformance_tests.rs"]
mod lifecycle_conformance_tests;

#[cfg(all(test, unix))]
#[path = "connect_capture_tests.rs"]
mod capture_tests;

#[cfg(all(test, unix))]
#[path = "connect_key_tests.rs"]
mod key_tests;

#[cfg(all(test, unix))]
#[path = "connect_adoption_tests.rs"]
mod adoption_tests;

#[cfg(test)]
mod image_verify_tests {
    use super::*;

    #[test]
    fn verification_includes_the_resolved_size_without_requiring_an_image_cache() {
        let resolved = sandbox_runtime::ResolvedHostImage {
            fingerprint: format!("sha256:{}", "a".repeat(64)),
            architecture: "x86_64".into(),
            size_bytes: Some(4096),
        };
        let frame = crate::sandbox_relay::plain_frame(&image_verified("r1", resolved)).unwrap();
        assert!(frame.contains("\"sizeBytes\":4096"));
    }
}

#[cfg(all(test, unix))]
#[path = "connect_credential_tests.rs"]
mod credential_tests;
