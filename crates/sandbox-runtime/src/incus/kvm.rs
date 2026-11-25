use crate::EffectOutcome;
use crate::before_issue::incus as pre;
use crate::before_issue::not_issued;
use crate::effect::PostIssueOutcome;
// Linux Incus/KVM implementation of SandboxRuntime.

use sandbox_protocol::{SandboxErrorCode, SandboxLifecycleState};

use crate::error::RuntimeError;
use crate::r#trait::{
    CreateSandboxRequest, CreateSandboxResponse, EntryInfo, ForkSandboxRequest,
    ForkSandboxResponse, KillSandboxRequest, KillSandboxResponse, ListDirRequest, ListDirResponse,
    ListProcessesRequest, ListProcessesResponse, MkdirRequest, MkdirResponse, MovePathRequest,
    ProbeSandboxRequest, ProbeSandboxResponse, ReadFileRequest, ReadFileResponse,
    ReconnectSandboxRequest, ReconnectSandboxResponse, RemovePathRequest, RemovePathResponse,
    RunCommandRequest, RunCommandResponse, SandboxLiveProbeState, SandboxRecord, SandboxRuntime,
    SignalProcessRequest, SnapshotRequest, SnapshotResponse, StatPathRequest, StopSandboxRequest,
    StopSandboxResponse, WriteFileRequest, WriteFileResponse, WriteStdinRequest,
    validate_managed_instance_name,
};

use super::client::{
    AgentWait, BoundInstance, IncusClient, METADATA_SANDBOX_ID, PassValidation, sandbox_not_running,
};
use super::effect_completion as evidence;
use super::exec::ExecSupervisor;
use super::guest_sudo::GuestSudoStep;
use sandbox_protocol::ReadinessFailureReason;

#[derive(Debug, Clone)]
pub struct IncusConfig {
    pub binary: String,
    pub project: String,
}

impl IncusConfig {
    pub fn from_env() -> Self {
        Self {
            binary: std::env::var("WSSP_INCUS_BINARY").unwrap_or_else(|_| "incus".to_string()),
            project: std::env::var("WSSP_INCUS_PROJECT").unwrap_or_else(|_| "wssp".to_string()),
        }
    }
}

#[derive(Clone)]
pub struct IncusKvmRuntime {
    client: IncusClient,
    supervisor: ExecSupervisor,
    policy_journal: std::sync::Arc<std::sync::Mutex<Option<crate::reconcile::PolicyJournal>>>,
    policy_health: std::sync::Arc<std::sync::Mutex<sandbox_protocol::PolicyReconcilerHealth>>,
    /// Shared by every clone (including `with_cancellation` scopes).
    dns_refresh: std::sync::Arc<super::dns_refresh::DnsRefreshScheduler>,
    /// B12 restart maintenance (stub recovery): one
    /// background worker shared by every clone, stopped with the last one.
    hint_maintenance: std::sync::Arc<super::dns_stub::HintMaintenance>,
}

impl IncusKvmRuntime {
    pub fn new(config: IncusConfig) -> Result<Self, RuntimeError> {
        let client = IncusClient::new(config.binary, config.project);
        client.ping()?;
        client.ensure_project()?;
        Ok(Self {
            supervisor: ExecSupervisor::new(client.clone()),
            client,
            policy_journal: Default::default(),
            policy_health: Default::default(),
            dns_refresh: Default::default(),
            hint_maintenance: Default::default(),
        })
    }

    pub fn with_root_disk(&self, root: &crate::RootDisk) -> Result<Self, RuntimeError> {
        Ok(Self {
            client: self.client.with_root_disk(root)?,
            ..self.clone()
        })
    }

    pub fn client(&self) -> &IncusClient {
        &self.client
    }

    /// Install the egress guard client the start fence attests through
    /// (§2.0.5). Until one is installed every start is refused.
    pub fn set_guard_probe(&mut self, probe: std::sync::Arc<dyn crate::guard::probe::GuardProbe>) {
        self.client.guard_probe = probe;
    }

    /// Test hook: the start fence's bridge wait.
    pub fn set_guard_fence_wait(&mut self, wait: std::time::Duration) {
        self.client.guard_fence_wait = wait;
    }

    /// Debug builds only (test daemons on an Incus double, whose "guest"
    /// terminate helper runs on the loaded host): widen the guest terminate
    /// helper's exec deadline. Never shortens it below
    /// [`GUEST_TERMINATE_TIMEOUT`](super::GUEST_TERMINATE_TIMEOUT). Sets the
    /// runtime's client and its supervisor's copy; call it before
    /// [`Self::exec_supervisor`], which hands out a clone of the client.
    #[cfg(any(test, debug_assertions))]
    pub fn set_guest_terminate_timeout(&mut self, timeout: std::time::Duration) {
        self.client.guest_terminate_timeout_override =
            Some(timeout.max(super::GUEST_TERMINATE_TIMEOUT));
        self.supervisor = self.supervisor.with_client(self.client.clone());
    }

    /// Test-only mutable client access (verdict-budget and failure-injection
    /// overrides, C37 R4).
    /// Test-only: wrap a shim-backed client without the daemon bootstrap
    /// (C51 PTY shim tests drive a minimal fake `incus`).
    #[cfg(test)]
    pub(crate) fn from_test_client(client: IncusClient) -> Self {
        Self {
            supervisor: ExecSupervisor::new(client.clone()),
            client,
            policy_journal: Default::default(),
            policy_health: Default::default(),
            dns_refresh: Default::default(),
            hint_maintenance: Default::default(),
        }
    }

    /// Test hook: wait until the B12 maintenance worker has ended.
    #[cfg(test)]
    pub(crate) fn wait_hint_maintenance(&self) -> bool {
        self.hint_maintenance
            .wait_finished(std::time::Duration::from_secs(20))
    }

    #[cfg(test)]
    pub(crate) fn dns_refresh_scheduler(&self) -> &super::dns_refresh::DnsRefreshScheduler {
        &self.dns_refresh
    }

    #[cfg(test)]
    pub(crate) fn client_mut(&mut self) -> &mut IncusClient {
        &mut self.client
    }

    fn cleanup_refused_create(&self, request: &CreateSandboxRequest) -> Result<(), RuntimeError> {
        let lock = self.client.sandbox_lock(&request.sandbox_id);
        let _guard = lock.lock().unwrap_or_else(|err| err.into_inner());
        // Rebind after acquiring the lock: a retry or lifecycle change may
        // have intervened since the refusal. Never delete a running or foreign VM.
        let bound = self.client.bind_instance(
            &request.instance_name,
            &request.sandbox_id,
            &request.template_digest,
            Some(&request.idempotency_key),
        )?;
        if !bound.is_stopped() {
            return Ok(());
        }
        // The same write-ahead and ownership fences as kill: a crash after
        // VM deletion still leaves a durable bridge/ACL teardown obligation.
        self.client.prepare_network_cleanup(&request.sandbox_id)?;
        self.client
            .delete_force(&bound)
            .map_err(crate::EffectError::into_error)?;
        self.client.teardown_sandbox_network(&request.sandbox_id)?;
        self.client
            .verify_sandbox_network_absent(&request.sandbox_id)?;
        self.client.clear_pending_cleanup(&request.sandbox_id)?;
        // A prior running incarnation may have recorded enforcement loss
        // before this stopped create retry. Verified absence fulfills that
        // obligation, exactly as kill does; failed cleanup retains it.
        self.client.clear_enforcement_loss(&request.sandbox_id)
    }

    /// C37 R3: act on one durably recorded enforcement loss. The drain is
    /// the always-running consumer every detection path (operation, receipt
    /// settle, census, probe) feeds: it re-verifies COHERENTLY before any
    /// destruction (a transient or inconclusive observation never tears
    /// down), never touches a foreign or unprovable instance, and tears a
    /// confirmed-drift VM down through the same write-ahead + tag-fenced
    /// ordering as a kill (obligation persisted BEFORE the VM is touched;
    /// the record retires only after verified network absence).
    fn drain_one_enforcement_loss(
        &self,
        sandbox_id: &str,
        settle: &dyn Fn(&str, crate::EnforcementLossStage) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        let name = crate::default_incus_instance_name(sandbox_id);
        let mut prepared = false;
        match self.client.bind_owned_instance(&name, sandbox_id) {
            Err(err) if err.code == SandboxErrorCode::SandboxNotFound => {
                // The VM is already gone: fall through to the fenced
                // network teardown and record retirement.
            }
            Err(err) if err.code == SandboxErrorCode::IdempotencyConflict => {
                // A FOREIGN (or unprovable) instance occupies the name:
                // never touched. The record stays — the census's binding
                // check fails closed on the same condition.
                return Ok(());
            }
            Err(err) => return Err(err),
            Ok(bound) => {
                match self.client.enforcement_observation(sandbox_id) {
                    super::acl::EnforcementVerdict::Verified => {
                        // Transient observation error at detection time:
                        // enforcement verifies now — retire, no action.
                        self.client.clear_enforcement_loss(sandbox_id)?;
                        return Ok(());
                    }
                    super::acl::EnforcementVerdict::Inconclusive(_) => {
                        // C37 R4: an inconclusive observation (timeout,
                        // cancellation, transport/daemon error, coherence
                        // budget) is NOT drift — keep the record, act
                        // never. Only confirmed drift authorizes cleanup.
                        return Ok(());
                    }
                    super::acl::EnforcementVerdict::ConfirmedDrift(_) => {}
                }
                // Lifecycle authority is captured before the sweep, never
                // inferred from a newer lease after destructive IO. A failed
                // generation/checkpoint veto must still halt current drift.
                if let Err(err) = settle(sandbox_id, crate::EnforcementLossStage::Prepare) {
                    let _ = self.client.halt_confirmed_breach(sandbox_id);
                    return Err(err);
                }
                prepared = true;
                // Confirmed drift. Write-ahead BEFORE the VM is touched —
                // the kill ordering: no crash window leaves an untracked
                // bridge/ACL.
                if let Err(err) = self.client.prepare_network_cleanup(sandbox_id) {
                    // C37 R6: teardown bookkeeping failed — halt the breach
                    // NOW through the ONE shared confirmed-drift boundary.
                    // The loss record already stands, so no later detection
                    // re-runs the boundary's persistence-failure stop;
                    // without this halt the unauthorized traffic stays
                    // live until lease expiry. Stop — never delete:
                    // destruction authority remains here once the journal
                    // write succeeds, and the retained record retries the
                    // teardown next pass. A halt failure never masks the
                    // bookkeeping error.
                    let _ = self.client.halt_confirmed_breach(sandbox_id);
                    return Err(err);
                }
                self.client
                    .delete_force(&bound)
                    .map_err(crate::EffectError::into_error)?;
            }
        }
        // Also checkpoint the already-absent recovery leg: a crash may have
        // deleted the VM before publishing its lifecycle completion.
        if !prepared {
            match settle(sandbox_id, crate::EnforcementLossStage::Prepare) {
                Ok(()) => {}
                // The lifecycle journal has already retired this sandbox.
                // This branch positively observed VM absence above; only
                // fenced network cleanup remains, never VM destruction.
                Err(err) if err.code == SandboxErrorCode::SandboxNotFound => {}
                Err(err) => return Err(err),
            }
        }
        // The VM is absent (already, or just deleted): the network teardown
        // runs through the fenced obligation, exactly as a kill's does.
        self.client.prepare_network_cleanup(sandbox_id)?;
        self.client
            .teardown_sandbox_network(sandbox_id)
            .and_then(|()| self.client.verify_sandbox_network_absent(sandbox_id))?;
        self.client.clear_pending_cleanup(sandbox_id)?;
        // Never retire the durable signal until its generation-fenced
        // lifecycle/capacity settlement is itself durable.
        settle(sandbox_id, crate::EnforcementLossStage::Complete)?;
        self.client.clear_enforcement_loss(sandbox_id)
    }

    /// Point durable host-side network state (cleanup journal, resolved
    /// plans, locks) at the host state dir the caller already resolved. The
    /// node daemon passes its relay state dir; without this the runtime falls
    /// back to the daemon's data dir (`WSSP_DATA_DIR`, then the platform
    /// default).
    pub fn set_host_state_dir(&mut self, dir: impl Into<std::path::PathBuf>) {
        self.client.set_host_state_dir(dir);
        if let Ok(body) = std::fs::read(
            self.client
                .state_root()
                .join("policy-reconciler/state.json"),
        ) && let Ok(journal) = serde_json::from_slice::<crate::reconcile::PolicyJournal>(&body)
        {
            // Historical observations never admit work after restart. Require
            // fresh coherent verification even for previously verified ids.
            self.client
                .policy_refusals
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend(journal.observations.keys().cloned());
            *self.policy_health.lock().unwrap_or_else(|e| e.into_inner()) = journal.health.clone();
            *self
                .policy_journal
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some(journal);
        }
    }

    /// Test-only wiring for deterministic subnet allocation and per-test
    /// cleanup journals; production resolves both from the host.
    #[cfg(test)]
    pub(crate) fn override_network_test_state(
        &mut self,
        state_dir: std::path::PathBuf,
        host_routes: Vec<(u32, u8)>,
    ) {
        #[cfg(test)]
        {
            // Model the administrator-provisioned shared lock directory:
            // per-test location, same shape (2770, owned by us).
            let lock_dir = state_dir.join("daemon-locks");
            std::fs::create_dir_all(&lock_dir).expect("test lock dir");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&lock_dir, std::fs::Permissions::from_mode(0o2770))
                    .expect("test lock dir mode");
            }
            self.client.daemon_lock_dir_override = Some(lock_dir);
        }
        self.client.state_dir = Some(state_dir);
        self.client.host_routes = Some(host_routes);
    }

    /// Test-only deterministic egress domain resolution.
    #[cfg(test)]
    pub(crate) fn override_resolver(&mut self, resolver: super::client::ResolveFn) {
        self.client.resolver = Some(super::client::TestResolver(resolver));
    }

    /// Test-only short agent-readiness budget so readiness-failure tests
    /// don't wait out the production timeout.
    #[cfg(test)]
    pub(crate) fn override_agent_timeout(&mut self, timeout: std::time::Duration) {
        self.client.agent_timeout = timeout;
    }

    pub fn exec_supervisor(&self) -> ExecSupervisor {
        self.supervisor.with_client(self.client.clone())
    }

    pub fn count_managed_vms(&self) -> Result<u32, RuntimeError> {
        self.sandbox_inventory()?.len().try_into().map_err(|_| {
            RuntimeError::new(SandboxErrorCode::HostCapacity, "host inventory too large")
        })
    }
}

/// The guest kernel's boot id, bound to a fresh host nonce.
pub(super) const GUEST_BOOT_ID_SCRIPT: &str = r#"IFS= read -r b < /proc/sys/kernel/random/boot_id || exit 1; printf 'WSSP_BOOT %s %s\n' "$1" "$b" >&2"#;

impl SandboxRuntime for IncusKvmRuntime {
    fn shutdown_local_children(&self) -> Result<(), RuntimeError> {
        self.client.shutdown_local_children()
    }

    fn reconcile_policies(&self, sandbox_ids: &[String]) -> Result<(), RuntimeError> {
        use crate::reconcile::{PolicyJournal, PolicyObservation};
        let mut state = self
            .policy_journal
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = self.client.state_root().join("policy-reconciler");
        let journal = state.get_or_insert_with(|| {
            std::fs::read(dir.join("state.json"))
                .ok()
                .and_then(|body| serde_json::from_slice::<PolicyJournal>(&body).ok())
                .unwrap_or_default()
        });
        journal.inspect(sandbox_ids, |id| {
            let lock = self.client.sandbox_lock(id);
            // An active managed transition is not drift. Do not wait behind
            // another operation and starve the remainder of this pass.
            let Ok(_guard) = lock.try_lock() else {
                // No observation occurred. Preserve the managed operation's
                // already-fenced authority rather than interrupt its internal
                // readiness helpers with a speculative dispatch refusal.
                return PolicyObservation::Pending;
            };
            let mut owed_cause = false;
            let observation = (|| {
                let mut scoped = self.client.clone();
                let permit = crate::RuntimePermit::with_timeout(std::time::Duration::from_secs(5));
                #[cfg(test)]
                let permit =
                    self.client
                        .policy_observation_budget_override
                        .map_or(permit, |budget| {
                            crate::RuntimePermit::with_test_clock(
                                budget,
                                std::sync::Arc::new(std::sync::Mutex::new(
                                    std::time::Instant::now(),
                                )),
                            )
                        });
                scoped.cancelled = Some(std::sync::Arc::new(permit));
                let captured = scoped.capture_enforcement_loss(id);
                let name = crate::default_incus_instance_name(id);
                let bound = match scoped.bind_owned_instance(&name, id) {
                    Ok(bound) => bound,
                    Err(err) if err.code == SandboxErrorCode::SandboxNotFound => {
                        return PolicyObservation::Absent;
                    }
                    Err(err) if err.code == SandboxErrorCode::IdempotencyConflict => {
                        return PolicyObservation::Foreign;
                    }
                    Err(_) => return PolicyObservation::Inconclusive,
                };
                // This is the SAME coherent/lifecycle-owned boundary used by
                // readiness, probes and census. No parallel verdict classifier,
                // live repair, or DNS refresh scheduling is introduced here.
                match scoped.verify_captured_bound_enforcement(bound.is_running(), captured) {
                    Ok(()) => PolicyObservation::Verified,
                    Err(err) if err.code == SandboxErrorCode::GuestUnavailable => {
                        // Prepare revoked dispatch authority before returning.
                        // Also cut existing traffic now, even when all journals
                        // succeeded. Stop only; destruction stays in the existing
                        // mandatory Prepare/Complete drain and expiry workers.
                        let _ = scoped.halt_confirmed_breach(id);
                        PolicyObservation::Drift
                    }
                    Err(err) if err.code == SandboxErrorCode::IdempotencyConflict => {
                        // Includes stopped drift and stale-authority/fresh-healthy
                        // refusal: NEVER authorize an additional mutation here.
                        PolicyObservation::Inconclusive
                    }
                    Err(err) => {
                        // C58 G1-R1-3: remember WHY — only a refusal caused
                        // by an owed refresh may be cleared by that refresh.
                        owed_cause = err.is_refresh_owed();
                        PolicyObservation::Inconclusive
                    }
                }
            })();
            {
                let mut owed = self
                    .client
                    .owed_refusals
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if owed_cause && matches!(observation, PolicyObservation::Inconclusive) {
                    owed.insert(id.to_owned());
                } else {
                    owed.remove(id);
                }
            }
            if matches!(
                observation,
                PolicyObservation::Drift
                    | PolicyObservation::Inconclusive
                    | PolicyObservation::Foreign
            ) {
                self.client
                    .policy_refusals
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(id.to_owned());
            }
            observation
        });
        *self.policy_health.lock().unwrap_or_else(|e| e.into_inner()) = journal.health.clone();
        let body = serde_json::to_string(journal).map_err(|err| {
            RuntimeError::new(
                SandboxErrorCode::Internal,
                format!("cannot encode policy health: {err}"),
            )
        })?;
        // The existing atomic fsync+rename journal boundary. Even if storage
        // fails, memory retains rotation and C37 retains restrictive recovery.
        self.client.write_durable_record(&dir, "state.json", &body)
    }

    fn refresh_dns_grants(&self, sandbox_ids: &[String]) -> Result<(), RuntimeError> {
        self.refresh_dns_grants_observed(sandbox_ids, &|_| {})
    }

    fn refresh_dns_grants_observed(
        &self,
        sandbox_ids: &[String],
        observe: &dyn Fn(&crate::DnsRefreshReport),
    ) -> Result<(), RuntimeError> {
        let pass = super::dns_refresh::refresh_pass(&self.client, &self.dns_refresh, sandbox_ids)?;
        for report in &pass.reports {
            observe(report);
        }
        match pass.failed.first() {
            None => Ok(()),
            // Failures never extend a grant (the armed lease still fences at
            // its expiry); report them for the operator log.
            Some((_, first)) => Err(RuntimeError::new(
                first.code,
                format!(
                    "{} of {} due DNS grant refreshes failed; grants lapse at their armed expiry unless a retry succeeds (first: {})",
                    pass.failed.len(),
                    pass.failed.len() + pass.refreshed.len() + pass.skipped.len(),
                    first.message
                ),
            )),
        }
    }

    fn policy_reconciler_health(&self) -> sandbox_protocol::PolicyReconcilerHealth {
        self.policy_health
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn set_enforcement_loss_lifecycle(
        &self,
        lifecycle: std::sync::Arc<dyn crate::EnforcementLossLifecycle>,
    ) {
        *self
            .client
            .loss_lifecycle
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(lifecycle);
    }

    fn egress_enforcement_capability(&self) -> Result<bool, RuntimeError> {
        self.client.egress_enforcement_capability()
    }

    fn egress_open_capability(
        &self,
        settings: &crate::egress::EgressSettings,
    ) -> Result<bool, RuntimeError> {
        // Static: guard health is never part of it (a guard that is down at
        // hello must not freeze a downgrade for the whole connection); the
        // live lease gate (daemon + server) owns guard health.
        if !self.egress_enforcement_capability()? {
            return Ok(false);
        }
        // Risk 5: dnsmasq forwards open-mode queries to the host resolv.conf
        // unless upstreams are configured; without either it cannot resolve.
        Ok(!settings.dns_upstreams.is_empty() || super::dns::host_dns_servers().is_ok())
    }

    fn egress_guard_probe(&self) -> Option<std::sync::Arc<dyn crate::guard::probe::GuardProbe>> {
        Some(self.client.guard_probe.clone())
    }

    /// B12: build VMs in allowlist mode forward non-granted names to a
    /// daemon-run in-memory DNS stub (`incus/dns_stub.rs`).
    fn refused_dns_hints_capability(&self) -> bool {
        true
    }

    /// The refusals recorded since the last drain: an in-memory queue read
    /// on the socket thread. The first call starts the background worker
    /// that re-binds the stubs of recorded build plans (daemon restart); it
    /// never waits for it.
    fn drain_refused_dns_names(&self) -> Vec<(String, String)> {
        self.hint_maintenance.start(&self.client);
        self.client.dns_stubs.drain()
    }

    /// CLI-logins proxy mode: every sandbox has its own bridge, and
    /// a sandbox created with a proxied login records the gateway allow
    /// (`wssp-credential-proxy`) in its network plan.
    fn bind_restore_base(&self, sandbox_id: &str, restore_base: &str) {
        self.client.set_restore_base(sandbox_id, Some(restore_base));
    }
    fn unbind_restore_base(&self, sandbox_id: &str) {
        self.client.set_restore_base(sandbox_id, None);
    }
    fn supports_credential_proxy(&self) -> bool {
        true
    }

    /// The recorded bridge gateway and proxy port, only for a sandbox whose
    /// recorded plan carries the proxy allow for exactly that endpoint: the
    /// proxy never listens where the guest's ACL would drop it, a daemon
    /// restart re-binds on the port the sandbox was created with (whatever
    /// the current configuration says), and a sandbox without one fails its
    /// install closed.
    fn credential_proxy_endpoint(&self, sandbox_id: &str) -> Option<std::net::SocketAddrV4> {
        let plan = self.client.persisted_enforcement_plan(sandbox_id)?;
        let port = plan.settings.as_ref()?.credential_proxy_port?;
        let gateway = format!("{}/32", plan.gateway);
        let port_text = port.to_string();
        plan.rules
            .iter()
            .any(|rule| {
                rule.description == super::network::CREDENTIAL_PROXY_RULE_TAG
                    && rule.destination.as_deref() == Some(gateway.as_str())
                    && rule.destination_port.as_deref() == Some(port_text.as_str())
            })
            .then_some(std::net::SocketAddrV4::new(plan.gateway, port))
    }

    fn tunnel_target(&self, sandbox_id: &str) -> Option<(std::net::Ipv4Addr, Vec<u16>)> {
        let plan = self.client.persisted_enforcement_plan(sandbox_id)?;
        let guest = plan.pinned_guest_address()?;
        // The committed rule must be recorded exactly as compiled for the
        // committed ports; the client may forward only what every possibly
        // live variant admits (committed ∩ an unconfirmed change).
        let expected = super::network::tunnel_ingress_rule(plan.gateway, plan.tunnel_ports())?;
        let ruled = plan
            .rules
            .iter()
            .filter(|rule| rule.description == super::network::TUNNEL_INGRESS_RULE_TAG)
            .eq(std::iter::once(&expected));
        let ports = plan.tunnel_target_ports();
        // The plan alone is not enough: its bridge must still exist.
        (ruled && !ports.is_empty() && self.client.live_network_matches(&plan))
            .then_some((guest, ports))
    }

    fn update_tunnel_ports(
        &self,
        sandbox_id: &str,
        revision: u64,
        ports: &[u16],
        before_acl: &dyn Fn(&[u16]),
    ) -> Result<crate::TunnelPortsUpdate, RuntimeError> {
        self.client
            .update_tunnel_ports(sandbox_id, revision, ports, before_acl)
    }

    fn egress_guard_check(&self) -> Result<(), RuntimeError> {
        crate::guard::probe::check_guard(self.client.guard_probe.as_ref())
    }

    fn egress_enforcement_unavailable_reason(&self) -> Option<String> {
        match self.client.egress_support() {
            Ok(support) => support.unavailable_reason(),
            Err(err) => Some(format!(
                "the incus daemon could not be queried for egress support: {err}"
            )),
        }
    }

    /// C37 R3: the always-running consumer for durably recorded
    /// bound-enforcement losses. Every record is acted on under the
    /// per-sandbox lock (serialized with any concurrent apply, reconnect,
    /// or kill for that sandbox). C37 R7: the pass is FAILURE-ISOLATED
    /// with a ROTATING cursor — the same scheduling boundary as the
    /// network-cleanup drain (`drain_pending_network_cleanups`). A
    /// record that keeps failing (for example an unwritable
    /// `network-cleanups` journal, whose confirmed breach is halted by
    /// the fail-safe stop but never retires) must not strand the breaches
    /// behind it: per-record errors are aggregated and surfaced AFTER the
    /// rest of the pass, and the cursor (`.drain-cursor` in the journal
    /// directory, a best-effort progress hint — never evidence) resumes
    /// the next pass AFTER the last attempted record, wrapping around, so
    /// the retained record can never monopolize the head of every sweep
    /// or hide records beyond the 256-per-pass bound.
    fn drain_enforcement_losses(
        &self,
        settle: &dyn Fn(&str, crate::EnforcementLossStage) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        let ids = self.client.enforcement_loss_sandbox_ids()?;
        let dir = self.client.enforcement_loss_dir();
        // Rotate: resume after the last record the previous drain
        // attempted, wrapping around. A lost cursor only restarts the
        // rotation.
        let cursor = std::fs::read_to_string(dir.join(".drain-cursor"))
            .map(|body| body.trim().to_owned())
            .unwrap_or_default();
        let start = ids.iter().position(|id| id > &cursor).unwrap_or(0);
        let mut ordered: Vec<String> = ids[start..].to_vec();
        ordered.extend_from_slice(&ids[..start]);
        ordered.truncate(256);
        let mut first_error: Option<RuntimeError> = None;
        let mut last_attempted: Option<String> = None;
        for sandbox_id in ordered {
            let sandbox_lock = self.client.sandbox_lock(&sandbox_id);
            let _guard = match sandbox_lock.try_lock() {
                Ok(guard) => guard,
                Err(std::sync::TryLockError::Poisoned(err)) => err.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => continue,
            };
            last_attempted = Some(sandbox_id.clone());
            // Failure isolation: one failing record never blocks the rest
            // of the pass; the FIRST failure is reported after it.
            if let Err(err) = self.drain_one_enforcement_loss(&sandbox_id, settle)
                && first_error.is_none()
            {
                first_error = Some(err);
            }
        }
        if let Some(id) = last_attempted {
            // Best-effort: the next pass resumes AFTER this record.
            let _ = IncusClient::write_private_file(&dir.join(".drain-cursor"), id.as_bytes());
        }
        if let Some(err) = first_error {
            return Err(err);
        }
        Ok(())
    }

    fn default_storage_pool(&self) -> Result<String, RuntimeError> {
        self.client
            .profile_root_device(
                sandbox_protocol::VmSize::defaults()
                    .map_err(|_| crate::storage::storage_error("invalid VM defaults"))?,
            )
            .map(|(_, pool)| pool)
    }
    fn initialize_storage_pool(
        &self,
        name: &str,
        expected: Option<&crate::StoragePoolIdentity>,
    ) -> Result<crate::StoragePoolIdentity, RuntimeError> {
        self.client.initialize_storage_marker(name, expected)
    }
    fn observe_storage_pool(
        &self,
        pool: &crate::StoragePoolIdentity,
    ) -> Result<crate::StoragePoolObservation, RuntimeError> {
        self.client.observe_storage_pool(pool)
    }
    fn storage_root_census(
        &self,
        pool: &crate::StoragePoolIdentity,
    ) -> Result<crate::StorageRootCensus, RuntimeError> {
        self.client.storage_root_census(pool)
    }
    fn storage_physical_usage(
        &self,
        pool: &crate::StoragePoolIdentity,
        roots: &[String],
        commitments: u64,
    ) -> Result<crate::PhysicalUsage, RuntimeError> {
        self.client.storage_physical_usage(pool, roots, commitments)
    }
    fn prove_root_absent(
        &self,
        root: &crate::RootDisk,
        name: &str,
    ) -> Result<crate::RootAbsenceProof, RuntimeError> {
        self.client.prove_root_absent(root, name)
    }
    fn create_sandbox_on_storage(
        &self,
        request: &CreateSandboxRequest,
        root: &crate::RootDisk,
    ) -> EffectOutcome<CreateSandboxResponse> {
        self.with_root_disk(root)?.create_bound(request)
    }
    fn reconnect_sandbox_on_storage(
        &self,
        request: &ReconnectSandboxRequest,
        root: &crate::RootDisk,
    ) -> EffectOutcome<ReconnectSandboxResponse> {
        self.with_root_disk(root)?.reconnect_bound(request)
    }
    fn kill_sandbox_on_storage(
        &self,
        request: &KillSandboxRequest,
        root: &crate::RootDisk,
    ) -> EffectOutcome<KillSandboxResponse> {
        self.with_root_disk(root)?.kill_bound(request)
    }

    fn host_resources(&self) -> Result<crate::HostResources, RuntimeError> {
        self.client.host_resources()
    }

    fn sandbox_inventory(&self) -> Result<Vec<crate::RuntimeInventoryEntry>, RuntimeError> {
        self.sandbox_inventory_skipping(&std::collections::HashSet::new())
    }

    fn sandbox_inventory_skipping(
        &self,
        busy: &std::collections::HashSet<String>,
    ) -> Result<Vec<crate::RuntimeInventoryEntry>, RuntimeError> {
        let mut client = self.client.clone();
        client.inspection_permit = client.cancelled.clone();
        // Startup owns DNS expiry obligation recovery (C36 r29 F1):
        // host startup reaches the runtime HERE, and neither the network
        // drain nor the instance listing below may run first — those
        // daemon observations can stall, and an expired allow must never
        // stay effective on a running VM because nothing triggered
        // recovery. The ledgers are enumerated from disk, so this costs
        // no daemon round-trip when nothing is armed; a settlement
        // failure fails the census closed rather than reporting an
        // unrecovered sandbox Ready.
        client.recover_all_dns_expiry_obligations()?;
        // Restart reconciliation doubles as the fenced drain for network
        // cleanup obligations a revoked worker could not finish. A busy
        // sandbox's obligation is left to a later drain (live finding R-1).
        client.drain_pending_network_cleanups_skipping(busy)?;
        let mut inventory = Vec::new();
        for row in client.list_instances()? {
            if row.instance_type != "virtual-machine"
                || validate_managed_instance_name(&row.name).is_err()
            {
                continue;
            }
            let tag = if row.config.is_empty() {
                client.inventory_sandbox_id(&row.name)?
            } else {
                row.config
                    .get(METADATA_SANDBOX_ID)
                    .and_then(|v| v.as_str())
                    .map(str::to_owned)
            };
            let Some(id) = tag.filter(|id| !id.is_empty()) else {
                continue;
            };
            if crate::default_incus_instance_name(&id) != row.name {
                return Err(RuntimeError::new(
                    SandboxErrorCode::IdempotencyConflict,
                    "inventory instance binding differs",
                ));
            }
            let state = if row.status.eq_ignore_ascii_case("stopped") {
                SandboxLifecycleState::Stopped
            } else if row.status.eq_ignore_ascii_case("running") && busy.contains(&id) {
                // Its in-flight work holds the lifecycle lock (possibly for a
                // whole boot): never wait on it here. Not vouched for, so
                // never a false Ready; a later census verifies it (R-1).
                SandboxLifecycleState::Unreachable
            } else if row.status.eq_ignore_ascii_case("running") {
                // C37 R2: the census certifies a bound running VM Ready only
                // through THE bound-enforcement boundary — the same
                // verification every readiness/runnability consumer passes.
                // A lost or tampered ACL reports Unreachable (the host
                // cannot vouch for the guest), never a false Ready. The
                // census is observational: cleanup for such a VM is driven
                // by the op-result paths (warm reconnect, query-settled
                // receipt, readiness) where the same boundary surfaces
                // GuestUnavailable to the generation-fenced cleanup.
                match client.verify_bound_enforcement(&id, true) {
                    Ok(()) => SandboxLifecycleState::Ready,
                    Err(_) => SandboxLifecycleState::Unreachable,
                }
            } else {
                SandboxLifecycleState::Provisioning
            };
            let sized = match &row.expanded_config {
                Some(config) => crate::resources::configured_vm_size(config),
                None => client.configured_vm_size(&row.name),
            };
            let configured_size = match sized {
                Ok(size) => crate::ConfiguredSize::Configured(size),
                Err(error) if error.code == SandboxErrorCode::VmSizeMismatch => {
                    crate::ConfiguredSize::Conflict
                }
                Err(error) => crate::ConfiguredSize::Unobserved(error),
            };
            inventory.push(crate::RuntimeInventoryEntry {
                sandbox_id: id,
                state,
                configured_size,
            });
        }
        let vm_ids: Vec<_> = inventory
            .iter()
            .map(|entry| entry.sandbox_id.clone())
            .collect();
        client.drain_pending_network_cleanups_skipping(busy)?;
        // A census only observes loss. The service-owned drain supplies the
        // generation-fenced lifecycle checkpoints; deleting here would bypass
        // both connected server settlement and local capacity release.
        // Absence evidence must include the network: while teardown evidence
        // is outstanding (journal or leftover owned objects), the census
        // reports the sandbox as still provisioning rather than omitting it —
        // an omission would read as successful-kill evidence downstream.
        for id in client.network_cleanup_sandbox_ids()? {
            if vm_ids.iter().any(|vm| vm == &id) {
                continue;
            }
            if client.network_cleanup_outstanding(&id)? {
                inventory.push(crate::RuntimeInventoryEntry {
                    sandbox_id: id,
                    state: SandboxLifecycleState::Provisioning,
                    configured_size: crate::ConfiguredSize::NoInstance,
                });
            }
        }
        Ok(inventory)
    }

    fn with_cancellation(
        &self,
        cancelled: std::sync::Arc<crate::RuntimePermit>,
    ) -> Box<dyn SandboxRuntime> {
        let mut scoped = self.clone();
        scoped.client.cancelled = Some(cancelled);
        scoped.supervisor = scoped.exec_supervisor();
        Box::new(scoped)
    }
    fn query_sandbox(
        &self,
        sandbox_id: &str,
        create_key: Option<&str>,
        template_fingerprint: Option<&str>,
    ) -> Result<Option<SandboxLifecycleState>, RuntimeError> {
        let name = crate::default_incus_instance_name(sandbox_id);
        let instance = match self.client.bind_instance(
            &name,
            sandbox_id,
            template_fingerprint.unwrap_or_default(),
            create_key,
        ) {
            Ok(instance) => instance,
            Err(err) if err.code == SandboxErrorCode::SandboxNotFound => {
                // Kill completion evidence requires network absence too: while
                // bridge/ACL cleanup is still owed, the sandbox is not absent.
                // Retain fenced cleanup ownership and try to finish it here.
                if self.client.network_cleanup_outstanding(sandbox_id)? {
                    let _ = self.client.drain_pending_network_cleanups();
                    if self.client.network_cleanup_outstanding(sandbox_id)? {
                        return Ok(Some(SandboxLifecycleState::Provisioning));
                    }
                }
                return Ok(None);
            }
            Err(err) => return Err(err),
        };
        Ok(Some(if instance.is_running() {
            // A running VM is only recovered allocation success when its
            // egress enforcement is verified: a crash between the network
            // apply and the NIC check leaves a running VM whose networking
            // was never enforced, and Ready would convert to a receipt.
            // C37 R2: verified through THE bound-enforcement boundary — this
            // VM is positively bound AND running, so a lost or tampered ACL
            // surfaces as GuestUnavailable, and the receipt settle that
            // consumes this result triggers the relay's generation-fenced
            // cleanup (a raw conflict code would leave the running,
            // unenforced VM to lease expiry).
            let spec = self
                .client
                .with_verified_enforcement(sandbox_id, true, || {
                    let spec = self.client.persisted_readiness(&instance)?;
                    // I11: the create's persisted mode (bootstrap for a
                    // community prep build VM), never a request field.
                    self.client.with_guest(&spec.guest).verify_guest_mode(
                        &instance,
                        Some(&spec.architecture),
                        spec.mode,
                    )?;
                    Ok(spec)
                })?;
            // Allocation recovery of a fresh create (its create key) re-runs the
            // root growth check the crash may have cut short; idempotent for a
            // grown root. Never for other queries (probes, expiry, reconnect).
            if let (Some(_), Some(disk_bytes)) = (create_key, spec.root_disk_bytes) {
                self.client
                    .with_verified_enforcement(sandbox_id, true, || {
                        self.client
                            .with_guest(&spec.guest)
                            .guest_root_grow_step(&instance, disk_bytes)
                    })?;
            }
            // R2: allocation recovery re-applies guest sudo from the spec in
            // its own fenced section (never the create-time audit). A grant
            // failure is GuestUnavailable with its reason, which triggers the
            // fenced cleanup above.
            self.client
                .with_verified_enforcement(sandbox_id, true, || {
                    self.client
                        .with_guest(&spec.guest)
                        .guest_sudo_step(&instance, GuestSudoStep::for_boot(spec.privilege.sudo))
                })?;
            SandboxLifecycleState::Ready
        } else if instance.is_stopped() {
            SandboxLifecycleState::Stopped
        } else {
            SandboxLifecycleState::Provisioning
        }))
    }

    fn resolve_image_ref(&self, image_ref: &str) -> Result<crate::ResolvedHostImage, RuntimeError> {
        self.client.resolve_image_ref(image_ref)
    }

    fn import_image(&self, path: &std::path::Path) -> Result<String, RuntimeError> {
        crate::guard::probe::refuse_shared_incus_server(self.client.guard_probe.as_ref())?;
        self.client.image_import(path)
    }

    fn import_split_image(
        &self,
        meta: &std::path::Path,
        disk: &std::path::Path,
        expected: &str,
    ) -> Result<String, RuntimeError> {
        crate::guard::probe::refuse_shared_incus_server(self.client.guard_probe.as_ref())?;
        self.client.image_import_split(meta, disk, expected)
    }

    fn export_image(
        &self,
        fingerprint: &str,
        dir: &std::path::Path,
    ) -> Result<Vec<std::path::PathBuf>, RuntimeError> {
        self.client.image_export(fingerprint, dir)
    }

    fn delete_image(&self, fingerprint: &str) -> Result<(), RuntimeError> {
        self.client.image_delete(fingerprint)
    }

    fn list_image_fingerprints(&self) -> Result<std::collections::BTreeSet<String>, RuntimeError> {
        self.client.image_fingerprints()
    }

    fn image_protected(&self, fingerprint: &str) -> Result<bool, RuntimeError> {
        self.client.image_protected(fingerprint)
    }

    fn publish_stopped_instance(
        &self,
        instance_name: &str,
        alias: &str,
    ) -> Result<crate::PublishedDisk, RuntimeError> {
        self.client.publish_stopped_instance(instance_name, alias)
    }

    fn instance_last_used(&self, instance_name: &str) -> Result<Option<String>, RuntimeError> {
        self.client.instance_last_used(instance_name)
    }

    fn cloud_init_instance_id(&self, instance_name: &str) -> Result<Option<String>, RuntimeError> {
        self.client.cloud_init_instance_id(instance_name)
    }

    fn instance_root_usage(&self, instance_name: &str) -> Result<Option<u64>, RuntimeError> {
        self.client.instance_root_usage(instance_name)
    }

    fn offload_aliases(&self) -> Result<Vec<crate::OffloadAlias>, RuntimeError> {
        self.client.offload_aliases()
    }

    fn instance_operation_running(&self, instance_name: &str) -> Result<bool, RuntimeError> {
        self.client.instance_operation_running(instance_name)
    }

    fn delete_orphan_root(
        &self,
        root: &crate::RootDisk,
        instance_name: &str,
    ) -> Result<(), RuntimeError> {
        self.client.delete_orphan_root(root, instance_name)
    }

    fn capture_template(
        &self,
        request: &crate::CaptureRequest,
        progress: &dyn Fn(crate::CapturePhase),
    ) -> Result<crate::CaptureOutcome, RuntimeError> {
        // A capture publishes a new template image into the shared store.
        crate::guard::probe::refuse_shared_incus_server(self.client.guard_probe.as_ref())?;
        self.client.capture_template(request, progress)
    }

    fn discard_capture(&self, sandbox_id: &str, operation_id: &str) -> Result<(), RuntimeError> {
        self.client.discard_capture(sandbox_id, operation_id)
    }

    fn credential_pack(
        &self,
        request: &crate::CredentialPackRequest,
    ) -> Result<crate::CredentialPackOutcome, RuntimeError> {
        self.client.credential_pack(request)
    }

    fn credential_restore(
        &self,
        request: &crate::CredentialRestoreRequest<'_>,
    ) -> Result<crate::CredentialRestoreOutcome, RuntimeError> {
        self.client.credential_restore(request)
    }

    fn credential_scrub(
        &self,
        request: &crate::CredentialScrubRequest,
    ) -> Result<crate::CredentialScrubOutcome, RuntimeError> {
        self.client.credential_scrub(request)
    }

    fn credential_quiesce(
        &self,
        guest: &crate::CredentialGuest,
    ) -> Result<crate::CredentialQuiesceOutcome, RuntimeError> {
        self.client.credential_quiesce(guest)
    }

    fn credential_helper_present(
        &self,
        guest: &crate::CredentialGuest,
    ) -> Result<bool, RuntimeError> {
        self.client.credential_helper_present(guest)
    }

    fn sandbox_exists(&self, sandbox_id: &str) -> Result<bool, RuntimeError> {
        let name = crate::resolve_managed_instance_name(sandbox_id, None)?;
        self.client.instance_exists(&name)
    }

    fn sandbox_may_be_running(&self, sandbox_id: &str) -> Result<bool, RuntimeError> {
        let name = crate::resolve_managed_instance_name(sandbox_id, None)?;
        self.client.instance_may_be_running(&name)
    }

    fn run_command(&self, request: &RunCommandRequest) -> crate::EffectOutcome<RunCommandResponse> {
        self.run_command_stream(request, &crate::CommandOutput::default())
    }
    fn run_command_stream(
        &self,
        request: &RunCommandRequest,
        output: &crate::CommandOutput,
    ) -> crate::EffectOutcome<RunCommandResponse> {
        pre::phase(
            |before| {
                pre::command(&before, request)?;
                let bound = pre::binding(
                    &before,
                    &self.client,
                    &request.instance_name,
                    &request.sandbox_id,
                    &request.template_fingerprint,
                )?;
                pre::running(&before, &self.client, &bound)?;

                before.issue(|| {
                    let response = self
                        .exec_supervisor()
                        .with_output(output.clone())
                        .run(&bound, request)?;
                    Ok(response)
                })
            },
            Ok,
        )
    }

    fn pty_capability(&self) -> bool {
        true
    }

    /// C51: the instance is derived from the sandbox id (never supplied),
    /// positively bound against host metadata, and must be Running. The
    /// session id is reserved FIRST, so a concurrent stop/delete either
    /// dooms this open or is observed by the binding.
    fn open_pty(
        &self,
        request: &crate::OpenPtyRequest,
    ) -> Result<crate::PtySession, crate::PtyOpenFailure> {
        let lifetime = request.validate()?;
        let name = crate::resolve_managed_instance_name(&request.sandbox_id, None)?;
        let client = self.client.with_guest(&request.guest);
        let reservation = client
            .pty_sessions
            .reserve(&request.session_id, &request.sandbox_id)?;
        if !request.env.is_empty() {
            return super::pty::open_with_env(&client, request, reservation, lifetime);
        }
        let bound = client.bind_instance(
            &name,
            &request.sandbox_id,
            &request.template_fingerprint,
            None,
        )?;
        require_running(&bound)?;
        super::pty::open(&client, &bound, request, reservation, lifetime)
    }

    fn close_pty_sessions(&self, sandbox_id: Option<&str>, intent: crate::PtyCloseIntent) -> usize {
        self.client.pty_sessions.close_matching(sandbox_id, intent)
    }

    fn channel_capability(&self) -> bool {
        true
    }

    fn spawn_channel(
        &self,
        request: &crate::SpawnChannelRequest,
    ) -> Result<crate::SpawnedChannel, crate::ChannelOpenFailure> {
        super::channel::spawn(&self.client, request)
    }

    fn kill_channel_scopes(
        &self,
        request: &crate::KillScopesRequest,
    ) -> Result<Vec<(String, crate::ScopeKill)>, RuntimeError> {
        super::channel::kill_scopes(&self.client, request)
    }

    fn read_file(&self, request: &ReadFileRequest) -> Result<ReadFileResponse, RuntimeError> {
        let client = self.client.with_guest(&request.guest);
        let bound = client.bind_instance(
            &request.instance_name,
            &request.sandbox_id,
            &request.template_fingerprint,
            None,
        )?;
        require_running(&bound)?;
        let bytes =
            client.file_pull_for_creator(&bound, &request.path, &request.sandbox_owner_id)?;
        let response = ReadFileResponse {
            path: request.path.clone(),
            bytes,
        };
        Ok(response)
    }

    fn write_file(&self, request: &WriteFileRequest) -> EffectOutcome<WriteFileResponse> {
        let client = self.client.with_guest(&request.guest);
        pre::phase(
            |before| {
                let bound = pre::binding(
                    &before,
                    &client,
                    &request.instance_name,
                    &request.sandbox_id,
                    &request.template_fingerprint,
                )?;
                pre::running(&before, &client, &bound)?;

                // The staging identity is bound to this attempt, so a host
                // crash can later settle it from guest evidence alone.
                let token = super::files::transfer_token(
                    &request.operation_id,
                    request.generation,
                    request.attempt,
                );
                before.issue(|| {
                    client
                        .file_put(&bound, &request.path, &request.bytes, &token)
                        .map(|proof| {
                            proof.map(|()| WriteFileResponse {
                                path: request.path.clone(),
                                bytes_written: request.bytes.len() as u64,
                            })
                        })
                })
            },
            Ok,
        )
    }
    fn recover_file_put(
        &self,
        request: &crate::RecoverFilePutRequest,
    ) -> EffectOutcome<WriteFileResponse> {
        let client = self.client.with_guest(&request.guest);
        let bound = client.bind_instance(
            &request.instance_name,
            &request.sandbox_id,
            &request.template_fingerprint,
            None,
        )?;
        require_running(&bound)?;
        client.recover_put(&bound, request).map(|proof| {
            proof.map(|()| WriteFileResponse {
                path: request.path.clone(),
                bytes_written: request.size,
            })
        })
    }

    fn stop_sandbox(&self, request: &StopSandboxRequest) -> EffectOutcome<StopSandboxResponse> {
        let _priority = self.client.request_lifecycle_priority(&request.sandbox_id);
        let name = &request.instance_name;

        let sandbox_lock = self.client.sandbox_lock(&request.sandbox_id);
        let _guard = sandbox_lock.lock().unwrap_or_else(|err| err.into_inner());
        pre::phase(
            |before| {
                let instance = self.client.bind_instance(
                    name,
                    &request.sandbox_id,
                    &request.template_fingerprint,
                    None,
                );

                before.issue(|| {
                    let proof = match instance {
                        Err(error) if error.code == SandboxErrorCode::SandboxNotFound => {
                            // A revoked boot may have allocated its network
                            // before init. No disk remains to reuse that
                            // network: settle it before confirming absence.
                            self.client.prepare_network_cleanup(&request.sandbox_id)?;
                            let absent = evidence::absent(&self.client, name)?;
                            self.client.teardown_sandbox_network(&request.sandbox_id)?;
                            self.client
                                .verify_sandbox_network_absent(&request.sandbox_id)?;
                            self.client.clear_pending_cleanup(&request.sandbox_id)?;
                            absent.map(|()| SandboxLifecycleState::Absent)
                        }
                        Err(error) => return Err(error.into()),
                        Ok(instance) if instance.is_stopped() => {
                            evidence::stopped_or_absent(&self.client, &instance)?
                        }
                        Ok(bound) => self.client.stop_force(&bound)?,
                    };
                    Ok(proof)
                })
            },
            |issued| {
                Ok(issued.map(|state| StopSandboxResponse {
                    sandbox: SandboxRecord {
                        sandbox_id: request.sandbox_id.clone(),
                        generation: 1,
                        state,
                        idempotency_key: request.idempotency_key.clone(),
                    },
                }))
            },
        )
    }

    fn stop_sandbox_graceful(
        &self,
        request: &StopSandboxRequest,
        timeout: std::time::Duration,
    ) -> EffectOutcome<StopSandboxResponse> {
        let _priority = self.client.request_lifecycle_priority(&request.sandbox_id);
        let name = &request.instance_name;
        let sandbox_lock = self.client.sandbox_lock(&request.sandbox_id);
        let _guard = sandbox_lock.lock().unwrap_or_else(|err| err.into_inner());
        pre::phase(
            |before| {
                let instance = self.client.bind_instance(
                    name,
                    &request.sandbox_id,
                    &request.template_fingerprint,
                    None,
                );
                before.issue(|| {
                    let proof = match instance {
                        Err(error) if error.code == SandboxErrorCode::SandboxNotFound => {
                            evidence::absent(&self.client, name)?
                                .map(|()| SandboxLifecycleState::Absent)
                        }
                        Err(error) => return Err(error.into()),
                        Ok(instance) if instance.is_stopped() => {
                            evidence::stopped_or_absent(&self.client, &instance)?
                        }
                        Ok(bound) => self.client.stop_graceful(&bound, timeout)?,
                    };
                    Ok(proof)
                })
            },
            |issued| {
                Ok(issued.map(|state| StopSandboxResponse {
                    sandbox: SandboxRecord {
                        sandbox_id: request.sandbox_id.clone(),
                        generation: 1,
                        state,
                        idempotency_key: request.idempotency_key.clone(),
                    },
                }))
            },
        )
    }

    fn list_dir(&self, request: &ListDirRequest) -> Result<ListDirResponse, RuntimeError> {
        let client = self.client.with_guest(&request.guest);
        let bound = client.bind_instance(
            &request.instance_name,
            &request.sandbox_id,
            &request.template_fingerprint,
            None,
        )?;
        require_running(&bound)?;
        client.guest_list_page(&bound, request)
    }

    fn stat_path(&self, request: &StatPathRequest) -> Result<EntryInfo, RuntimeError> {
        let client = self.client.with_guest(&request.guest);
        let bound = client.bind_instance(
            &request.instance_name,
            &request.sandbox_id,
            &request.template_fingerprint,
            None,
        )?;
        require_running(&bound)?;
        client.guest_stat(&bound, &request.path)
    }

    fn mkdir(&self, request: &MkdirRequest) -> crate::EffectOutcome<MkdirResponse> {
        let client = self.client.with_guest(&request.guest);
        pre::phase(
            |before| {
                let bound = pre::binding(
                    &before,
                    &client,
                    &request.instance_name,
                    &request.sandbox_id,
                    &request.template_fingerprint,
                )?;
                pre::running(&before, &client, &bound)?;

                before.issue(|| client.guest_mkdir(&bound, &request.path))
            },
            Ok,
        )
    }

    fn remove_path(&self, request: &RemovePathRequest) -> crate::EffectOutcome<RemovePathResponse> {
        let client = self.client.with_guest(&request.guest);
        pre::phase(
            |before| {
                let bound = pre::binding(
                    &before,
                    &client,
                    &request.instance_name,
                    &request.sandbox_id,
                    &request.template_fingerprint,
                )?;
                pre::running(&before, &client, &bound)?;

                before.issue(|| client.guest_remove(&bound, &request.path, request.recursive))
            },
            Ok,
        )
    }

    fn move_path(&self, request: &MovePathRequest) -> crate::EffectOutcome<EntryInfo> {
        let client = self.client.with_guest(&request.guest);
        pre::phase(
            |before| {
                let bound = pre::binding(
                    &before,
                    &client,
                    &request.instance_name,
                    &request.sandbox_id,
                    &request.template_fingerprint,
                )?;
                pre::running(&before, &client, &bound)?;

                before.issue(|| client.guest_move(&bound, &request.from, &request.to))
            },
            Ok,
        )
    }

    fn cancel_operation(&self, operation_id: &str) -> crate::EffectOutcome<()> {
        self.exec_supervisor().cancel(operation_id)
    }

    fn list_processes(
        &self,
        request: &ListProcessesRequest,
    ) -> Result<ListProcessesResponse, RuntimeError> {
        // Supervisor's in-memory map only; no guest exec and no Incus query.
        Ok(self.supervisor.list_processes(&request.instance_name))
    }

    fn signal_process(
        &self,
        request: &SignalProcessRequest,
    ) -> crate::EffectOutcome<crate::SignalOutcome> {
        let client = self.client.with_guest(&request.guest);
        pre::phase(
            |before| {
                let bound = pre::binding(
                    &before,
                    &client,
                    &request.instance_name,
                    &request.sandbox_id,
                    &request.template_fingerprint,
                )?;
                pre::running(&before, &client, &bound)?;

                before.issue(|| {
                    self.supervisor.with_client(client.clone()).signal(
                        &bound,
                        request.pid,
                        request.signal,
                        request.target.as_ref(),
                    )
                })
            },
            Ok,
        )
    }

    fn write_stdin(&self, request: &WriteStdinRequest) -> crate::EffectOutcome<()> {
        self.supervisor.write_stdin(request)
    }

    /// Only sound proofs. A managed instance Incus reports stopped
    /// or absent runs no guest process. On a running one, a receipt that
    /// journaled its start uid runs the root retire helper
    /// (`command_scope.rs`): its scope gone (no unscoped launch this boot),
    /// empty or killed with no populated guest-uid cgroup root proves the
    /// attempt gone; a running scope is `Running`; `unscoped` and `legacy`
    /// fall back to today's reboot arm, compared with the helper's root-read
    /// boot; every other verdict is final unproven. A receipt without a
    /// journaled uid keeps today's arm only: the guest booted again since
    /// the birth (a different boot id). The helper's only effect is a due
    /// command's `cgroup.kill`; nothing is ever signalled by pid.
    fn qemu_identity(&self, sandbox_id: &str) -> Option<crate::QemuIdentity> {
        self.client
            .qemu_identity(&crate::default_incus_instance_name(sandbox_id))
    }

    fn retire_command_group(
        &self,
        request: &crate::RetireCommandRequest,
    ) -> Result<crate::RetireObservation, RuntimeError> {
        // Every unproven and gone answer carries a constant verdict label
        // for the daemon's retirement log (never guest output).
        let unproven = |verdict: &'static str| {
            RuntimeError::new(
                SandboxErrorCode::UnknownOutcome,
                "command disappearance unproven",
            )
            .with_diagnostic(verdict)
        };
        let gone = |verdict: &'static str| {
            Ok(crate::RetireObservation::Gone(
                crate::CommandGroupGone::proven_by(&request.birth, verdict),
            ))
        };
        crate::validate_managed_instance_name(&request.instance_name)?;
        if request.instance_name != crate::default_incus_instance_name(&request.sandbox_id) {
            return Err(unproven("foreign_instance"));
        }
        // Every host read below shares one preflight budget (never the 120 s
        // client default). A read the budget cuts short is an error, never a
        // `SandboxNotFound`/stopped answer, so it can only end unproven; the
        // QEMU identity read degrades to `None`, which proves nothing.
        let deadline = std::time::Instant::now() + super::command_scope::RETIRE_PREFLIGHT_BUDGET;
        let within = |client: &IncusClient| {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return Err(unproven("preflight_timeout"));
            }
            Ok(client.bounded(left))
        };
        if !within(&self.client)?.instance_may_be_running(&request.instance_name)? {
            return gone("vm_stopped");
        }
        let client = self.client.with_guest(&request.guest);
        let bound = within(&client)?.bind_instance(
            &request.instance_name,
            &request.sandbox_id,
            &request.template_fingerprint,
            None,
        )?;
        if !within(&client)?.query_instance(&bound)?.is_running() {
            return Err(unproven("vm_not_running"));
        }
        // R11: a different QEMU process than the one the start journaled is
        // host evidence for every sandbox (the guest's memory is gone). The
        // converse does not hold: Incus may reset a guest inside the same
        // QEMU process, so an unchanged identity proves nothing.
        // Both QEMU-identity reads share the absolute deadline (each one is
        // bounded by what is left, recomputed before it runs).
        if let Some(started) = request.qemu
            && within(&client)?
                .qemu_identity_by(&request.instance_name, deadline)
                .is_some_and(|now| now != started)
        {
            return gone("qemu_restarted");
        }
        if request.host_proof_only {
            // I7: guest root can forge every guest-side proof (scope
            // verdicts, the boot id). A due kill still runs once per
            // admission for its effect; its verdict is ignored. Then park.
            if request.mode.kills()
                && let Some(uid) = request.uid
                && let Ok(client) = within(&client)
            {
                let _ = client.run_retire_helper(&bound, request, uid);
            }
            return Ok(crate::RetireObservation::Parked);
        }
        // The exec's own binding refresh and admission share the remaining
        // preflight budget; the helper's wait keeps its own fixed deadline.
        let client = within(&client)?;
        let boot = if let Some(uid) = request.uid {
            use super::command_scope::RetireVerdict as V;
            let record = client
                .run_retire_helper(&bound, request, uid)
                .map_err(|error| error.with_diagnostic("helper_unavailable"))?;
            match record.verdict {
                V::Absent => return gone("absent"),
                V::Empty => return gone("empty"),
                V::Killed => return gone("killed"),
                V::Populated => return Ok(crate::RetireObservation::Running { not_due: None }),
                V::NotDue(ms) => {
                    return Ok(crate::RetireObservation::Running {
                        not_due: Some(std::time::Duration::from_millis(ms)),
                    });
                }
                // A launch in this boot ran outside its scope, or the guest
                // has no cgroup2: only today's reboot arm, one exec total.
                V::Unscoped | V::Legacy => record.boot_id,
                V::Unsupported => return Err(unproven("unsupported")),
                V::UidPopulated => return Err(unproven("uid_populated")),
                V::Timeout => return Err(unproven("timeout")),
            }
        } else {
            let nonce = super::client::random_nonce()?;
            let out = client
                .exec_argv_effect_bounded(
                    &bound,
                    &[
                        "/bin/sh".to_string(),
                        "-c".to_string(),
                        GUEST_BOOT_ID_SCRIPT.to_string(),
                        "wssp-boot".to_string(),
                        nonce.clone(),
                    ],
                    std::time::Duration::from_secs(10),
                )
                .map_err(crate::EffectError::into_error)?;
            (out.exit_code == 0)
                .then(|| super::frames::parse_boot_record(&nonce, &out.stdout, &out.stderr))
                .flatten()
                .ok_or_else(|| unproven("boot_unreadable"))?
        };
        if boot != request.birth.boot_id {
            return gone("rebooted");
        }
        Err(unproven("same_boot"))
    }

    fn create_snapshot(
        &self,
        _request: &SnapshotRequest,
    ) -> crate::EffectOutcome<SnapshotResponse> {
        Err(crate::before_issue::unsupported_capability("snapshot"))
    }

    fn restore_snapshot(
        &self,
        _request: &SnapshotRequest,
    ) -> crate::EffectOutcome<SnapshotResponse> {
        Err(crate::before_issue::unsupported_capability("restore"))
    }

    fn fork_sandbox(
        &self,
        _request: &ForkSandboxRequest,
    ) -> crate::EffectOutcome<ForkSandboxResponse> {
        Err(crate::before_issue::unsupported_capability("fork"))
    }

    fn probe_sandbox(
        &self,
        request: &ProbeSandboxRequest,
    ) -> Result<ProbeSandboxResponse, RuntimeError> {
        // Serialize a live probe's complete observe/Prepare/fresh-retry
        // boundary with periodic inspection and managed lifecycle changes.
        // The poller skips this lock; it must not start a second observation
        // half-way through the probe's stale-authority recovery.
        let probe_lock = self.client.sandbox_lock(&request.sandbox_id);
        let _probe_guard = probe_lock.lock().unwrap_or_else(|e| e.into_inner());
        let observed = self.client.bind_instance(
            &request.instance_name,
            &request.sandbox_id,
            &request.template_fingerprint,
            None,
        );
        if let Err(error) = &observed
            && error.code == SandboxErrorCode::IdempotencyConflict
        {
            return Err(error.clone());
        }
        let state = match observed {
            Err(error) if error.code == SandboxErrorCode::SandboxNotFound => {
                SandboxLiveProbeState::ConfirmedAbsent
            }
            Ok(instance) if instance.is_stopped() => SandboxLiveProbeState::Stopped,
            Ok(instance) if instance.is_running() => {
                // C37 R2: a probe certifies GuestReady only through THE
                // bound-enforcement boundary — a bound, RUNNING VM whose
                // enforcement is lost or tampered is never reported ready.
                // The boundary's GuestUnavailable propagates (the live-probe
                // caller maps it to "unreachable"), and a dispatched probe
                // op carries the failure as its result.
                self.client
                    .verify_bound_enforcement_locked(&request.sandbox_id, true)?;
                // I11: a bootstrap build VM is probed with its persisted
                // bootstrap readiness; anything else (or no readable spec)
                // gets the standard identity check.
                let mode = self
                    .client
                    .persisted_readiness(&instance)
                    .map(|spec| spec.mode)
                    .unwrap_or_default();
                match self.client.with_guest(&request.guest).verify_guest_mode(
                    &instance,
                    request.architecture.as_deref(),
                    mode,
                ) {
                    Ok(()) => SandboxLiveProbeState::GuestReady,
                    Err(error) if error.code == SandboxErrorCode::IdempotencyConflict => {
                        return Err(error);
                    }
                    Err(_) => SandboxLiveProbeState::Unreachable,
                }
            }
            _ => SandboxLiveProbeState::Unreachable,
        };
        Ok(ProbeSandboxResponse { state })
    }
}

fn finish_create(
    runtime: &IncusKvmRuntime,
    request: &CreateSandboxRequest,
    completion: crate::Completed<()>,
) -> PostIssueOutcome<CreateSandboxResponse> {
    let name = &request.instance_name;
    let bound = runtime.client.bind_instance(
        name,
        &request.sandbox_id,
        &request.template_digest,
        Some(&request.idempotency_key),
    )?;
    // Failure stays UNKNOWN after launch. Server finalization commits generation-
    // fenced cleanup before dispatching deletion; never discard that durable owner.
    let client = runtime.client.with_guest(&request.guest);
    let readiness_restarts = check_readiness(
        &client,
        &bound,
        request.architecture.as_deref(),
        GuestSudoStep::for_create(request.guest_privilege),
        request.readiness,
        RootGrowth::for_create(runtime, request),
    )?;

    let egress_denied_grants = recorded_denied_grants(runtime, &request.sandbox_id);
    let guest_group_signals = super::exec::probe_group_signals(&client, &bound);
    let guest_linger = client.probe_guest_linger(&bound);
    Ok(completion.map(|()| CreateSandboxResponse {
        sandbox: SandboxRecord {
            sandbox_id: request.sandbox_id.clone(),
            generation: 1,
            state: SandboxLifecycleState::Ready,
            idempotency_key: request.idempotency_key.clone(),
        },
        egress_denied_grants,
        guest_group_signals,
        guest_linger,
        readiness_restarts,
    }))
}

/// The grants the domain blocklist denied, from the plan persisted at
/// materialization (§2.6). Display data: an unreadable record reports none.
fn recorded_denied_grants(runtime: &IncusKvmRuntime, sandbox_id: &str) -> Vec<String> {
    match runtime
        .client
        .persisted_enforcement_plan_checked(sandbox_id)
    {
        Ok(Some(plan)) => crate::bounded_denied_grants(plan.denied_grants),
        _ => Vec::new(),
    }
}
/// Create-path issued outcome: a fresh VM completion, or an existing VM
/// whose binding was proven BEFORE its NIC was verified/reconfigured.
enum CreateIssued {
    Created(crate::Completed<()>),
    Existing(BoundInstance),
}

fn reconcile_existing_create(
    runtime: &IncusKvmRuntime,
    request: &CreateSandboxRequest,
    bound: &BoundInstance,
) -> PostIssueOutcome<CreateSandboxResponse> {
    #[cfg(test)]
    runtime
        .client
        .pause_create_for_test("before_existing_start");
    // No name-only adoption: the binding was already proven before any NIC
    // mutation. Never relabel an existing VM.
    let client = runtime.client.with_guest(&request.guest);
    let proof = start_if_stopped(
        &client,
        bound,
        request.architecture.as_deref(),
        request.vm_size,
        GuestSudoStep::for_create(request.guest_privilege),
        request.readiness,
        RootGrowth::for_create(runtime, request),
    )
    .map_err(crate::effect::PostIssueError::from_final_start)?;
    let egress_denied_grants = recorded_denied_grants(runtime, &request.sandbox_id);
    let guest_group_signals = super::exec::probe_group_signals(&client, bound);
    let guest_linger = client.probe_guest_linger(bound);
    Ok(proof.map(|readiness_restarts| CreateSandboxResponse {
        sandbox: SandboxRecord {
            sandbox_id: request.sandbox_id.clone(),
            generation: 1,
            state: SandboxLifecycleState::Ready,
            idempotency_key: request.idempotency_key.clone(),
        },
        egress_denied_grants,
        guest_group_signals,
        guest_linger,
        readiness_restarts,
    }))
}

/// Ok carries how many guest restarts readiness tolerated (for the daemon log).
///
/// `mode` is the create's gate-proven readiness (I11). `BuildBootstrap`
/// keeps every rule of the pass below (agent wait, restart re-pass, retry
/// bounds, binding refresh, architecture compare, fences, guest sudo,
/// network) and replaces only the identity script and the repo ensure with
/// the boot settle, run as the declared uid.
fn check_readiness(
    client: &IncusClient,
    name: &BoundInstance,
    architecture: Option<&str>,
    sudo: GuestSudoStep,
    mode: crate::ReadinessMode,
    root: RootGrowth,
) -> Result<u32, RuntimeError> {
    // C37: readiness includes the network/DNS policy fence — revocation
    // markers must have committed and the live bridge/ACL must read back
    // equal to the persisted recorded policy. A guest that answers while
    // its egress enforcement is unverifiable is never Ready.
    // C37 R1/R2: this instance is POSITIVELY BOUND (the caller bound it
    // pre-issue) and the readiness context is post-start (this op launched
    // or resumed the VM), so the shared boundary's verdict is authoritative
    // here. C37 R4: it propagates UNWRAPPED — the boundary emits
    // GuestUnavailable ONLY for confirmed drift, and an inconclusive
    // observation (timeout, cancellation, transport/daemon error, coherence
    // budget) must keep its own retryable code instead of being converted
    // to the cleanup-triggering one. A FOREIGN-instance binding conflict
    // never reaches this point (bind_instance raises it pre-issue) and must
    // never trigger that cleanup.
    let sandbox_id = crate::sandbox_id_from_instance_name(name.name())?;
    client.verify_bound_enforcement(sandbox_id, true)?;
    #[cfg(test)]
    if let Some(barrier) = &client.readiness_barrier {
        barrier.wait();
        barrier.wait();
    }
    // One agent budget for every pass (an Ubuntu 26.04 first boot reboots
    // once, about a second after its agent starts). Each guest check is
    // clamped to the remaining budget, and every pass result (pass or fail)
    // is used only after `validate_pass` re-observed the guest: a restart
    // (state left Running, new QEMU pid, or new guest boot id: Incus can
    // reset a guest inside the same QEMU process) runs the pass again under
    // the same deadline, bounded by MAX_GUEST_RESTARTS (then
    // `guest_restarts`). The budget spent before that observation is
    // `agent_timeout`, never READY.
    let mut wait = client.readiness_wait(mode);
    // Bootstrap: the last pass's boot settle saw no settled system.
    let mut unsettled = false;
    let guest = loop {
        // A clone of the client whose host and guest calls end with the budget.
        let clamped = |wait: &AgentWait| {
            let remaining = wait.remaining();
            if remaining.is_zero() {
                return Err(wait.deadline_error(name.name()));
            }
            let mut step = client.clone();
            step.agent_timeout = remaining;
            Ok(step)
        };
        let pass = (|| {
            client.wait_for_agent_fenced(name, &mut wait)?;
            #[cfg(test)]
            if let Some(barrier) = &client.readiness_after_agent_barrier {
                barrier.wait();
                barrier.wait();
            }
            client.record_pass_boot(name, &mut wait)?;
            // Re-observe after waiting: a periodic pass may have refused dispatch
            // or discovered real drift while no lifecycle gate was held.
            let step = clamped(&wait)?;
            match mode {
                crate::ReadinessMode::Standard => {
                    step.with_verified_enforcement(sandbox_id, true, || {
                        clamped(&wait)?.verify_guest_identity(name, architecture, false)?;
                        // B2-K-3: template layout keeps `mkdir -p` follow semantics.
                        let dir = clamped(&wait)?;
                        dir.guest_ensure_directory(name, &format!("{}/repo", dir.guest.guest_home))
                            .map_err(|err| {
                                let err = err.into_error();
                                let readiness = err.readiness_reason();
                                err.with_readiness_reason(
                                    readiness.unwrap_or(ReadinessFailureReason::GuestRepo),
                                )
                            })?;
                        clamped(&wait)?.verify_guest(name, architecture)
                    })?;
                }
                // D-C: the raw upstream image does not carry the declared
                // identity yet, so nothing here depends on it (no script,
                // no repo, cwd `/`).
                crate::ReadinessMode::BuildBootstrap => {
                    step.with_verified_enforcement(sandbox_id, true, || {
                        clamped(&wait)?
                            .verify_guest_architecture(name, architecture)
                            .map(|_| ())
                    })?;
                    let remaining = wait.remaining();
                    if remaining.is_zero() {
                        return Err(wait.deadline_error(name.name()));
                    }
                    if clamped(&wait)?.guest_boot_settle(name, remaining)?
                        == super::client::BootSettle::Unsettled
                    {
                        unsettled = true;
                        return Err(super::client::boot_unsettled());
                    }
                }
            }
            // Root growth (create only): its own fenced section once the guest
            // is known ready, before guest sudo. Idempotent, so a restart's
            // re-pass grows and measures again.
            if let RootGrowth::Create { disk_bytes } = root {
                let step = clamped(&wait)?;
                step.with_verified_enforcement(sandbox_id, true, || {
                    clamped(&wait)?.guest_root_grow_step(name, disk_bytes)
                })?;
            }
            // Guest sudo (plan step 11, M2): its own short fenced section once
            // the guest is known ready, never inside the identity closure. The
            // pass is used only after `validate_pass` saw no restart after it
            // (VM state, QEMU pid, guest boot id), and a restart reruns the
            // whole pass: the grant or removal lies in the final validated
            // pass, after the last guest restart.
            // Clamped to the remaining budget like every guest check.
            let step = clamped(&wait)?;
            step.with_verified_enforcement(sandbox_id, true, || {
                guest_sudo_spec_check(&step, name, sudo)?;
                clamped(&wait)?.guest_sudo_step(name, sudo)
            })?;
            // E1-A-01: a guest without a DHCP lease is never Ready. Waited for
            // after the fenced verification (it can take seconds, and the fence
            // must observe first), outside it.
            let remaining = wait.remaining();
            if remaining.is_zero() {
                return Err(wait.deadline_error(name.name()));
            }
            client.verify_guest_network(name, remaining)
        })();
        // Bootstrap: an unsettled boot re-passes, counted like a restart
        // (once: a restart the validation sees is that count).
        if std::mem::take(&mut unsettled) {
            match client.validate_pass(name, &mut wait) {
                Ok(PassValidation::Restarted) => continue,
                Ok(PassValidation::Stable | PassValidation::Unobserved) => {
                    match wait.unobserved_pass(name.name()) {
                        Ok(()) => continue,
                        Err(restarts) => break Err(restarts),
                    }
                }
                Err(observed) => break Err(observed),
            }
        }
        // A fence or cancellation refusal is final; so is a pass whose agent
        // wait itself failed (it already tolerates restarts and owns the
        // budget). Every other result is validated first.
        if let Err(err) = &pass
            && (matches!(
                err.code,
                SandboxErrorCode::IdempotencyConflict | SandboxErrorCode::Cancelled
            ) || err.is_enforcement_inconclusive()
                || matches!(
                    err.readiness_reason(),
                    Some(
                        ReadinessFailureReason::AgentTimeout
                            | ReadinessFailureReason::VmNotRunning
                            | ReadinessFailureReason::GuestRestarts
                    )
                ))
        {
            break pass;
        }
        match (client.validate_pass(name, &mut wait), pass) {
            (Ok(PassValidation::Restarted), _) => continue,
            (Ok(PassValidation::Stable), pass) => break pass,
            // Never READY without the observation: rerun under the restart
            // bound. A failed pass keeps its own error (a fence refusal or
            // cancellation must stay retryable, never become a restart).
            (Ok(PassValidation::Unobserved), Ok(())) => match wait.unobserved_pass(name.name()) {
                Ok(()) => continue,
                Err(restarts) => break Err(restarts),
            },
            (Ok(PassValidation::Unobserved), Err(failed)) => break Err(failed),
            // The budget ran out before the observation: a passed (or timed
            // out) pass is `agent_timeout`; a concrete failure keeps its own.
            (Err(observed), Err(failed))
                if observed.readiness_reason() == Some(ReadinessFailureReason::AgentTimeout)
                    && failed.code != SandboxErrorCode::Timeout =>
            {
                break Err(failed);
            }
            (Err(observed), _) => break Err(observed),
        }
    };
    // B2-C-1: a fence or cancellation refusal (runtime work preempted, or a
    // confirmed `cancelled`) keeps its own retryable code. Only an ordinary
    // guest failure is the cleanup-triggering GuestUnavailable, and it keeps
    // the failed check's constant reason (never guest text).
    let restarts = wait.restarts();
    guest.map(|()| restarts).map_err(|err: RuntimeError| {
        if matches!(
            err.code,
            SandboxErrorCode::IdempotencyConflict
                | SandboxErrorCode::UnknownOutcome
                | SandboxErrorCode::Cancelled
                | SandboxErrorCode::GuestNetworkUnavailable
        ) || err.is_enforcement_inconclusive()
        {
            err
        } else {
            let reason = err
                .readiness_reason()
                .unwrap_or(ReadinessFailureReason::GuestCheck);
            RuntimeError::new(
                SandboxErrorCode::GuestUnavailable,
                format!("readiness failed ({}): {}", reason.as_str(), err.message),
            )
            .with_readiness_reason(reason)
            .with_not_running_detail(err.not_running_detail().cloned())
        }
    })
}

/// The persisted readiness spec's `privilege.sudo` must equal the lease's
/// (I3, step 10): a mismatch is refused as `guest_check`. A pre-feature spec
/// reads false, as does a pre-feature lease.
/// Whether readiness grows and checks the guest root (create only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootGrowth {
    /// A fresh create: grow the root to the configured disk and verify it.
    Create { disk_bytes: u64 },
    /// Start, reconnect, a restore of a stored disk, or no known root disk.
    Skip,
}

impl RootGrowth {
    /// A create grows to its bound root disk. A restore launches the
    /// sandbox's own stored disk (same size, already grown): nothing to do.
    fn for_create(runtime: &IncusKvmRuntime, request: &crate::CreateSandboxRequest) -> Self {
        match (&request.restore, &runtime.client.expected_root) {
            (None, Some(root)) => Self::Create {
                disk_bytes: root.size_bytes(),
            },
            _ => Self::Skip,
        }
    }
}

fn guest_sudo_spec_check(
    client: &IncusClient,
    name: &BoundInstance,
    step: GuestSudoStep,
) -> Result<(), RuntimeError> {
    // Without readable metadata only a grant is refused: a removal is the
    // fail-closed direction and never needs the spec.
    let spec_sudo = match client.persisted_readiness(name) {
        Ok(spec) => spec.privilege.sudo,
        Err(error) if step.sudo() => return Err(error),
        Err(_) => false,
    };
    if spec_sudo != step.sudo() {
        return Err(RuntimeError::new(
            SandboxErrorCode::GuestUnavailable,
            "guest sudo binding differs from the instance's readiness spec",
        )
        .with_readiness_reason(ReadinessFailureReason::GuestCheck));
    }
    Ok(())
}

fn require_running(name: &BoundInstance) -> Result<(), RuntimeError> {
    if !name.is_running() {
        return Err(sandbox_not_running(name.name()));
    }
    Ok(())
}

fn start_if_stopped(
    client: &IncusClient,
    name: &BoundInstance,
    architecture: Option<&str>,
    vm_size: sandbox_protocol::VmSize,
    sudo: GuestSudoStep,
    mode: crate::ReadinessMode,
    root: RootGrowth,
) -> EffectOutcome<u32> {
    let restarts = std::cell::Cell::new(0);
    pre::phase(
        |before| {
            let lock = client.sandbox_lock(
                crate::sandbox_id_from_instance_name(name.name()).map_err(not_issued)?,
            );
            let _guard = lock.lock().unwrap_or_else(|e| e.into_inner());
            pre::bound(&before, client, name)?;
            let instance = client.query_instance(name)?;
            // Running retries must pass the same allocation/config fence.
            pre::launch_config(&before, client, name.name(), vm_size)?;

            before.issue(|| {
                let proof = if instance.is_stopped() {
                    client.start_bound(name, vm_size)?
                } else {
                    evidence::running(client, name, None)?
                };
                Ok(proof)
            })
        },
        |issued| {
            issued
                .observe(|| {
                    check_readiness(client, name, architecture, sudo, mode, root)
                        .map(|n| restarts.set(n))
                })
                .map_err(Into::into)
        },
    )
    .map(|proof| proof.map(|()| restarts.get()))
}

impl IncusKvmRuntime {
    pub(super) fn create_bound(
        &self,
        request: &CreateSandboxRequest,
    ) -> crate::EffectOutcome<CreateSandboxResponse> {
        let name = &request.instance_name;
        let mut existence = None;
        let outcome = pre::phase(
            |before| {
                // Validate before provisioning IO. A refusal still requires a
                // read-only existence observation before it can release a slot.
                pre::recorded_policy(
                    &before,
                    request.egress_policy.as_ref(),
                    request.egress_policy_hash.as_deref(),
                )?;
                // §1.5 create check, before any host IO: the guard (both
                // modes) and, for open mode, the node owner's consent.
                request
                    .egress_admission
                    .check(
                        request
                            .egress_policy
                            .as_ref()
                            .map(|policy| policy.mode)
                            .unwrap_or_default(),
                    )
                    .map_err(not_issued)?;
                crate::resources::validate_vm_size(request.vm_size).map_err(not_issued)?;
                request.lease.validate_now().map_err(|message| {
                    not_issued(RuntimeError::new(SandboxErrorCode::StateConflict, message))
                })?;
                pre::guest(&before, &request.guest)?;
                // A restore launches the stored disk image;
                // the template tag stays the template digest.
                let fingerprint = pre::launch_image(&before, request)?;
                let identity = crate::incus::BindingIdentity {
                    template_fingerprint: request.template_digest.clone(),
                    restore_base: request.restore.as_ref().map(|_| fingerprint.clone()),
                };
                if let Some(base) = &identity.restore_base {
                    // Every later bind of this sandbox (readiness, finish,
                    // recovery) binds the restored lineage.
                    self.client
                        .set_restore_base(&request.sandbox_id, Some(base));
                }
                pre::name_belongs_to_sandbox(&before, &request.sandbox_id, name)?;
                // Once a VM is observed, this may be a retry of an effective
                // create whose result was lost. No later refusal proves 0→1
                // was unissued, even when this attempt has not mutated it.
                let observed = self.client.instance_exists(name);
                existence = Some(observed.clone());
                let exists = observed.map_err(not_issued)?;
                pre::profile_safety(&before, &self.client, request.vm_size)?;
                if let Some(root) = &self.client.expected_root {
                    self.client
                        .observe_storage_pool(&root.pool)
                        .map_err(not_issued)?;
                }
                // C37-R8-2: audit the template BEFORE network apply or VM
                // init. The start boundary still audits effective config.
                self.client
                    .verify_template_launch_config(&fingerprint, request.vm_size)
                    .map_err(not_issued)?;
                // Compile DNS before any allocation. The gateway chosen here
                // is tentative; apply rechecks it under the daemon lock and
                // releases that lock as soon as the bridge exists.
                if exists {
                    // Refuse a changed-size retry before network adoption or
                    // its durable provisioning intent. Identity still wins.
                    self.client
                        .bind_instance_as(
                            name,
                            &request.sandbox_id,
                            &identity,
                            Some(&request.idempotency_key),
                        )
                        .map_err(not_issued)?;
                    pre::launch_config(&before, &self.client, name, request.vm_size)?;
                }
                let mut plan = pre::network_plan(&before, &self.client, request)?;
                #[cfg(test)]
                self.client
                    .pause_create_for_test("before_existing_adoption");
                before.issue(move || {
                    // Apply-to-adoption is one serialized section per sandbox:
                    // a restart drain can never delete between its fence read
                    // and this attempt's restamp.
                    let sandbox_lock = self.client.sandbox_lock(&request.sandbox_id);
                    let _guard = sandbox_lock.lock().unwrap_or_else(|err| err.into_inner());
                    let mut client = self.client.clone();
                    client.settle_create = true;
                    // C58 NEW-1 (create reader): a create retry over an
                    // EXISTING VM whose DNS refresh is owed would fail the
                    // apply's strict idempotency readback and roll back the
                    // live VM's bridge and ACL. The owed refresh is our own
                    // uncommitted work, not drift: refuse inconclusively,
                    // before any mutation, and let the retry land after the
                    // refresh commits.
                    if exists && client.dns_commit_owed(&request.sandbox_id) {
                        return Err(RuntimeError::new(
                            SandboxErrorCode::Internal,
                            "a DNS refresh is owed for this sandbox; retry the create after it commits",
                        )
                        .enforcement_inconclusive()
                        .into());
                    }
                    // Recheck under the sandbox lock before any adoption:
                    // the preflight observation can have changed meanwhile.
                    let existing = if exists {
                        let bound = client.bind_instance_as(
                            name,
                            &request.sandbox_id,
                            &identity,
                            Some(&request.idempotency_key),
                        )?;
                        client.verify_launch_config(bound.name(), request.vm_size)?;
                        Some(bound)
                    } else {
                        None
                    };
                    // C58 G1F-1: a retry over an EXISTING VM adopts its
                    // network — never rolled back on failure.
                    client.apply_allocated_sandbox_network(&mut plan, exists)?;
                    if let Some(bound) = existing {
                        // Bind before mutation: the existing VM must provably
                        // carry this sandbox's immutable metadata (sandbox id,
                        // template, base image, create key) before its NIC is
                        // touched. A pre-C35 VM on an unrestricted bridge must
                        // never be adopted: verify (or safely reconfigure,
                        // when stopped) the effective NIC before accepting it.
                        client.ensure_instance_egress_device(bound.name(), &plan)?;
                        // Adoption: the VM is the durable proof of
                        // provisioning; the write-ahead intent record is
                        // retired. Bookkeeping failure is safe: the drain
                        // retires the record once it observes the VM.
                        let _ = client.clear_pending_cleanup(&request.sandbox_id);
                        return Ok(CreateIssued::Existing(bound));
                    }
                    #[cfg(test)]
                    client.pause_create_for_test("before_init");
                    let issued = client
                        .create_vm(request, &plan)
                        .map(CreateIssued::Created)?;
                    let _ = client.clear_pending_cleanup(&request.sandbox_id);
                    Ok(issued)
                })
            },
            |completion| match completion {
                CreateIssued::Created(completion) => finish_create(self, request, completion),
                CreateIssued::Existing(bound) => reconcile_existing_create(self, request, &bound),
            },
        );
        if request.first_attempt
            && matches!(&existence, Some(Ok(false)))
            && matches!(
                &outcome,
                Err(crate::EffectError::Completed(
                    crate::effect::CompletionFailure::StartRefused(_)
                ))
            )
        {
            // Only a proven refused FIRST start may clean up. Existing-VM
            // refusals never acquire destruction authority. Release the hold
            // only after observing absence, even if cleanup itself failed.
            let _ = self.cleanup_refused_create(request);
            existence = Some(self.sandbox_exists(&request.sandbox_id));
        }
        outcome.map_err(|error| {
            let state = match existence {
                Some(observed) => {
                    crate::allocation_refusal_state(request.first_attempt, observed.ok())
                }
                None => crate::allocation_refusal_for_runtime(
                    self,
                    crate::AllocationKind::Create,
                    request.first_attempt,
                    &request.sandbox_id,
                ),
            };
            if state == sandbox_protocol::OperationState::Failed {
                error
            } else {
                error.after_issue()
            }
        })
    }
    pub(super) fn kill_bound(
        &self,
        request: &KillSandboxRequest,
    ) -> EffectOutcome<KillSandboxResponse> {
        let _priority = self.client.request_lifecycle_priority(&request.sandbox_id);
        let name = &request.instance_name;
        pre::phase(
            |before| {
                before.issue(|| {
                    // Read the identity AFTER the revoked create releases its
                    // mutation lock. A pre-lock read can observe partial init
                    // metadata or absence while the daemon is still creating.
                    let sandbox_lock = self.client.sandbox_lock(&request.sandbox_id);
                    let _guard = sandbox_lock.lock().unwrap_or_else(|err| err.into_inner());
                    let instance = self.client.bind_instance(
                        name,
                        &request.sandbox_id,
                        &request.template_fingerprint,
                        None,
                    );
                    if let Some(root) = &self.client.expected_root {
                        self.client.observe_storage_pool(&root.pool)?;
                    }
                    // Write-ahead: while any network resource exists, the
                    // teardown obligation is durable BEFORE the VM is touched.
                    // No crash window can then leave an untracked bridge/ACL,
                    // and the obligation binds the resources' current
                    // incarnation so a later retry is never fenced against.
                    self.client.prepare_network_cleanup(&request.sandbox_id)?;
                    let completion = match instance {
                        Err(error) if error.code == SandboxErrorCode::SandboxNotFound => {
                            evidence::absent(&self.client, name)?
                        }
                        Err(error) => return Err(error.into()),
                        Ok(bound) => self.client.delete_force(&bound)?,
                    };
                    // Kill completion evidence includes the sandbox's network
                    // resources: a crash between VM deletion and teardown must
                    // not confirm the kill. The obligation was already
                    // persisted above; it is cleared only after verified
                    // absence.
                    self.client
                        .teardown_sandbox_network(&request.sandbox_id)
                        .and_then(|()| {
                            self.client
                                .verify_sandbox_network_absent(&request.sandbox_id)
                        })?;
                    if let Some(root) = &self.client.expected_root {
                        self.client.prove_root_absent(root, name)?;
                    }
                    self.client.clear_pending_cleanup(&request.sandbox_id)?;
                    // A completed kill fulfills any recorded
                    // enforcement-loss obligation for this sandbox (C37
                    // R3): retire it so the drain never re-acts.
                    self.client.clear_enforcement_loss(&request.sandbox_id)?;
                    Ok(completion)
                })
            },
            |completion| {
                Ok(completion.map(|()| KillSandboxResponse {
                    sandbox: SandboxRecord {
                        sandbox_id: request.sandbox_id.clone(),
                        generation: 1,
                        state: SandboxLifecycleState::Deleted,
                        idempotency_key: request.idempotency_key.clone(),
                    },
                }))
            },
        )
    }
    pub(super) fn reconnect_bound(
        &self,
        request: &ReconnectSandboxRequest,
    ) -> EffectOutcome<ReconnectSandboxResponse> {
        crate::resources::validate_vm_size(request.vm_size)?;
        request
            .lease
            .validate_now()
            .map_err(|message| RuntimeError::new(SandboxErrorCode::StateConflict, message))?;
        let client = self.client.with_guest(&request.guest);
        pre::phase(
            |before| {
                // Recorded-policy validation is pure and runs first: an
                // out-of-bounds policy must not even bind the VM.
                pre::recorded_policy(
                    &before,
                    request.egress_policy.as_ref(),
                    request.egress_policy_hash.as_deref(),
                )?;
                pre::binding(
                    &before,
                    &client,
                    &request.instance_name,
                    &request.sandbox_id,
                    &request.template_fingerprint,
                )?;
                pre::launch_config(&before, &client, &request.instance_name, request.vm_size)?;
                // Reconnect allocates nothing: the recorded network must
                // verify as-is (C37 R1 refusal semantics), so no subnet
                // allocation lock is taken here.
                let mut plan = pre::network_plan_for(
                    &before,
                    &client,
                    &request.sandbox_id,
                    request.egress_policy.as_ref(),
                    request.egress_policy_hash.as_deref(),
                )?;
                // Persist the VM's ORIGINAL create binding, never this
                // reconnect operation's key: the VM retains its creation
                // metadata, and the drain's bind check must match IT.
                let original_create_key = client
                    .instance_create_key(&request.instance_name)
                    .map_err(not_issued)?;
                plan.binding = Some(crate::incus::network::PlanBinding {
                    template_fingerprint: request.template_fingerprint.clone(),
                    create_key: original_create_key,
                });
                before.issue(move || {
                    let sandbox_lock = client.sandbox_lock(&request.sandbox_id);
                    let _guard = sandbox_lock.lock().unwrap_or_else(|err| err.into_inner());
                    // The binding is proven FIRST: the verification's failure
                    // semantics are the BOUND VM's power state, and a foreign
                    // instance conflicts here — never reaching the boundary,
                    // never triggering cleanup.
                    let bound = client.bind_instance(
                        &request.instance_name,
                        &request.sandbox_id,
                        &request.template_fingerprint,
                        None,
                    )?;
                    client.verify_launch_config(bound.name(), request.vm_size)?;
                    // C37 R2 (one bound-enforcement boundary): reconnect
                    // verifies through the shared boundary, so the failure
                    // code is the bound VM's power state:
                    // - WARM reconnect (the VM is RUNNING): a lost or
                    //   tampered ACL surfaces as GuestUnavailable — the op
                    //   result feeds the relay's generation-fenced cleanup.
                    //   No journal is taken: the drain only repairs devices
                    //   and retries verification; it cannot fence a RUNNING
                    //   VM's traffic, so a journaled refusal would leave the
                    //   unenforced guest up until lease expiry.
                    // - COLD reconnect (the VM is STOPPED): the R1 refusal
                    //   stands — IdempotencyConflict, journaled with the VM's
                    //   ORIGINAL binding so the restart drain keeps the
                    //   sandbox deliberately fenced. Nothing is rebuilt
                    //   around the VM.
                    if let Err(err) = client
                        .verify_bound_enforcement_locked(&request.sandbox_id, bound.is_running())
                    {
                        if err.code == SandboxErrorCode::GuestUnavailable {
                            return Err(err.into());
                        }
                        // C37 R4: an INCONCLUSIVE observation (timeout,
                        // cancellation, transport/daemon error, coherence
                        // budget) is retryable WITHOUT a refusal fence —
                        // nothing has been shown to be wrong, and a
                        // journaled intent would make the restart drain
                        // repair a healthy sandbox. Only the stopped-VM
                        // confirmed-drift refusal journals.
                        if err.code != SandboxErrorCode::IdempotencyConflict {
                            return Err(err.into());
                        }
                        if let Ok(attempt) = IncusClient::new_attempt_token() {
                            let _ = client.persist_provisioning_intent(
                                &request.sandbox_id,
                                &attempt,
                                plan.binding.as_ref(),
                            );
                        }
                        return Err(err.into());
                    }
                    // Recorded-policy immutability, explicit now that
                    // reconnect no longer re-applies: the request's recorded
                    // policy identity must equal the persisted one.
                    client.verify_recorded_policy_identity(
                        &request.sandbox_id,
                        request.egress_policy_hash.as_deref(),
                    )?;
                    // §1.5 COLD reconnect check (the bound VM is stopped):
                    // the guard (both modes) and, for a RECORDED open-mode
                    // sandbox, the node owner's live consent. After the
                    // read-only verification, BEFORE the provisioning intent
                    // and any NIC repair or start: nothing is journaled or
                    // fenced (enforcement itself is fine), the VM stays
                    // stopped and its network objects stay intact. A warm
                    // reconnect (VM running) is never refused.
                    if !bound.is_running() {
                        let mode = client.recorded_egress_mode(&request.sandbox_id)?;
                        request.egress_admission.check(mode)?;
                    }
                    // Write-ahead BEFORE the only remaining mutation (a
                    // stopped VM's NIC repair): a crash or failure between
                    // the verification and the adoption bookkeeping below
                    // keeps the obligation, exactly as the apply's journal
                    // did.
                    let attempt = IncusClient::new_attempt_token()?;
                    client.persist_provisioning_intent(
                        &request.sandbox_id,
                        &attempt,
                        plan.binding.as_ref(),
                    )?;
                    // The existing VM's NIC must provably sit on the sandbox
                    // bridge before it is started again. The binding is
                    // refreshed immediately before any NIC mutation.
                    let bound = client.refresh_binding(&bound)?;
                    client.ensure_instance_egress_device(bound.name(), &plan)?;
                    // Adoption retires the provisioning write-ahead record —
                    // only AFTER the NIC is verifiably enforced: a repair or
                    // read-back failure (or a crash) before this point must
                    // keep the obligation for the drain.
                    let _ = client.clear_pending_cleanup(&request.sandbox_id);
                    let lease = serde_json::to_string(&request.lease).map_err(|_| {
                        RuntimeError::new(SandboxErrorCode::ProtocolError, "invalid lease")
                    })?;
                    client.config_set(&bound, "user.flycockpit.lease", &lease)?;
                    request.lease.validate_now().map_err(|message| {
                        RuntimeError::new(SandboxErrorCode::StateConflict, message)
                    })?;
                    // C37 cold-reconnect revalidation: the recorded policy
                    // hash was bound to the plan pre-issue and the live
                    // bridge/ACL/DNS state verified against the persisted
                    // recorded plan above — a lost or modified ACL was
                    // refused (journaled, fenced), never rebuilt. The resume
                    // itself is fenced at the enforced boundary too — the
                    // start's pre-issue launch-config + verified-policy fence
                    // (a cold resume) or the readiness fence (a warm
                    // reconnect) — so no window between this point and Ready
                    // can resume unenforced.
                    // Readiness polls in short verified sections; do not park
                    // urgent expiry/restrictive recovery behind a guest boot.
                    drop(_guard);
                    start_if_stopped(
                        &client,
                        &bound,
                        request.architecture.as_deref(),
                        request.vm_size,
                        GuestSudoStep::for_boot(request.guest_sudo),
                        // Never bootstrap: a reconnect always proves the
                        // declared identity (the daemon refuses bootstrap
                        // and build reconnects, I12).
                        crate::ReadinessMode::Standard,
                        // The disk never changes after create.
                        RootGrowth::Skip,
                    )
                    .map(|proof| {
                        let signals = super::exec::probe_group_signals(&client, &bound);
                        let linger = client.probe_guest_linger(&bound);
                        proof.map(|restarts| (signals, linger, restarts))
                    })
                })
            },
            Ok,
        )
        // Reconnect targets a possibly live VM; a refusal before this
        // attempt's mutations is not evidence that an earlier start failed.
        .map_err(crate::EffectError::after_issue)
        .map(|proof| {
            proof.map(|(guest_group_signals, guest_linger, readiness_restarts)| {
                ReconnectSandboxResponse {
                    sandbox: SandboxRecord {
                        sandbox_id: request.sandbox_id.clone(),
                        generation: 1,
                        state: SandboxLifecycleState::Ready,
                        idempotency_key: request.idempotency_key.clone(),
                    },
                    guest_group_signals,
                    guest_linger,
                    readiness_restarts,
                }
            })
        })
    }
}

impl IncusKvmRuntime {
    pub fn root_disk(&self) -> Option<&crate::RootDisk> {
        self.client.expected_root.as_ref()
    }
}

#[cfg(test)]
mod refused_create_tests {
    use super::*;
    use std::fs;

    #[test]
    fn existing_refused_create_preserves_prior_enforcement_loss_and_resources() {
        for fail_cleanup in [false, true] {
            let (runtime, log) = super::super::shim_tests::runtime_for("c37_start_gated");
            let request = super::super::shim_tests::create_req();
            runtime
                .create_bound(&request)
                .expect("initial create ready");
            let dir = log.parent().unwrap();
            let acl = super::super::network::sandbox_network_names(&request.sandbox_id).1;
            let acl_path = dir.join(format!("acls/{acl}.egress"));
            let original = fs::read_to_string(&acl_path).unwrap();
            fs::write(
                &acl_path,
                format!("{original}action=allow destination=128.66.1.99/32 description=injected\n"),
            )
            .unwrap();
            runtime
                .client()
                .verify_bound_enforcement(&request.sandbox_id, true)
                .expect_err("confirmed drift records enforcement loss");
            let loss = runtime.client().enforcement_loss_dir().join("sbx-1.json");
            assert!(loss.exists(), "real detection persisted the loss");
            fs::write(&acl_path, original).unwrap();
            runtime
                .stop_sandbox(&StopSandboxRequest {
                    template_fingerprint: request.template_digest.clone(),
                    sandbox_id: request.sandbox_id.clone(),
                    instance_name: request.instance_name.clone(),
                    operation_id: "stop-before-retry".into(),
                    idempotency_key: "stop-before-retry".into(),
                })
                .expect("stop the earlier running incarnation");
            assert!(
                loss.exists(),
                "stopping and repairing do not retire the loss"
            );
            fs::write(
                dir.join("start-error"),
                "Error: Failed to start device \"eth0\": br_netfilter kernel module not loaded",
            )
            .unwrap();
            if fail_cleanup {
                fs::write(
                    dir.join(format!(
                        "fail-delete-{}",
                        super::super::network::sandbox_network_names(&request.sandbox_id).0
                    )),
                    "",
                )
                .unwrap();
            }
            let err = runtime
                .create_bound(&request)
                .expect_err("retry start is refused");
            assert_eq!(
                err.state(),
                sandbox_protocol::OperationState::UnknownOutcome,
                "{err:?}"
            );
            assert!(loss.exists(), "a refused retry cannot retire prior loss");
            assert!(
                !super::super::shim_tests::log_invoked(&log, "delete"),
                "an existing VM refusal cannot authorize cleanup"
            );
            assert!(
                runtime
                    .client()
                    .verify_sandbox_network_absent(&request.sandbox_id)
                    .is_err(),
                "the prior network must remain held"
            );
            assert!(
                runtime
                    .client()
                    .bind_owned_instance(&request.instance_name, &request.sandbox_id)
                    .unwrap()
                    .is_stopped(),
                "the original VM must remain present"
            );
        }
    }
}
