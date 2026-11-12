//! Pre-issue proof constructors. No constructor accepts a post-issue observation.
//! Only the scoped preparation callback receives a capability. Consuming it
//! crosses into a separate callback whose error sum cannot contain NotIssued.
#[cfg(target_os = "linux")]
use crate::effect::EffectResult;
use crate::{EffectError, RuntimeError};
use sandbox_protocol::SandboxErrorCode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotIssuedProof {
    error: RuntimeError,
}
impl NotIssuedProof {
    fn failed(error: RuntimeError) -> EffectError {
        EffectError::NotIssued(Self { error })
    }
    pub(crate) fn error(&self) -> &RuntimeError {
        &self.error
    }
    pub(crate) fn into_error(self) -> RuntimeError {
        self.error
    }
}

/// A preparation-phase failure: the effect was never issued.
pub(crate) fn not_issued(error: RuntimeError) -> EffectError {
    NotIssuedProof::failed(error)
}

pub(crate) fn unsupported_runtime() -> EffectError {
    NotIssuedProof::failed(RuntimeError::new(
        SandboxErrorCode::HostRuntimeUnsupported,
        "sandbox host runtime is only available on Linux",
    ))
}
#[cfg(target_os = "linux")]
pub(crate) fn unsupported_capability(capability: &str) -> EffectError {
    NotIssuedProof::failed(RuntimeError::new(
        SandboxErrorCode::UnsupportedCapability,
        format!("Unsupported capability: {capability}"),
    ))
}

/// A non-cloneable, invariant capability tied to a single preparation callback.
/// Neither it nor a reference to it can escape `phase` in its result.
#[cfg(target_os = "linux")]
pub(crate) struct BeforeIssue<'phase> {
    _scope: std::marker::PhantomData<&'phase mut &'phase ()>,
}
#[cfg(target_os = "linux")]
pub(crate) struct Issued<T>(T);
#[cfg(target_os = "linux")]
impl<T> Issued<T> {
    pub(crate) fn map<U>(self, map: impl FnOnce(T) -> U) -> Issued<U> {
        Issued(map(self.0))
    }
}
#[cfg(target_os = "linux")]
impl BeforeIssue<'_> {
    /// Consume the capability before invoking the issuing substep. No pre-issue
    /// capability is available to that substep's post-issue continuation.
    pub(crate) fn issue<T>(
        self,
        issue: impl FnOnce() -> EffectResult<T>,
    ) -> EffectResult<Issued<T>> {
        issue().map(Issued)
    }
}
#[cfg(target_os = "linux")]
pub(crate) fn phase<P, T>(
    prepare: impl for<'phase> FnOnce(BeforeIssue<'phase>) -> EffectResult<Issued<P>>,
    after: impl FnOnce(P) -> Result<T, crate::effect::PostIssueError>,
) -> EffectResult<T> {
    let Issued(prepared) = prepare(BeforeIssue {
        _scope: std::marker::PhantomData,
    })?;
    after(prepared).map_err(EffectError::from)
}

#[cfg(target_os = "linux")]
pub(crate) mod incus {
    pub(crate) use super::phase;
    use super::*;
    use crate::incus::client::{refuse_root, validate_config_pair, validate_guest_path};
    use crate::incus::{BoundInstance, IncusClient};
    use std::process::{Child, Command};

    pub fn supervised_admission<G>(
        _before: &BeforeIssue<'_>,
        admit: impl FnOnce() -> Result<(std::sync::Arc<std::sync::atomic::AtomicBool>, G), RuntimeError>,
    ) -> EffectResult<(std::sync::Arc<std::sync::atomic::AtomicBool>, G)> {
        // This callback acquires the relay's pre-spawn authority guard.
        admit().map_err(NotIssuedProof::failed)
    }
    pub fn guest(_before: &BeforeIssue<'_>, guest: &crate::GuestIdentity) -> EffectResult<()> {
        guest.validate().map_err(NotIssuedProof::failed)
    }
    pub fn wrapper(
        _before: &BeforeIssue<'_>,
        request: &crate::RunCommandRequest,
    ) -> EffectResult<(Vec<String>, String)> {
        use crate::incus::exec as wrap;
        let op = &request.operation_id;
        let root = request.runs_as_root();
        if let Some(crate::BuildStep::Copy(copy)) = &request.build_step {
            crate::build_copy_argv(copy, &request.guest)
                .and_then(|argv| wrap::wrap_build_root_command(op, &argv))
                .map_err(NotIssuedProof::failed)
        } else if let Some(script) = &request.script {
            if !request.argv.is_empty() {
                return Err(NotIssuedProof::failed(RuntimeError::new(
                    SandboxErrorCode::ProtocolError,
                    "command.run cannot combine argv and script",
                )));
            }
            if root {
                wrap::wrap_build_root_script(op, script)
            } else {
                wrap::wrap_user_script(op, script, &request.guest)
            }
            .map_err(NotIssuedProof::failed)
        } else if root {
            wrap::wrap_build_root_command(op, &request.argv).map_err(NotIssuedProof::failed)
        } else {
            wrap::wrap_user_command(op, &request.argv, &request.guest)
                .map_err(NotIssuedProof::failed)
        }
    }
    pub fn spawn(before: BeforeIssue<'_>, command: &mut Command) -> EffectResult<Issued<Child>> {
        before.issue(|| {
            command.spawn().map_err(|e| {
                NotIssuedProof::failed(RuntimeError::new(
                    SandboxErrorCode::HostEffectNotIssued,
                    format!("incus spawn failed before issue: {e}"),
                ))
            })
        })
    }
    /// C51: spawn the ONE PTY child (`incus exec -t …`) on the slave side of
    /// a host PTY. Like `spawn`, a failure here happened before exec.
    pub fn spawn_pty(
        before: BeforeIssue<'_>,
        slave: &dyn portable_pty::SlavePty,
        builder: portable_pty::CommandBuilder,
    ) -> EffectResult<Issued<Box<dyn portable_pty::Child + Send + Sync>>> {
        before.issue(|| {
            slave.spawn_command(builder).map_err(|e| {
                NotIssuedProof::failed(RuntimeError::new(
                    SandboxErrorCode::HostEffectNotIssued,
                    format!("incus pty spawn failed before issue: {e}"),
                ))
            })
        })
    }

    pub fn name(_before: &BeforeIssue<'_>, name: &str) -> EffectResult<()> {
        crate::validate_managed_instance_name(name).map_err(NotIssuedProof::failed)
    }
    pub fn path(_before: &BeforeIssue<'_>, path: &str, mutate: bool) -> EffectResult<()> {
        validate_guest_path(path)
            .and_then(|()| if mutate { refuse_root(path) } else { Ok(()) })
            .map_err(NotIssuedProof::failed)
    }
    pub fn metadata_path(
        _before: &BeforeIssue<'_>,
        path: &str,
        mutate: bool,
    ) -> EffectResult<String> {
        crate::canonical_metadata_path(path, mutate).map_err(NotIssuedProof::failed)
    }
    pub fn file_path(_before: &BeforeIssue<'_>, path: &str) -> EffectResult<()> {
        crate::metadata::validate_file_path(path).map_err(NotIssuedProof::failed)
    }
    pub fn config(_before: &BeforeIssue<'_>, key: &str, value: &str) -> EffectResult<()> {
        validate_config_pair(key, value).map_err(NotIssuedProof::failed)
    }
    pub fn image(
        _before: &BeforeIssue<'_>,
        incus_fingerprint: Option<&str>,
        template_digest: &str,
    ) -> EffectResult<String> {
        crate::require_launch_fingerprint(incus_fingerprint, template_digest)
            .map_err(NotIssuedProof::failed)
    }
    /// The launch image of a create: the template, or on a restore the
    /// stored disk image with the template tag unchanged.
    pub fn launch_image(
        before: &BeforeIssue<'_>,
        request: &crate::CreateSandboxRequest,
    ) -> EffectResult<String> {
        match &request.restore {
            Some(restore) => crate::require_restore_launch_fingerprint(
                &restore.fingerprint,
                &request.template_digest,
            )
            .map_err(NotIssuedProof::failed),
            None => image(
                before,
                request.incus_fingerprint.as_deref(),
                &request.template_digest,
            ),
        }
    }
    pub fn bound(
        _before: &BeforeIssue<'_>,
        client: &IncusClient,
        bound: &BoundInstance,
    ) -> EffectResult<()> {
        client
            .query_instance(bound)
            .map(|_| ())
            .map_err(NotIssuedProof::failed)
    }
    pub fn binding(
        _before: &BeforeIssue<'_>,
        client: &IncusClient,
        name: &str,
        sandbox_id: &str,
        fingerprint: &str,
    ) -> EffectResult<BoundInstance> {
        client
            .bind_instance(name, sandbox_id, fingerprint, None)
            .map_err(NotIssuedProof::failed)
    }
    /// Recorded-policy validation is pure: presence, hash binding, and the
    /// 128-entry input bound. It MUST precede provisioning IO (profile queries,
    /// VM binding and the allocation lock). A refusal may subsequently read
    /// VM existence to classify FAILED versus UNKNOWN, without provisioning.
    pub fn recorded_policy(
        _before: &BeforeIssue<'_>,
        policy: Option<&sandbox_protocol::EgressPolicy>,
        hash: Option<&str>,
    ) -> EffectResult<()> {
        crate::incus::network::verify_policy_presence_and_hash(policy, hash)
            .map_err(NotIssuedProof::failed)
    }
    /// The instance name must be the sandbox's own managed name — checked
    /// BEFORE the allocation lock and any network apply, so a mismatched
    /// request never provisions bridge/ACL/intent state under a sandbox id
    /// whose cleanup paths would never reclaim it.
    pub fn name_belongs_to_sandbox(
        _before: &BeforeIssue<'_>,
        sandbox_id: &str,
        instance_name: &str,
    ) -> EffectResult<()> {
        let expected = crate::default_incus_instance_name(sandbox_id);
        if instance_name != expected {
            return Err(NotIssuedProof::failed(RuntimeError::new(
                SandboxErrorCode::IdempotencyConflict,
                format!(
                    "instance name `{instance_name}` does not belong to sandbox `{sandbox_id}`"
                ),
            )));
        }
        Ok(())
    }
    pub fn network_plan(
        before: &BeforeIssue<'_>,
        client: &IncusClient,
        request: &crate::CreateSandboxRequest,
    ) -> EffectResult<crate::incus::network::SandboxNetworkPlan> {
        #[cfg(test)]
        if let Some(count) = &client.network_planning_count {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        // B12 (coordinator ruling (c)): only a TEMPLATE_BUILD VM in
        // allowlist mode forwards non-granted names to the daemon's in-memory
        // DNS stub; every other sandbox's resolver has no stub (and no
        // resolver logs anything). Decided before the compile so the port
        // is part of the recorded settings.
        let mut settings = request.egress_settings.clone();
        settings.refused_dns_stub_port = None;
        let allowlist = request
            .egress_policy
            .as_ref()
            .is_none_or(|policy| policy.mode == sandbox_protocol::EgressMode::Allowlist);
        if request.refused_dns_hints && allowlist {
            let granted = request
                .egress_policy
                .as_ref()
                .map(|policy| {
                    policy
                        .domains
                        .iter()
                        .map(|domain| domain.to_ascii_lowercase())
                        .collect()
                })
                .unwrap_or_default();
            // Advisory: a stub that cannot start means no hints, never a
            // create failure (the resolver then refuses those names itself).
            settings.refused_dns_stub_port =
                match client.dns_stubs.prepare(&request.sandbox_id, granted, None) {
                    Ok(port) => Some(port),
                    Err(err) => {
                        eprintln!(
                            "wssp: DNS hints disabled for sandbox {}: {}",
                            request.sandbox_id, err.message
                        );
                        None
                    }
                };
        }
        let mut plan = network_plan_allocating(
            before,
            client,
            &request.sandbox_id,
            request.egress_policy.as_ref(),
            request.egress_policy_hash.as_deref(),
            &settings,
            || client.gateway_for(&request.sandbox_id),
        )?;
        // The full bind_instance tuple: persisted with the provisioning
        // intent so restart recovery applies the same authorization the
        // create path does before repairing or adopting an existing VM.
        plan.binding = Some(crate::incus::network::PlanBinding {
            template_fingerprint: request.template_digest.clone(),
            create_key: Some(request.idempotency_key.clone()),
        });
        Ok(plan)
    }
    /// The reconnect plan (§2.6): the effective policy is fixed at
    /// materialization, so a recorded plan bound to this policy hash supplies
    /// the rules, mode, settings and resolver base; the compile against
    /// current node settings is only a placeholder that, without a record,
    /// fails the readback closed.
    pub fn network_plan_for(
        before: &BeforeIssue<'_>,
        client: &IncusClient,
        sandbox_id: &str,
        policy: Option<&sandbox_protocol::EgressPolicy>,
        hash: Option<&str>,
    ) -> EffectResult<crate::incus::network::SandboxNetworkPlan> {
        let mut plan = network_plan_allocating(
            before,
            client,
            sandbox_id,
            policy,
            hash,
            &crate::egress::EgressSettings::default(),
            || client.gateway_for(sandbox_id),
        )?;
        if client.recorded_policy_hash(sandbox_id) == Some(hash.map(str::to_owned)) {
            client
                .overlay_recorded_plan(&mut plan)
                .map_err(NotIssuedProof::failed)?;
        }
        Ok(plan)
    }
    fn network_plan_allocating(
        _before: &BeforeIssue<'_>,
        client: &IncusClient,
        sandbox_id: &str,
        policy: Option<&sandbox_protocol::EgressPolicy>,
        hash: Option<&str>,
        settings: &crate::egress::EgressSettings,
        allocate: impl FnOnce() -> Result<std::net::Ipv4Addr, RuntimeError>,
    ) -> EffectResult<crate::incus::network::SandboxNetworkPlan> {
        // Policy/hash verification precedes any host IO (C35 fail-closed).
        crate::incus::network::verify_policy_presence_and_hash(policy, hash)
            .map_err(NotIssuedProof::failed)?;
        // The gateway reuses an owned bridge's persisted address on retries,
        // else a collision-checked allocation against managed networks and
        // host routes. Compilation is bounded and cancellation-aware: a
        // revoked worker resolves no further domains.
        let limits = crate::incus::network::CompileLimits {
            deadline: std::time::Instant::now() + crate::incus::network::COMPILE_BUDGET,
            cancelled: client.cancelled.as_deref(),
        };
        // Immutable reuse: the resolved grant expansion persisted at apply
        // time for this exact recorded hash replaces fresh DNS resolution, so
        // ordinary DNS rotation under an unchanged policy cannot break
        // reconnect. A hash mismatch (a different policy) never reuses.
        let mut effective: Option<(sandbox_protocol::EgressPolicy, String)> = None;
        if let (Some(policy), Some(hash)) = (policy, hash)
            && !policy.domains.is_empty()
            && let Some(grants) = client.persisted_plan_grants(sandbox_id, hash)
        {
            let mut cidrs = policy.cidrs.clone();
            cidrs.extend(grants);
            let expanded = sandbox_protocol::EgressPolicy {
                mode: sandbox_protocol::EgressMode::Allowlist,
                domains: Vec::new(),
                cidrs,
            };
            let expanded_hash = crate::incus::network::policy_hash_hex(&expanded);
            effective = Some((expanded, expanded_hash));
        }
        let recorded = (policy, hash);
        let (policy, hash) = match &effective {
            Some((expanded, expanded_hash)) => (Some(expanded), Some(expanded_hash.as_str())),
            None => recorded,
        };
        let resolver = |domain: &str, wait: std::time::Duration| {
            client.resolve_domain(sandbox_id, domain, wait)
        };
        let mut plan = crate::incus::network::compile_network_plan_allocating(
            sandbox_id, policy, hash, settings, &resolver, allocate, &limits,
        )
        .map_err(NotIssuedProof::failed)?;
        if effective.is_some()
            && let (Some(recorded), Some(recorded_hash)) = recorded
        {
            // The plan persists against the RECORDED policy identity, not the
            // expanded one it was compiled from.
            plan.policy_hash = Some(recorded_hash.to_owned());
            plan.policy_domains = recorded.domains.clone();
            plan.policy_cidrs = recorded.cidrs.clone();
            // C36: the flat expansion cannot reproduce the per-domain rule
            // identity (wssp-dns-<tag>) the refresh loop diffs by, so the
            // reused plan takes the rule set persisted at apply time
            // verbatim. Absent rules fall back to the compiled set, which
            // fails the reconnect readback closed (the persisted record is
            // the same write, so this means tampering or truncation).
            if let Some(rules) = client.persisted_plan_rules(sandbox_id, recorded_hash) {
                plan.rules = rules;
            }
            // §2.6: the reused plan also takes the recorded mode, settings,
            // resolver base and denied grants — never recompiled from
            // current node settings. A legacy record yields none.
            if let Ok(Some(recorded)) = client.persisted_enforcement_plan_checked(sandbox_id) {
                plan.mode = recorded.mode;
                plan.settings = recorded.settings;
                plan.dnsmasq_base = recorded.dnsmasq_base;
                plan.denied_grants = recorded.denied_grants;
            }
        }
        Ok(plan)
    }
    /// C37 start fence: an instance may only be STARTED after its recorded
    /// network policy (bridge + ACL + DNS state, read back against the
    /// persisted plan) verifies as enforced. This runs pre-issue so a fence
    /// failure is a refusal (NotIssued — the start was never attempted),
    /// never an uncertain outcome. Defense in depth at the runtime boundary:
    /// every start — create, adopt, reconnect, or a direct client call —
    /// passes through it, so no caller can resume a VM whose egress policy
    /// is lost, modified, or unverifiable.
    pub fn verified_enforcement(
        _before: &BeforeIssue<'_>,
        client: &IncusClient,
        instance_name: &str,
    ) -> EffectResult<()> {
        let sandbox_id =
            crate::sandbox_id_from_instance_name(instance_name).map_err(NotIssuedProof::failed)?;
        client
            .verify_provisioned_enforcement(sandbox_id)
            .map_err(NotIssuedProof::failed)?;
        // §2.0.5 guard attestation, AFTER the ACL/DNS readback and
        // immediately before `incus start`: a fresh guard `status` must
        // satisfy the lease rule and cover THIS sandbox's bridge and its
        // exact gateway pair. The early daemon check is only a cheap
        // refusal; this is the authoritative one. Nothing is started on
        // failure (NotIssued, `egress_guard_unavailable`).
        client
            .attest_guard_for_start(sandbox_id)
            .map_err(NotIssuedProof::failed)
    }
    pub fn storage_pool(
        _before: &BeforeIssue<'_>,
        client: &IncusClient,
        pool: &crate::StoragePoolIdentity,
    ) -> EffectResult<()> {
        client
            .observe_storage_pool(pool)
            .map(|_| ())
            .map_err(NotIssuedProof::failed)
    }
    pub fn profile_safety(
        _before: &BeforeIssue<'_>,
        client: &IncusClient,
        vm_size: sandbox_protocol::VmSize,
    ) -> EffectResult<()> {
        client
            .verify_launch_profile_safety(vm_size)
            .map_err(NotIssuedProof::failed)
    }
    /// C37 R1: launch-config hardening lives at the START boundary, not at
    /// initialization — the instance's EFFECTIVE config must carry only the
    /// audited allowlist on EVERY start (fresh create, existing-instance
    /// retry, cold resume, or a direct call), so a launch config rejected
    /// once can never be launched later through a path that skips init.
    pub fn launch_config(
        _before: &BeforeIssue<'_>,
        client: &IncusClient,
        instance_name: &str,
        vm_size: sandbox_protocol::VmSize,
    ) -> EffectResult<()> {
        client
            .verify_launch_config(instance_name, vm_size)
            .map_err(NotIssuedProof::failed)
    }
    pub fn running(
        _before: &BeforeIssue<'_>,
        client: &IncusClient,
        bound: &BoundInstance,
    ) -> EffectResult<()> {
        if !client
            .query_instance(bound)
            .map_err(NotIssuedProof::failed)?
            .is_running()
        {
            return Err(NotIssuedProof::failed(
                crate::incus::client::sandbox_not_running(bound.name()),
            ));
        }
        Ok(())
    }
    pub fn command(
        _before: &BeforeIssue<'_>,
        request: &crate::RunCommandRequest,
    ) -> EffectResult<()> {
        let checked = || {
            request.validate_command_shape()?;
            crate::incus::exec::validate_operation_id(&request.operation_id)?;
            crate::validate_managed_instance_name(&request.instance_name)?;
            if let Some(cwd) = &request.cwd {
                validate_guest_path(cwd)?;
            }
            crate::incus::client::validate_env(&request.env)
        };
        checked().map_err(NotIssuedProof::failed)
    }
    pub fn signal(_before: &BeforeIssue<'_>, pid: u32) -> EffectResult<()> {
        // PID 0/1 can never be a tracked wrapper leader (ProcessRef pid >= 2).
        if pid < 2 {
            return Err(NotIssuedProof::failed(RuntimeError::new(
                SandboxErrorCode::ProtocolError,
                "process signal requires a tracked pid",
            )));
        }
        Ok(())
    }
    /// Tracked-signal gate/target refusals (4b) are pre-effect by construction:
    /// they run before the helper is spawned.
    pub fn signal_admission<T>(
        _before: &BeforeIssue<'_>,
        admitted: Result<T, RuntimeError>,
    ) -> EffectResult<T> {
        admitted.map_err(NotIssuedProof::failed)
    }
}
