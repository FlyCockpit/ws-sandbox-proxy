//! Preview tunnels: a tunnel sandbox's declared ports changed at runtime by
//! a server-issued `tunnel.ports` (docs/guide/tunnels.md).
//!
//! The recorded plan (`network-plans/<id>.json`) is the drift checker's
//! reference, so the live ACL and the record must move together without a
//! window a verifier could read as drift (which deletes a healthy VM) and
//! without a window where the host's client forwards an undeclared port:
//!
//! 1. `sandbox_lock` (lifecycle operations, the DNS refresh and the policy
//!    reconciler's try-lock are serialized with it);
//! 2. the DNS lease owner's `commit` lock (the lease settlement rewrites the
//!    recorded rules from a live readback under it) and a DNS transition
//!    (lockless verifiers retry instead of convicting a straddled read);
//! 3. an earlier unconfirmed change is rolled back first (one confirmed ACL
//!    write to the committed variant; a confirmed write changes the ACL's
//!    ETag, so no earlier uncertain write can land afterwards);
//! 4. write-ahead: the record gains `tunnel_pending` (this revision); from
//!    here every comparison accepts the committed or this variant, and the
//!    client may forward only ports both keep;
//! 5. `before_acl` stops a client forwarding anything else (its live
//!    connections close with it);
//! 6. one If-Match ACL write replaces only the tagged ingress rule;
//! 7. a fresh read-modify-write of the record commits the rule, the ports
//!    and the revision and clears the pending change.
//!
//! A crash or an uncertain write leaves the pending change: verification
//! tolerates exactly the two variants, the DNS refresh resolves it before it
//! commits anything, and the next `tunnel.ports` (the server retries until
//! acknowledged) rolls it back first. Nothing in the guest reaches any of
//! this: the only writer is the relay's server-authenticated frame.

use sandbox_protocol::{SandboxErrorCode, TunnelPortsOutcomeV11 as Outcome};

use super::acl::{ObservedRule, api_rule};
use super::client::IncusClient;
use super::network::{
    AclDirection, AclRule, NETWORK_PROJECT_TAG, NETWORK_SANDBOX_TAG, SandboxNetworkPlan,
    TUNNEL_INGRESS_RULE_TAG, sandbox_network_names, tunnel_ingress_rule, with_tunnel_variant,
};
use crate::TunnelPortsUpdate;
use crate::egress::{EgressSettings, TunnelPortsPending};
use crate::error::RuntimeError;

fn internal(message: impl Into<String>) -> RuntimeError {
    RuntimeError::new(SandboxErrorCode::Internal, message)
}

impl IncusClient {
    /// `tunnel.ports`: see the module documentation.
    pub(crate) fn update_tunnel_ports(
        &self,
        sandbox_id: &str,
        revision: u64,
        ports: &[u16],
        before_acl: &dyn Fn(&[u16]),
    ) -> Result<TunnelPortsUpdate, RuntimeError> {
        crate::validate_managed_instance_name(&crate::default_incus_instance_name(sandbox_id))?;
        if revision == 0 || !sandbox_protocol::valid_declared_tunnel_ports(ports) {
            return Err(RuntimeError::new(
                SandboxErrorCode::ProtocolError,
                "a tunnel-port change needs a revision and 0-8 ascending ports",
            ));
        }
        let lock = self.sandbox_lock(sandbox_id);
        let _guard = lock.lock().unwrap_or_else(|err| err.into_inner());
        let answer = |outcome, revision| TunnelPortsUpdate { outcome, revision };
        self.hold_dns_commit(sandbox_id, || {
            let _transition = self.begin_dns_transition(sandbox_id);
            let Some(plan) = self.persisted_enforcement_plan_checked(sandbox_id)? else {
                return Ok(answer(Outcome::Absent, revision));
            };
            if !plan.tunnel_enabled() || plan.pinned_guest_address().is_none() {
                return Ok(answer(Outcome::Refused, revision));
            }
            // A record whose bridge is gone (a teardown that could not
            // unlink it) is no plan to change.
            if !self.live_network_matches(&plan) {
                return Ok(answer(Outcome::Absent, revision));
            }
            self.roll_back_tunnel_pending_held(sandbox_id)?;
            let settings = recorded_settings(&plan)?;
            if revision <= settings.tunnel_revision {
                return Ok(answer(Outcome::Applied, settings.tunnel_revision));
            }
            self.rewrite_tunnel_record(sandbox_id, |settings, _| {
                settings.tunnel_pending = Some(TunnelPortsPending {
                    revision,
                    ports: ports.to_vec(),
                });
                Ok(None)
            })?;
            let forwardable: Vec<u16> = plan
                .tunnel_ports()
                .iter()
                .copied()
                .filter(|port| ports.contains(port))
                .collect();
            before_acl(&forwardable);
            let committed = plan.tunnel_ports().to_vec();
            if let Err(error) = self.write_tunnel_rule(&plan, &[&committed, ports], ports) {
                // Best effort: a confirmed roll-back clears the pending
                // change now; otherwise it stays (tolerated) for the retry.
                let _ = self.roll_back_tunnel_pending_held(sandbox_id);
                return Err(error);
            }
            self.rewrite_tunnel_record(sandbox_id, |settings, gateway| {
                if settings
                    .tunnel_pending
                    .as_ref()
                    .is_none_or(|pending| pending.revision != revision)
                {
                    return Err(internal("the pending tunnel-port change was replaced"));
                }
                settings.tunnel_ports = Some(ports.to_vec());
                settings.tunnel_revision = revision;
                settings.tunnel_pending = None;
                Ok(Some((gateway, ports.to_vec())))
            })?;
            Ok(answer(Outcome::Applied, revision))
        })
    }

    /// Resolve an unconfirmed change before a writer that copies the live
    /// ACL into the record (the DNS refresh). The caller holds
    /// `sandbox_lock`; this takes the commit lock itself.
    pub(crate) fn resolve_tunnel_pending_locked(
        &self,
        sandbox_id: &str,
    ) -> Result<(), RuntimeError> {
        // An unreadable record carries no change to resolve: the caller's
        // own fences refuse it (with their own error) as before.
        let pending = self
            .persisted_enforcement_plan(sandbox_id)
            .and_then(|plan| plan.settings)
            .and_then(|settings| settings.tunnel_pending);
        if pending.is_none() {
            return Ok(());
        }
        self.hold_dns_commit(sandbox_id, || {
            let _transition = self.begin_dns_transition(sandbox_id);
            self.roll_back_tunnel_pending_held(sandbox_id)
        })
    }

    /// Under `sandbox_lock` and the commit lock: one confirmed write of the
    /// committed variant, then the pending change is cleared.
    fn roll_back_tunnel_pending_held(&self, sandbox_id: &str) -> Result<(), RuntimeError> {
        let Some(plan) = self.persisted_enforcement_plan_checked(sandbox_id)? else {
            return Ok(());
        };
        let Some(pending) = plan
            .settings
            .as_ref()
            .and_then(|settings| settings.tunnel_pending.clone())
        else {
            return Ok(());
        };
        let committed = plan.tunnel_ports().to_vec();
        self.write_tunnel_rule(&plan, &[&committed, &pending.ports], &committed)?;
        self.rewrite_tunnel_record(sandbox_id, |settings, _| {
            settings.tunnel_pending = None;
            Ok(None)
        })
    }

    /// One If-Match write of the sandbox's ACL replacing only its tunnel
    /// rule with the variant for `ports`. The live rule must be one of the
    /// `allowed` variants (anything else is drift for the checker to
    /// convict, never laundered here), and the ACL must be this sandbox's.
    fn write_tunnel_rule(
        &self,
        plan: &SandboxNetworkPlan,
        allowed: &[&[u16]],
        ports: &[u16],
    ) -> Result<(), RuntimeError> {
        let (_, acl_name) = sandbox_network_names(&plan.sandbox_id);
        let gateway = plan.gateway;
        self.update_acl(&acl_name, self.agent_timeout, |metadata| {
            let config = &metadata["config"];
            if config[NETWORK_SANDBOX_TAG].as_str() != Some(plan.sandbox_id.as_str())
                || config[NETWORK_PROJECT_TAG].as_str() != Some(self.project.as_str())
            {
                return Err(super::acl::foreign_object("network acl", &acl_name));
            }
            let ingress = metadata["ingress"].as_array().cloned().unwrap_or_default();
            let live: Vec<ObservedRule> = ingress
                .iter()
                .map(ObservedRule::from_json)
                .collect::<Result<_, _>>()?;
            let tagged: Vec<&ObservedRule> = live
                .iter()
                .filter(|rule| rule.description == TUNNEL_INGRESS_RULE_TAG)
                .collect();
            let known = allowed.iter().any(|variant| {
                match (tunnel_ingress_rule(gateway, variant), tagged.as_slice()) {
                    (None, []) => true,
                    (Some(expected), [observed]) => observed.matches_plan(&expected),
                    _ => false,
                }
            });
            // A tunnel rule is always the first ingress rule.
            let placed = tagged.is_empty()
                || live
                    .first()
                    .is_some_and(|rule| rule.description == TUNNEL_INGRESS_RULE_TAG);
            if !known || !placed {
                return Err(RuntimeError::new(
                    SandboxErrorCode::IdempotencyConflict,
                    "the sandbox's live tunnel rule differs from its recorded plan",
                ));
            }
            let mut next: Vec<serde_json::Value> = ingress
                .into_iter()
                .filter(|rule| {
                    rule.get("description").and_then(serde_json::Value::as_str)
                        != Some(TUNNEL_INGRESS_RULE_TAG)
                })
                .collect();
            if let Some(rule) = tunnel_ingress_rule(gateway, ports) {
                next.insert(0, api_rule(&rule));
            }
            metadata["ingress"] = next.into();
            Ok(())
        })
    }

    /// Fresh read-modify-write of the recorded plan's tunnel fields (other
    /// writers own the rest of the record). `edit` may return
    /// `(gateway, ports)`: the recorded tunnel rule becomes that variant.
    fn rewrite_tunnel_record(
        &self,
        sandbox_id: &str,
        edit: impl FnOnce(
            &mut EgressSettings,
            std::net::Ipv4Addr,
        ) -> Result<Option<(std::net::Ipv4Addr, Vec<u16>)>, RuntimeError>,
    ) -> Result<(), RuntimeError> {
        // Shape-checks the whole record first (an unreadable record is
        // never rewritten).
        let plan = self
            .persisted_enforcement_plan_checked(sandbox_id)?
            .ok_or_else(|| internal("the recorded plan is gone"))?;
        let path = self.plans_dir().join(format!("{sandbox_id}.json"));
        let body = std::fs::read_to_string(&path)
            .map_err(|err| internal(format!("cannot read the recorded plan: {err}")))?;
        let mut record: serde_json::Value = serde_json::from_str(&body)
            .map_err(|err| internal(format!("cannot parse the recorded plan: {err}")))?;
        let mut settings = recorded_settings(&plan)?;
        if let Some((gateway, ports)) = edit(&mut settings, plan.gateway)? {
            let rules = with_tunnel_variant(&plan.rules, gateway, &ports);
            record["rules"] = serde_json::to_value(&rules)
                .map_err(|err| internal(format!("cannot encode the plan rules: {err}")))?;
        }
        settings.validate()?;
        record["settings"] = serde_json::to_value(&settings)
            .map_err(|err| internal(format!("cannot encode the egress settings: {err}")))?;
        self.write_durable_record(
            &self.plans_dir(),
            &format!("{sandbox_id}.json"),
            &record.to_string(),
        )
    }

    /// Verification tolerance: the recorded rules with the tunnel rule
    /// replaced by the unconfirmed change's variant, when the record carries
    /// one (`rules` are the reference rules the caller compares against).
    pub(crate) fn tunnel_pending_variant(
        &self,
        sandbox_id: &str,
        rules: &[AclRule],
    ) -> Option<Vec<AclRule>> {
        let plan = self.persisted_enforcement_plan(sandbox_id)?;
        let pending = plan.settings.as_ref()?.tunnel_pending.as_ref()?;
        Some(with_tunnel_variant(rules, plan.gateway, &pending.ports))
    }
}

fn recorded_settings(plan: &SandboxNetworkPlan) -> Result<EgressSettings, RuntimeError> {
    plan.settings
        .clone()
        .ok_or_else(|| internal("the recorded plan has no egress settings"))
}

/// The lease settlement's tolerance (it compares every live rule with the
/// derived record): while a change is pending, the tunnel rule is compared
/// separately — the live one must be one of the two variants — and the
/// record keeps its committed rule.
pub(crate) fn tunnel_rule_is_known_variant(
    observed: &[ObservedRule],
    gateway: std::net::Ipv4Addr,
    committed: &[u16],
    pending: &[u16],
) -> bool {
    let tagged: Vec<&ObservedRule> = observed
        .iter()
        .filter(|rule| rule.description == TUNNEL_INGRESS_RULE_TAG)
        .collect();
    [committed, pending].iter().any(|variant| {
        match (tunnel_ingress_rule(gateway, variant), tagged.as_slice()) {
            (None, []) => true,
            (Some(expected), [rule]) => {
                expected.direction == AclDirection::Ingress && rule.matches_plan(&expected)
            }
            _ => false,
        }
    })
}
