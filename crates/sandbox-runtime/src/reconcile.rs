//! A receipt in Effect phase has no pre-issue proof after restart. Only the
//! operation's expected host state can provide a new completion proof.
use crate::effect::PositiveEvidence;
use crate::{EffectOutcome, RuntimeError, SandboxRuntime};
use sandbox_protocol::{SandboxErrorCode, SandboxLifecycleState};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const POLICY_BATCH_MAX: usize = 16;

/// These are observations, never independent stop/delete authority. Incus
/// obtains them through C37's coherent, lifecycle-owned enforcement boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PolicyObservation {
    Verified,
    Drift,
    Inconclusive,
    Foreign,
    Absent,
    Pending,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyJournal {
    pub cursor: String,
    pub observations: BTreeMap<String, PolicyObservation>,
    pub health: sandbox_protocol::PolicyReconcilerHealth,
}

impl PolicyJournal {
    /// The candidate set is lifecycle-owned. No daemon-wide scan, no mutation
    /// based on a filename/name prefix. Failure isolation and rotation apply
    /// BEFORE observation, so a retained bad first entry cannot starve later ids.
    pub fn inspect(&mut self, ids: &[String], mut observe: impl FnMut(&str) -> PolicyObservation) {
        let ids: BTreeSet<_> = ids
            .iter()
            .filter(|id| {
                crate::validate_managed_instance_name(&crate::default_incus_instance_name(id))
                    .is_ok()
            })
            .cloned()
            .collect();
        self.observations.retain(|id, _| ids.contains(id));
        let ordered: Vec<_> = ids.iter().collect();
        let start = ordered
            .iter()
            .position(|id| *id > &self.cursor)
            .unwrap_or(0);
        for id in ordered[start..]
            .iter()
            .chain(ordered[..start].iter())
            .take(POLICY_BATCH_MAX)
        {
            let verdict = observe(id);
            self.observations.insert((*id).clone(), verdict);
            self.cursor = (*id).clone();
        }
        let mut health = sandbox_protocol::PolicyReconcilerHealth {
            enabled: true,
            last_pass_unix_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
            pending: u32::try_from(ids.len().saturating_sub(self.observations.len()))
                .unwrap_or(u32::MAX),
            ..Default::default()
        };
        for observation in self.observations.values() {
            match observation {
                PolicyObservation::Verified => health.verified += 1,
                PolicyObservation::Drift => health.drift += 1,
                PolicyObservation::Inconclusive => health.inconclusive += 1,
                PolicyObservation::Foreign => health.foreign += 1,
                PolicyObservation::Absent => health.absent += 1,
                PolicyObservation::Pending => health.pending += 1,
            }
        }
        self.health = health;
    }
}
pub(crate) struct InventoryProof(SandboxLifecycleState);
impl PositiveEvidence for InventoryProof {
    type Value = SandboxLifecycleState;
    fn value(self) -> Self::Value {
        self.0
    }
}

pub fn reconcile_effect(
    runtime: &dyn SandboxRuntime,
    kind: &str,
    sandbox_id: &str,
    create_key: Option<&str>,
    template_fingerprint: Option<&str>,
) -> EffectOutcome<SandboxLifecycleState> {
    if matches!(kind, "sandbox.create" | "sandbox.reconnect")
        && template_fingerprint.is_none_or(|value| !crate::is_incus_fingerprint(value))
    {
        return Err(RuntimeError::new(
            SandboxErrorCode::ProtocolError,
            "allocation receipt lacks a canonical template fingerprint",
        )
        .into());
    }
    if matches!(
        kind,
        "sandbox.create" | "sandbox.reconnect" | "sandbox.stop" | "sandbox.kill"
    ) {
        let observed = runtime.query_sandbox(
            sandbox_id,
            create_key,
            Some(template_fingerprint.unwrap_or_default()),
        )?;
        let end_state = match (kind, observed) {
            ("sandbox.create" | "sandbox.reconnect", Some(SandboxLifecycleState::Ready)) => {
                Some(SandboxLifecycleState::Ready)
            }
            ("sandbox.stop", Some(SandboxLifecycleState::Stopped)) => {
                Some(SandboxLifecycleState::Stopped)
            }
            ("sandbox.stop", None) => Some(SandboxLifecycleState::Absent),
            ("sandbox.kill", None) => Some(SandboxLifecycleState::Deleted),
            _ => None,
        };
        if let Some(state) = end_state {
            return Ok(InventoryProof(state).complete());
        }
    }
    Err(RuntimeError::new(
        SandboxErrorCode::UnknownOutcome,
        "host query does not prove the expected end state",
    )
    .into())
}
