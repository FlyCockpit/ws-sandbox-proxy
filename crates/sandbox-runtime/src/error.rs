use sandbox_protocol::SandboxErrorCode;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{code}: {message}")]
pub struct RuntimeError {
    pub code: SandboxErrorCode,
    pub message: String,
    evidence: RuntimeEvidence,
    failure: Option<sandbox_protocol::results::Failure>,
    storage_reason: Option<sandbox_protocol::capacity_v11::StorageReason>,
    /// Typed egress refusal reason (docs/guide/network.md#refusal-reasons): the
    /// daemon maps it onto the wire `details.reason`, never message text.
    egress_refusal: Option<crate::egress::EgressRefusal>,
    /// Which readiness check failed: a constant label the daemon maps onto
    /// the wire `details.reason` of a `guest_unavailable`, never guest text.
    readiness_reason: Option<sandbox_protocol::ReadinessFailureReason>,
    /// A constant diagnostic label (never guest or host text), safe to log.
    diagnostic: Option<&'static str>,
    /// Host facts of a `vm_not_running` readiness failure, safe to log.
    not_running: Option<Box<NotRunningDetail>>,
}

/// Host facts of a `vm_not_running` readiness failure: which readiness path
/// saw the VM out of Running, the last Incus status read and how long ago the
/// VM was last seen Running. Never guest output; the status name is reduced
/// to at most 16 ASCII alphanumerics. Its `Display` is the operator log form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotRunningDetail {
    path: &'static str,
    status: Option<(String, u64)>,
    last_running_ms: Option<u128>,
}

impl NotRunningDetail {
    pub fn new(
        path: &'static str,
        status: Option<(&str, u64)>,
        last_running: Option<std::time::Duration>,
    ) -> Self {
        let status = status.map(|(name, code)| {
            let label: String = name
                .chars()
                .filter(char::is_ascii_alphanumeric)
                .take(16)
                .collect();
            let label = if label.is_empty() {
                "unknown".to_string()
            } else {
                label
            };
            (label, code)
        });
        Self {
            path,
            status,
            last_running_ms: last_running.map(|elapsed| elapsed.as_millis()),
        }
    }
}

impl std::fmt::Display for NotRunningDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "readiness path {}, observed status ", self.path)?;
        match &self.status {
            Some((name, code)) => write!(f, "{name}/{code}")?,
            None => f.write_str("none")?,
        }
        match self.last_running_ms {
            Some(ms) => write!(f, ", last seen Running {ms} ms ago"),
            None => f.write_str(", last seen Running never"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeEvidence {
    Ordinary,
    EnforcementInconclusive,
    /// Inconclusive BECAUSE a managed DNS refresh is owed (C58 NEW-1): the
    /// one refusal cause the owed refresh itself may clear.
    RefreshOwed,
}

impl RuntimeError {
    pub fn new(code: SandboxErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            evidence: RuntimeEvidence::Ordinary,
            failure: None,
            storage_reason: None,
            egress_refusal: None,
            readiness_reason: None,
            diagnostic: None,
            not_running: None,
        }
    }

    /// Host facts of a `vm_not_running` readiness failure, for operator logs.
    pub fn not_running_detail(&self) -> Option<&NotRunningDetail> {
        self.not_running.as_deref()
    }
    pub fn with_not_running_detail(mut self, detail: Option<NotRunningDetail>) -> Self {
        self.not_running = detail.map(Box::new);
        self
    }

    /// A constant label naming why this error happened, for operator logs.
    pub fn diagnostic(&self) -> Option<&'static str> {
        self.diagnostic
    }
    pub(crate) fn with_diagnostic(mut self, label: &'static str) -> Self {
        self.diagnostic = Some(label);
        self
    }

    pub fn egress_refusal(&self) -> Option<crate::egress::EgressRefusal> {
        self.egress_refusal
    }
    /// The typed wire `reason` for this error, if it is an egress refusal
    /// that travels as one and its code is the one the reason pairs with.
    pub fn wire_reason(&self) -> Option<sandbox_protocol::ProtocolErrorReason> {
        self.egress_refusal
            .and_then(crate::egress::EgressRefusal::wire_reason)
            .map(sandbox_protocol::ProtocolErrorReason::from)
            .or(self
                .readiness_reason
                .map(sandbox_protocol::ProtocolErrorReason::from))
            .filter(|reason| reason.fits(self.code))
    }
    pub fn readiness_reason(&self) -> Option<sandbox_protocol::ReadinessFailureReason> {
        self.readiness_reason
    }
    pub(crate) fn with_readiness_reason(
        mut self,
        reason: sandbox_protocol::ReadinessFailureReason,
    ) -> Self {
        self.readiness_reason = Some(reason);
        self
    }
    pub(crate) fn with_egress_refusal(mut self, reason: crate::egress::EgressRefusal) -> Self {
        self.egress_refusal = Some(reason);
        self
    }

    pub fn storage_reason(&self) -> Option<sandbox_protocol::capacity_v11::StorageReason> {
        self.storage_reason.clone()
    }
    pub(crate) fn storage_missing(mut self) -> Self {
        self.storage_reason = Some(sandbox_protocol::capacity_v11::StorageReason::Missing);
        self
    }

    pub fn failure(&self) -> Option<&sandbox_protocol::results::Failure> {
        self.failure.as_ref()
    }

    pub(crate) fn filesystem(mut self, effect: sandbox_protocol::results::FailureEffect) -> Self {
        self.failure = Some(sandbox_protocol::results::Failure {
            reason: None,
            resource: sandbox_protocol::results::FailureResource::Filesystem,
            effect,
        });
        self
    }
    pub(crate) fn uncertain(mut self) -> Self {
        if let Some(failure) = &mut self.failure {
            failure.effect = sandbox_protocol::results::FailureEffect::Unknown;
        }
        self
    }

    /// Unavailable policy evidence is never a cleanup-authorizing guest failure.
    /// Keep this typed through helper/effect/readiness wrappers, not message matching.
    pub(crate) fn enforcement_inconclusive(mut self) -> Self {
        if self.evidence != RuntimeEvidence::RefreshOwed {
            self.evidence = RuntimeEvidence::EnforcementInconclusive;
        }
        if self.code == SandboxErrorCode::GuestUnavailable {
            self.code = SandboxErrorCode::Internal;
        }
        self
    }

    pub(crate) fn is_enforcement_inconclusive(&self) -> bool {
        matches!(
            self.evidence,
            RuntimeEvidence::EnforcementInconclusive | RuntimeEvidence::RefreshOwed
        )
    }

    /// Inconclusive evidence whose cause is an owed DNS refresh (C58
    /// G1-R1-3). Never cleanup-authorizing, like every inconclusive error.
    pub(crate) fn refresh_owed(mut self) -> Self {
        self.evidence = RuntimeEvidence::RefreshOwed;
        if self.code == SandboxErrorCode::GuestUnavailable {
            self.code = SandboxErrorCode::Internal;
        }
        self
    }

    pub(crate) fn is_refresh_owed(&self) -> bool {
        self.evidence == RuntimeEvidence::RefreshOwed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inconclusive_evidence_never_carries_cleanup_authority() {
        for code in [
            SandboxErrorCode::Internal,
            SandboxErrorCode::Timeout,
            SandboxErrorCode::Cancelled,
            SandboxErrorCode::Transport,
            SandboxErrorCode::GuestUnavailable,
        ] {
            let error = RuntimeError::new(code, "unavailable evidence").enforcement_inconclusive();
            assert!(error.is_enforcement_inconclusive());
            assert_ne!(error.code, SandboxErrorCode::GuestUnavailable);
            assert_eq!(
                error.code,
                if code == SandboxErrorCode::GuestUnavailable {
                    SandboxErrorCode::Internal
                } else {
                    code
                }
            );
        }
    }
}
