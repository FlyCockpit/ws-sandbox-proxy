//! Guard status production.
//!
//! The status FORMAT and the `guard_ok` lease rule are owned by
//! [`crate::guard::probe`] (`GuardStatus`, `evaluate_guard`,
//! `attest_bridge`): the guard emits exactly that object on the socket and
//! in `/run/wssp-guard/status.json`. This module maps the guard's internal
//! source provenance onto it and holds the per-instance helpers.

use crate::guard::probe::{GuardSourceState, GuardSourceStatus, GuardStatus};

use super::sources::{Source, SourceState};

/// Wire state of one source: its provenance state and the digest of the
/// content it currently enforces (its last valid content). Never contents.
pub fn source_status(source: &Source) -> GuardSourceStatus {
    let state = match &source.state {
        SourceState::Valid { .. } => GuardSourceState::Valid,
        SourceState::NotConfigured { .. } => GuardSourceState::NotConfigured,
        SourceState::Invalid { .. } => GuardSourceState::Invalid,
        SourceState::Missing => GuardSourceState::Missing,
        SourceState::Unknown => GuardSourceState::Unknown,
    };
    let digest = match &source.state {
        SourceState::Valid { digest, .. } | SourceState::NotConfigured { digest } => {
            Some(digest.clone())
        }
        _ => source.last_valid.as_ref().map(|c| c.digest()),
    };
    GuardSourceStatus { state, digest }
}

/// Machine reason code for an unhealthy source, e.g.
/// `root_source:invalid:line:7`, `deployment_source:unknown`.
pub fn source_reason(name: &str, source: &Source) -> Option<String> {
    match &source.state {
        SourceState::Valid { .. } | SourceState::NotConfigured { .. } => None,
        SourceState::Invalid {
            line: Some(line), ..
        } => Some(format!("{name}_source:invalid:line:{line}")),
        other => Some(format!("{name}_source:{}", other.label())),
    }
}

/// Rejects a status older than one already seen from the same guard
/// instance (`(instance_id, generation)` fence, §2.0.5). A new instance
/// resets it. For the daemon's heartbeat (E3).
#[derive(Debug, Clone, Default)]
pub struct GenerationFence {
    last: Option<(String, u64)>,
}

impl GenerationFence {
    /// `false` (and no update) for a stale status.
    pub fn observe(&mut self, status: &GuardStatus) -> bool {
        if let Some((instance, generation)) = &self.last
            && *instance == status.instance_id
            && status.generation < *generation
        {
            return false;
        }
        self.last = Some((status.instance_id.clone(), status.generation));
        true
    }
}

/// A fresh random 128-bit instance id (hex).
pub fn new_instance_id() -> std::io::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|err| std::io::Error::other(err.to_string()))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
#[path = "tests/status.rs"]
mod tests;
