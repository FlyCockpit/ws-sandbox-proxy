//! Lifecycle states for sandboxes and operations (control-plane contract).

use serde::{Deserialize, Serialize};

/// Sandbox machine state from the implementation plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxLifecycleState {
    Requested,
    Scheduled,
    Provisioning,
    Ready,
    Stopping,
    Stopped,
    /// Host-observed absence; the control plane records this STOP outcome as Deleted.
    Absent,
    Reclaiming,
    Deleted,
    Unreachable,
    Recovered,
    HostLost,
    Error,
}

/// Durable operation state tracked by the control plane and host WAL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Queued,
    Dispatched,
    Accepted,
    Running,
    CancelRequested,
    Succeeded,
    Failed,
    Cancelled,
    UnknownOutcome,
}
