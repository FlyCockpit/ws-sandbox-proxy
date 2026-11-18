//! Sandbox host relay wiring (protocol types shared with the control plane).

pub mod authority;
mod build;
mod carry;
mod command_retire;
pub mod connect;
pub mod credentials;
pub mod images;
pub mod journal;
mod journal_key;
pub mod live_admission;
pub mod offload;
mod output;
pub mod protocol;
pub mod reconcile;
mod startup;
pub mod supervisor;

mod files;

mod agent_policy;
mod clock;
mod egress_hints;
mod egress_state;
mod evidence;
mod expiry;
mod host_access;
mod host_exec;
mod host_files;
mod host_mask;
mod host_policy;
mod host_reports;
pub mod quiesce;
mod resolutions;
mod revocation;
mod terminal;
mod test_timing;
#[cfg(target_os = "linux")]
pub(crate) mod tunnel;
#[cfg(not(target_os = "linux"))]
#[path = "tunnel_stub.rs"]
pub(crate) mod tunnel;
pub(crate) mod tunnel_ports;

/// Encode a daemon frame using the sole supported 1.0 vocabulary.
pub(crate) fn spell(
    wire: sandbox_protocol::WireCodes,
    message: &sandbox_protocol::DaemonControlMessage,
    kind: Option<&str>,
) -> anyhow::Result<String> {
    let spelled = wire.encode(message, kind)?;
    Ok(spelled.text)
}

/// Encode a control frame for the current protocol.
pub(crate) fn plain_frame(
    message: &sandbox_protocol::DaemonControlMessage,
) -> anyhow::Result<String> {
    spell(sandbox_protocol::WireCodes::CURRENT, message, None)
}
#[cfg(test)]
mod test_support;

#[cfg(all(test, target_os = "linux"))]
mod host_access_wire_tests;
