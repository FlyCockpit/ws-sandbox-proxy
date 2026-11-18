//! Preview tunnels run only on Linux nodes; elsewhere nothing is installed
//! and the capability is never advertised.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use sandbox_protocol::{TunnelApplyV11, TunnelCapabilityV11, TunnelClearV11, TunnelStatusV11};
use sandbox_runtime::SandboxRuntime;

#[derive(Debug, Clone)]
pub(crate) struct TunnelSettings {
    pub client: PathBuf,
    pub client_sha256: String,
    pub max_tunnels: u32,
    pub allow_for_others: bool,
}

pub(crate) struct TunnelManager;

impl TunnelManager {
    pub(crate) fn capability(&self) -> TunnelCapabilityV11 {
        unreachable_manager()
    }
    pub(crate) fn drain_events(&self) -> Vec<TunnelStatusV11> {
        Vec::new()
    }
    pub(crate) fn report_all(&self) {}
    pub(crate) fn apply(&self, _apply: TunnelApplyV11) {}
    pub(crate) fn clear(&self, _clear: &TunnelClearV11) {}
    pub(crate) fn stop_all(&self) {}
    pub(crate) fn restrict(&self, _sandbox_id: &str, _allowed: &[u16]) {}
}

fn unreachable_manager() -> TunnelCapabilityV11 {
    TunnelCapabilityV11 {
        client_sha256: String::new(),
        max_tunnels: 0,
        allow_for_others: false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeaseHere {
    Unknown,
    Lapsed,
    Live { own: bool },
}

pub(crate) type Holder = Arc<dyn Fn(&str) -> LeaseHere + Send + Sync>;

pub(crate) fn install(
    _settings: Option<TunnelSettings>,
    _runtime: Arc<dyn SandboxRuntime>,
    _state_dir: &Path,
    _holder: Holder,
) {
}

pub(crate) fn installed() -> Option<&'static Arc<TunnelManager>> {
    None
}

pub(crate) fn sweep_leftovers(_state_dir: &Path) -> anyhow::Result<()> {
    Ok(())
}
