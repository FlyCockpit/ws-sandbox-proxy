//! One process-wide hook that runs before a sandbox's bridge and ACL are
//! deleted, on every teardown path (destroy, rollback, journal drains). The
//! node daemon uses it to stop the sandbox's preview-tunnel client and wait
//! for it to exit: a client must never outlive the network its target
//! address belongs to, because a later sandbox may reuse that subnet.

use std::sync::{Arc, OnceLock};

use crate::RuntimeError;

/// Called with the sandbox id; an error aborts the teardown (fail closed:
/// the network and subnet stay reserved and the teardown is retried).
pub type NetworkTeardownHook = Arc<dyn Fn(&str) -> Result<(), RuntimeError> + Send + Sync>;

static HOOK: OnceLock<NetworkTeardownHook> = OnceLock::new();

/// Called with the sandbox id after a new bridge was created for it.
pub type NetworkCreatedHook = Arc<dyn Fn(&str) + Send + Sync>;

static CREATED: OnceLock<NetworkCreatedHook> = OnceLock::new();

/// Install the bridge-created hook once per process.
pub fn set_network_created_hook(hook: NetworkCreatedHook) -> bool {
    CREATED.set(hook).is_ok()
}

pub(crate) fn network_created(sandbox_id: &str) {
    if let Some(hook) = CREATED.get() {
        hook(sandbox_id);
    }
}

/// Called with the sandbox id once its network and recorded plan are gone.
pub type NetworkRemovedHook = Arc<dyn Fn(&str) + Send + Sync>;

static REMOVED: OnceLock<NetworkRemovedHook> = OnceLock::new();

/// Install the network-removed hook once per process.
pub fn set_network_removed_hook(hook: NetworkRemovedHook) -> bool {
    REMOVED.set(hook).is_ok()
}

pub(crate) fn network_removed(sandbox_id: &str) {
    if let Some(hook) = REMOVED.get() {
        hook(sandbox_id);
    }
}

/// Install the hook once per process; `false` if one is already installed.
pub fn set_network_teardown_hook(hook: NetworkTeardownHook) -> bool {
    HOOK.set(hook).is_ok()
}

pub(crate) fn before_network_teardown(sandbox_id: &str) -> Result<(), RuntimeError> {
    match HOOK.get() {
        Some(hook) => hook(sandbox_id),
        None => Ok(()),
    }
}
