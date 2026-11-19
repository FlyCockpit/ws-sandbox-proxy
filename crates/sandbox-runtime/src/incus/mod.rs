pub(crate) mod acl;
pub(crate) mod client;
mod command_scope;
#[cfg(test)]
mod credential_shim_tests;
mod credentials;
pub(crate) mod dns;
pub(crate) mod dns_refresh;
mod dns_stub;
mod dns_stub_peer;
pub(crate) mod effect_completion;
mod env_frame;
#[cfg(test)]
mod env_frame_tests;
pub(crate) mod exec;
mod frames;
mod guest_sudo;
mod kvm;
pub(crate) mod network;
pub(crate) mod pty;
mod root_grow;
mod server_lease;
mod storage;
#[cfg(test)]
mod storage_shim_tests;
mod tunnel_ports;
#[cfg(test)]
mod tunnel_ports_tests;

#[cfg(test)]
mod bootstrap_shim_tests;
#[cfg(test)]
mod command_scope_shim_tests;
#[cfg(test)]
mod dns_refresh_shim_tests;
#[cfg(test)]
mod dns_shim_tests;
#[cfg(test)]
mod egress_mode_tests;
#[cfg(test)]
mod egress_open_shim_tests;
#[cfg(test)]
mod image_shim_tests;
#[cfg(test)]
mod network_shim_tests;
#[cfg(test)]
mod pty_shim_tests;
#[cfg(test)]
mod restore_shim_tests;
#[cfg(test)]
mod shim_tests;
#[cfg(test)]
mod vm_size_shim_tests;

pub use client::{
    BindingIdentity, BoundInstance, HostInstance, IncusClient, IncusCommandOutput, ListedInstance,
};
pub use dns::{
    DnsRefreshOutcome, DnsTransport, FakeDnsOutcome, FakeDnsRecord, FakeDnsTransport,
    UdpDnsTransport, host_dns_servers,
};
pub use exec::{ExecSupervisor, GUEST_TERMINATE_TIMEOUT};
pub use kvm::{IncusConfig, IncusKvmRuntime};
pub use network::sandbox_network_names;
pub use server_lease::{
    DaemonIdentity, LEASE_PROFILE_PREFIX, LEASE_RENEW_EVERY, LEASE_TTL_SECS, LeaseEvent,
    LeaseFencedProbe, LeaseHealth, LeaseHolder, LeaseTiming, ServerLease, ServerLeaseError,
};

mod files;
#[cfg(test)]
mod metadata_tests;
#[cfg(test)]
mod mutation_tests;
#[cfg(test)]
mod signal_helper_tests;

#[cfg(test)]
use crate::managed_child;
