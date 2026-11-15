//! Shared implementation for the `wssp` binary.
//!
//! The binary entry point stays thin, while command definitions, config, exit
//! codes, logging, paths, and output helpers live here so they can be tested and
//! documented like normal Rust code.

pub mod auth;
pub mod cli;
pub mod commands;
pub mod config;
pub mod exit;
pub mod guard_report;
mod host_context;
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub mod host_process;
pub mod logging;
pub mod output;
pub mod paths;
pub mod sandbox_relay;
pub mod shutdown;
pub mod slug;
pub mod state;
pub mod storage_capacity;
pub mod tls;
pub mod vm_capacity;

#[cfg(test)]
mod release_identity;
#[cfg(test)]
mod sandbox_relay_protocol_tests {
    include!("sandbox_relay/protocol_test.rs");
}

#[cfg(all(test, unix))]
#[path = "../../../crates/sandbox-runtime/tests/support/managed_child.rs"]
pub(crate) mod managed_child;
