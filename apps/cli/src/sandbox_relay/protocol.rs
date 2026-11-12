//! Thin re-export of `sandbox-protocol` for the node daemon binary. Full WSS
//! session handling lands in a later phase; this module keeps compile-time parity
//! with the server-side relay types.

pub use sandbox_protocol::*;
