//! The single relay protocol accepted by both peers.
pub const SANDBOX_RELAY_PROTOCOL_VERSION: &str = "1.0";
pub const SANDBOX_RELAY_SUBPROTOCOL: &str = "ws-sandbox-proxy.relay.v1";

pub fn known_protocol_version(version: &str) -> bool {
    version == SANDBOX_RELAY_PROTOCOL_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_current_version_is_accepted() {
        assert!(known_protocol_version("1.0"));
        for version in ["11.0", "0.9", "1.1", "2.0", "", "1", "1.0.0"] {
            assert!(!known_protocol_version(version), "{version}");
        }
    }
}
