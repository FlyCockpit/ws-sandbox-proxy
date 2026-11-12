#[cfg(test)]
mod tests {
    use crate::sandbox_relay::protocol::{SANDBOX_RELAY_PROTOCOL_VERSION, known_protocol_version};

    #[test]
    fn reexported_protocol_version_matches_crate() {
        assert_eq!(SANDBOX_RELAY_PROTOCOL_VERSION, "1.0");
        assert!(known_protocol_version(SANDBOX_RELAY_PROTOCOL_VERSION));
        assert!(!known_protocol_version("11.0"));
    }
}
