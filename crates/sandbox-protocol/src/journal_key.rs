//! Authenticated private key bootstrap. The derived key must never be logged.
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JournalKeyInstall {
    pub connection_epoch: u64,
    pub key_version: u32,
    pub key_id: String,
    pub server: String,
    pub host_owner_id: String,
    pub host_id: String,
    pub key_hex: String,
}
impl std::fmt::Debug for JournalKeyInstall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JournalKeyInstall([REDACTED])")
    }
}
impl JournalKeyInstall {
    pub fn is_valid(&self) -> bool {
        self.connection_epoch > 0
            && self.connection_epoch <= i32::MAX as u64
            && self.key_version == 1
            && self.key_id.len() == 32
            && self
                .key_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && crate::canonical_body_hash(&self.key_hex)
            && !self.server.is_empty()
            && self.server.len() <= 2048
            && crate::terminal::valid_terminal_id(&self.host_owner_id)
            && crate::terminal::valid_terminal_id(&self.host_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ServerControlMessage, encode_server_control, parse_server_control};
    #[test]
    fn key_frame_debug_and_decode_errors_are_redacted() {
        let key = JournalKeyInstall {
            connection_epoch: 2,
            key_version: 1,
            key_id: "d".repeat(32),
            server: "wss://example.test/ws/sandbox-host".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
            key_hex: "ab".repeat(32),
        };
        let frame = ServerControlMessage::JournalKeyInstall(key.clone());
        assert!(!format!("{frame:?}").contains(&key.key_hex));
        let wire = encode_server_control(&frame).unwrap();
        assert!(matches!(
            parse_server_control(&wire).unwrap(),
            ServerControlMessage::JournalKeyInstall(_)
        ));
        for raw in [
            wire.replace("journal.key.install", &key.key_hex),
            wire.replace("keyVersion\":1", "keyVersion\":2"),
        ] {
            let error = parse_server_control(&raw).unwrap_err();
            assert!(!format!("{error:?} {error}").contains(&key.key_hex));
        }
    }
}

/// One enrolled transport, shared by all its workload creators. Never guessed
/// from a workload owner. This is also the host-derived journal-key scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportBindingV11 {
    pub server: String,
    pub host_owner_id: String,
    pub host_id: String,
}
impl TransportBindingV11 {
    pub fn is_valid(&self) -> bool {
        !self.server.is_empty()
            && self.server.len() <= 2048
            && crate::valid_terminal_id(&self.host_owner_id)
            && crate::valid_terminal_id(&self.host_id)
    }
}
