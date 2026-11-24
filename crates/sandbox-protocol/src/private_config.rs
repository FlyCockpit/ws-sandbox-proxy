//! Private config transport. Values and binding MACs are never Debug data.
use serde::{Deserialize, Serialize};

pub const PRIVATE_CONFIG_MAX_BYTES: usize = 96 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivateConfigRef {
    pub config_id: String,
    pub binding_scheme: String,
    pub binding_key_id: String,
    pub binding_mac: String,
}

impl std::fmt::Debug for PrivateConfigRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivateConfigRef([REDACTED])")
    }
}

pub fn valid_key_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl PrivateConfigRef {
    pub fn is_valid(&self) -> bool {
        crate::ids::valid_terminal_id(&self.config_id)
            && self.binding_scheme == "hmac-sha256-v1"
            && valid_key_id(&self.binding_key_id)
            && crate::canonical_body_hash(&self.binding_mac)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivateConfigInstall {
    pub sandbox_owner_id: String,
    pub connection_epoch: u64,
    pub server: String,
    pub host_owner_id: String,
    pub host_id: String,
    pub sandbox_id: String,
    pub generation: u64,
    pub config: PrivateConfigRef,
    pub env: Vec<(String, String)>,
    /// Correlation token for a refusal before persistence. Required on the wire.
    #[serde(deserialize_with = "crate::egress::present")]
    pub refusal_token: Option<String>,
}

impl std::fmt::Debug for PrivateConfigInstall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivateConfigInstall([REDACTED])")
    }
}

impl PrivateConfigInstall {
    pub fn is_valid(&self) -> bool {
        self.connection_epoch > 0
            && self.connection_epoch <= i32::MAX as u64
            && !self.server.is_empty()
            && self.server.len() <= crate::RECEIPT_LIMITS.server_bytes
            && [&self.host_owner_id, &self.host_id, &self.sandbox_id]
                .iter()
                .all(|id| crate::ids::valid_terminal_id(id))
            && self.generation > 0
            && self.generation <= i32::MAX as u64
            && crate::valid_terminal_id(&self.sandbox_owner_id)
            && self.config.is_valid()
            && self
                .refusal_token
                .as_ref()
                .is_some_and(|token| crate::ids::valid_terminal_id(token))
            && crate::validate_env(&self.env).is_ok()
            && self
                .env
                .iter()
                .all(|(name, _)| !matches!(name.as_str(), "HOME" | "SHELL" | "TERM"))
    }
}

/// Only the server binding is echoed. The local integrity checksum is private.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivateConfigAck {
    pub sandbox_owner_id: String,
    pub connection_epoch: u64,
    pub sandbox_id: String,
    pub generation: u64,
    pub config: PrivateConfigRef,
}

impl std::fmt::Debug for PrivateConfigAck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivateConfigAck([REDACTED])")
    }
}

impl PrivateConfigAck {
    pub fn is_valid(&self) -> bool {
        self.connection_epoch > 0
            && self.connection_epoch <= i32::MAX as u64
            && crate::ids::valid_terminal_id(&self.sandbox_id)
            && self.generation > 0
            && self.generation <= i32::MAX as u64
            && crate::valid_terminal_id(&self.sandbox_owner_id)
            && self.config.is_valid()
    }
}

/// Closed pre-effect causes. No private values, paths, hashes or free text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum PrivateConfigRefusalReason {
    #[error("private config cleanup watermark")]
    CleanupWatermark,
    #[error("private config count bound")]
    ConfigCountBound,
    #[error("private config journal IO before persistence")]
    JournalIoBeforePersistence,
}

/// A refusal before persistence, correlated to the install token. It never
/// refuses an operation whose effect may already have been issued.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivateConfigRefused {
    pub sandbox_owner_id: String,
    pub connection_epoch: u64,
    pub sandbox_id: String,
    pub generation: u64,
    pub config_id: String,
    pub refusal_token: String,
    pub reason: PrivateConfigRefusalReason,
}

impl PrivateConfigRefused {
    pub fn is_valid(&self) -> bool {
        self.connection_epoch > 0
            && self.connection_epoch <= i32::MAX as u64
            && self.generation > 0
            && self.generation <= i32::MAX as u64
            && [
                &self.sandbox_owner_id,
                &self.sandbox_id,
                &self.config_id,
                &self.refusal_token,
            ]
            .iter()
            .all(|id| crate::ids::valid_terminal_id(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::encode_daemon_control;
    use crate::{
        DaemonControlMessage, ServerControlMessage, encode_server_control, parse_daemon_control,
        parse_server_control,
    };

    #[test]
    fn private_config_refusal_round_trip_is_closed_and_values_free() {
        for reason in [
            PrivateConfigRefusalReason::CleanupWatermark,
            PrivateConfigRefusalReason::ConfigCountBound,
            PrivateConfigRefusalReason::JournalIoBeforePersistence,
        ] {
            let refusal = PrivateConfigRefused {
                sandbox_owner_id: "owner".into(),
                connection_epoch: 1,
                sandbox_id: "sandbox".into(),
                generation: 2,
                config_id: "config".into(),
                refusal_token: "install-token".into(),
                reason,
            };
            let wire =
                encode_daemon_control(&DaemonControlMessage::PrivateConfigRefused(refusal.clone()))
                    .unwrap();
            let DaemonControlMessage::PrivateConfigRefused(parsed) =
                parse_daemon_control(&wire).unwrap()
            else {
                panic!("expected refusal")
            };
            assert_eq!(parsed, refusal);
            for extra in [
                serde_json::json!({"env":[["SECRET","private"]]}),
                serde_json::json!({"path":"private"}),
                serde_json::json!({"digest":"private"}),
                serde_json::json!({"reason":"private"}),
                serde_json::json!({"connectionEpoch":0}),
            ] {
                let mut value: serde_json::Value = serde_json::from_str(&wire).unwrap();
                value
                    .as_object_mut()
                    .unwrap()
                    .extend(extra.as_object().unwrap().clone());
                assert!(parse_daemon_control(&value.to_string()).is_err());
            }
        }
    }

    #[test]
    fn frozen_private_config_and_pruned_frames_match_the_typescript_peer() {
        let cases: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../fixtures/control_private_config.json")).unwrap();
        for case in cases {
            let wire = case["frame"].to_string();
            let encoded = if case["direction"] == "server" {
                encode_server_control(&parse_server_control(&wire).unwrap()).unwrap()
            } else {
                encode_daemon_control(&parse_daemon_control(&wire).unwrap()).unwrap()
            };
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&encoded).unwrap(),
                case["frame"]
            );
        }
    }

    #[test]
    fn private_config_frames_are_strict_bounded_and_redacted() {
        let install = PrivateConfigInstall {
            sandbox_owner_id: "owner".into(),
            refusal_token: Some("install-token".into()),
            connection_epoch: 1,
            server: "wss://server/ws/sandbox-host".into(),
            host_owner_id: "owner".into(),
            host_id: "host".into(),
            sandbox_id: "sandbox".into(),
            generation: 1,
            config: PrivateConfigRef {
                config_id: "config".into(),
                binding_scheme: "hmac-sha256-v1".into(),
                binding_key_id: "d".repeat(32),
                binding_mac: "c".repeat(64),
            },
            env: vec![("K".into(), "private-config-wire-sentinel".into())],
        };
        let frame = ServerControlMessage::PrivateConfigInstall(install.clone());
        assert!(!format!("{frame:?}").contains(&install.env[0].1));
        assert!(!format!("{frame:?}").contains(&install.config.binding_mac));
        let wire = encode_server_control(&frame).unwrap();
        assert!(matches!(
            parse_server_control(&wire).unwrap(),
            ServerControlMessage::PrivateConfigInstall(_)
        ));
        for patch in [
            serde_json::json!({"env":[["K", "private-config-wire-sentinel"], ["K", "duplicate"]]}),
            serde_json::json!({"env":[["K", "x".repeat(4097)]]}),
            serde_json::json!({"env":[["HOME", "private-config-wire-sentinel"]]}),
            serde_json::json!({"env":[["SHELL", "private-config-wire-sentinel"]]}),
            serde_json::json!({"env":[["TERM", "private-config-wire-sentinel"]]}),
            serde_json::json!({"generation":0}),
            serde_json::json!({"connectionEpoch":0}),
            serde_json::json!({"extra":"private-config-wire-sentinel"}),
            serde_json::json!({"env":[["K", {"bad":"private-config-wire-sentinel"}]]}),
        ] {
            let mut value: serde_json::Value = serde_json::from_str(&wire).unwrap();
            value
                .as_object_mut()
                .unwrap()
                .extend(patch.as_object().unwrap().clone());
            let error = parse_server_control(&value.to_string()).unwrap_err();
            assert!(!format!("{error:#}").contains(&install.env[0].1));
        }
        let ack = DaemonControlMessage::PrivateConfigAck(PrivateConfigAck {
            sandbox_owner_id: "owner".into(),
            connection_epoch: 1,
            sandbox_id: install.sandbox_id,
            generation: 1,
            config: install.config,
        });
        let wire = encode_daemon_control(&ack).unwrap();
        assert!(!wire.contains("checksum"));
        assert!(matches!(
            parse_daemon_control(&wire).unwrap(),
            DaemonControlMessage::PrivateConfigAck(_)
        ));
        assert!(parse_daemon_control(&wire.replace("\"configId\"", "\"checksum\"")).is_err());
    }
}

/// Durable private-config/receipt/lease identity before any workload Effect.
/// Host custody confers no creator authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkloadBindingV11 {
    pub server: String,
    pub host_owner_id: String,
    pub host_id: String,
    pub sandbox_owner_id: String,
    pub sandbox_id: String,
    pub generation: u32,
}
impl WorkloadBindingV11 {
    pub fn transport(&self) -> crate::TransportBindingV11 {
        crate::TransportBindingV11 {
            server: self.server.clone(),
            host_owner_id: self.host_owner_id.clone(),
            host_id: self.host_id.clone(),
        }
    }
    pub fn is_valid(&self) -> bool {
        crate::TransportBindingV11 {
            server: self.server.clone(),
            host_owner_id: self.host_owner_id.clone(),
            host_id: self.host_id.clone(),
        }
        .is_valid()
            && crate::valid_terminal_id(&self.sandbox_owner_id)
            && crate::valid_terminal_id(&self.sandbox_id)
            && self.generation > 0
            && self.generation <= i32::MAX as u32
    }
}
