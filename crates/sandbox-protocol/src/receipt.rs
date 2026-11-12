//! Single wire/storage bound manifest, also imported by the TypeScript peer.
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptLimits {
    pub body_hash_bytes: usize,
    pub idempotency_key_bytes: usize,
    pub identity_bytes: usize,
    pub server_bytes: usize,
    pub receipt_bytes: usize,
    pub result_bytes: usize,
    pub error_bytes: usize,
    pub guest_path_bytes: usize,
    pub guest_id_max: u32,
    pub kinds: Vec<String>,
}
pub static RECEIPT_LIMITS: LazyLock<ReceiptLimits> = LazyLock::new(|| {
    serde_json::from_str(include_str!(
        "../../../packages/config/src/sandbox-receipt-limits.json"
    ))
    .expect("receipt bound manifest")
});
pub fn canonical_body_hash(value: &str) -> bool {
    value.len() == RECEIPT_LIMITS.body_hash_bytes
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn valid_receipt_fields(hash: &str, key: &str, kind: &str) -> bool {
    canonical_body_hash(hash)
        && !key.is_empty()
        && key.len() <= RECEIPT_LIMITS.idempotency_key_bytes
        && RECEIPT_LIMITS.kinds.iter().any(|allowed| allowed == kind)
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptConfirmation {
    pub sandbox_owner_id: String,
    pub operation_id: String,
    pub sandbox_id: String,
    pub generation: u64,
    pub attempt: u64,
    pub body_hash: String,
    pub idempotency_key: String,
    pub kind: String,
    /// The server durably settled this predecessor after a proven cleanup of
    /// the same sandbox on this host. Ordinary confirmations omit this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_generation: Option<u64>,
    /// Only with the negotiated `commandRetire`: the server durably
    /// recorded this exact `command.run` receipt as UNKNOWN (its row stays
    /// UNKNOWN). The host retires the receipt once it proves the command can
    /// no longer run (VM stopped/absent or guest rebooted); this is never a
    /// settlement of the outcome.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub retire_command: bool,
}

/// Identity-only acknowledgement of a pruned report, never a result settlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrunedReceiptAck {
    pub sandbox_owner_id: String,
    pub connection_epoch: u64,
    pub operation_id: String,
    pub sandbox_id: String,
    pub generation: u64,
    pub attempt: u64,
    pub idempotency_key: String,
    pub kind: String,
}
impl PrunedReceiptAck {
    pub fn is_valid(&self) -> bool {
        crate::valid_terminal_id(&self.sandbox_owner_id)
            && self.connection_epoch > 0
            && self.connection_epoch <= i32::MAX as u64
            && crate::valid_terminal_id(&self.operation_id)
            && crate::valid_terminal_id(&self.sandbox_id)
            && self.generation > 0
            && self.generation <= i32::MAX as u64
            && self.attempt > 0
            && self.attempt <= i32::MAX as u64
            && !self.idempotency_key.is_empty()
            && self.idempotency_key.len() <= RECEIPT_LIMITS.idempotency_key_bytes
            && RECEIPT_LIMITS.kinds.contains(&self.kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ServerControlMessage, encode_server_control, parse_server_control};

    #[test]
    fn pruned_ack_round_trips_without_any_digest_and_rejects_invalid_identities() {
        let ack = PrunedReceiptAck {
            sandbox_owner_id: "owner".into(),
            connection_epoch: 1,
            operation_id: "op".into(),
            sandbox_id: "sbx".into(),
            generation: 2,
            attempt: 1,
            idempotency_key: "key".into(),
            kind: "command.run".into(),
        };
        let wire = encode_server_control(&ServerControlMessage::ReceiptPrunedAck(ack)).unwrap();
        assert!(!wire.contains("Hash"));
        assert!(!wire.contains("digest"));
        assert!(matches!(
            parse_server_control(&wire).unwrap(),
            ServerControlMessage::ReceiptPrunedAck(_)
        ));
        let mut value: serde_json::Value = serde_json::from_str(&wire).unwrap();
        for field in ["connectionEpoch", "generation", "attempt"] {
            let mut wrong = value.clone();
            wrong[field] = serde_json::json!(0);
            assert!(parse_server_control(&wrong.to_string()).is_err(), "{field}");
        }
        for field in [
            "sandboxOwnerId",
            "operationId",
            "sandboxId",
            "idempotencyKey",
            "kind",
        ] {
            let mut wrong = value.clone();
            wrong[field] = serde_json::json!("");
            assert!(parse_server_control(&wrong.to_string()).is_err(), "{field}");
        }
        value["bodyHash"] = serde_json::json!("a".repeat(64));
        assert!(parse_server_control(&value.to_string()).is_err());
    }
}
