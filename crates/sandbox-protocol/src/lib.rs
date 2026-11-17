//! Sandbox host relay protocol: version negotiation, control messages, and
//! binary stream framing shared by the control plane and `wssp` node daemon.

mod host_access;
pub use host_access::*;
mod private_config;
pub use private_config::{
    PRIVATE_CONFIG_MAX_BYTES, PrivateConfigAck, PrivateConfigInstall, PrivateConfigRef,
    PrivateConfigRefusalReason, PrivateConfigRefused, WorkloadBindingV11, valid_key_id,
};
mod journal_key;
pub use journal_key::{JournalKeyInstall, TransportBindingV11};
mod admission;
pub use admission::*;
mod image;
pub use image::*;
mod disk;
pub use disk::*;
mod build;
pub use build::{
    BUILD_CONTEXT_DIR, BUILD_CONTEXT_FILE, BUILD_COPY_DEST_MAX_BYTES, BUILD_COPY_MODE_MAX,
    BUILD_COPY_SRC_MAX, BUILD_COPY_SRC_MAX_BYTES, BuildCopyOwnerV11, BuildCopyV11,
    DispatchBuildV11, RunAsV11, build_context_path, build_id_of_context_path,
    valid_build_copy_dest, valid_build_copy_src, valid_build_id,
};
mod startup;
pub use startup::{
    DispatchStartupV11, STARTUP_COMMAND_MAX_BYTES, STARTUP_CWD_MAX_BYTES,
    STARTUP_READY_TIMEOUT_DEFAULT_MS, STARTUP_READY_TIMEOUT_MAX_MS, STARTUP_READY_TIMEOUT_MIN_MS,
};
mod credentials;
pub use credentials::*;
mod egress;
pub use egress::{
    EGRESS_BLOCKLIST_ENTRY_MAX_LEN, EGRESS_BLOCKLIST_MAX_ENTRIES, EGRESS_GUARD_INSTANCE_ID_MAX_LEN,
    EGRESS_GUARD_REASON_MAX_LEN, EgressBlocklistV11, EgressCapabilitiesV11, EgressMode,
    EgressPolicy, EgressRefusalReason, HostEgressStateV11, egress_blocklist_digest_input,
    valid_egress_guard_instance_id, valid_egress_guard_reason,
};
mod capabilities;
mod tunnel;
pub use tunnel::{
    TUNNEL_MAX_PORTS, TunnelApplyV11, TunnelCapabilityV11, TunnelClearV11, TunnelErrorV11,
    TunnelStateV11, TunnelStatusV11, valid_tunnel_ports, valid_tunnel_server, valid_tunnel_token,
};
mod egress_hints;
pub use egress_hints::{
    EGRESS_REFUSED_MIN_INTERVAL_MS, EGRESS_REFUSED_NAMES_MAX, EgressRefusedV11,
    HINT_DNS_LABEL_MAX_BYTES, HINT_DNS_NAME_MAX_BYTES, valid_hint_dns_name,
};
mod command;
mod command_limits;
mod control;
mod dispatch;
mod env_limits;
mod error;
pub use env_limits::{ENV_LIMITS, EnvLimits, canonical_env_json, env_limits, validate_env};
mod frame;
mod state;
mod terminal;
mod version;
mod vm_size;
pub use vm_size::{
    HostMemoryReserve, VmCapacity, VmSize, VmSizeError, VmSizeLimits, VmSizeOverrides,
    host_memory_budget_from_bytes, host_memory_reserve_bytes, host_vcpu_budget_default,
    vm_live_memory_charge_mi_b, vm_root_charge_gi_b, vm_size_limits,
};

pub use capabilities::{
    DEFAULT_MAX_LEASE_MS, DaemonCapabilities, HostInventorySnapshot, HostLeasePolicyV11,
    HostQuiesceAckV11, HostQuiesceV11, HostTerminalPolicyV11, LEASE_CEILING_MAX_MS,
    LEASE_CEILING_MIN_MS, NegotiatedCapabilities, PolicyReconcilerHealth, RuntimeKind,
    valid_lease_ceiling,
};
pub use command::{
    CommandRunSpec, serialized_command_payload_bytes, validate_command_run_spec,
    validate_command_timeout,
};
pub use command_limits::{COMMAND_LIMITS, command_payload_max_bytes, json_control_max_bytes};
pub use control::DaemonHello;
pub use control::{
    AdoptPhase, AllocationVerdict, DISPATCH_AUDIT_PAGE_MAX, DaemonControlMessage,
    DispatchAuditEntry, DispatchAuditVerdict, HostTerminalPolicyControlV11, OperationDispatch,
    PENDING_RECEIPTS_MAX, ProtocolErrorDetail, ProtocolErrorReason, ReadinessFailureReason,
    ServerControlMessage, dispatch_vm_size, encode_server_control,
    encode_server_control_for_version, parse_daemon_control, parse_daemon_control_for_version,
    parse_server_control, parse_server_control_for_version, valid_pending_receipts,
};
pub use dispatch::{
    ALLOWED_HOST_DISPATCH_KINDS, DispatchKindClass, KEY_FREE_CLEANUP_KINDS,
    RELAY_CONTROL_DISPATCH_KINDS, UNSUPPORTED_HOST_DISPATCH_KINDS, classify_dispatch_kind,
    unsupported_dispatch_error,
};
pub use error::{SandboxErrorCode, WIRE_ERROR_CODE_MAX_BYTES, WireErrorCode};
pub use frame::{
    SANDBOX_BINARY_CHUNK_MAX_BYTES, SANDBOX_LIST_MAX_DEPTH, SANDBOX_LIST_MAX_ENTRIES,
    SANDBOX_OUTPUT_CHUNK_MIN_BYTES, SANDBOX_OUTPUT_CHUNK_OFFER_BYTES, SANDBOX_STREAM_WINDOW_CHUNKS,
    StreamBinaryMetadata, StreamChunkFlags, StreamKind, encode_binary_frame,
    negotiated_output_chunk_bytes, parse_binary_frame, parse_binary_frame_ref,
    valid_output_chunk_bytes,
};
pub use state::{OperationState, SandboxLifecycleState};
pub use terminal::*;
pub use version::{
    SANDBOX_RELAY_PROTOCOL_VERSION, SANDBOX_RELAY_SUBPROTOCOL, known_protocol_version,
};

mod receipt;
pub use receipt::{
    PrunedReceiptAck, RECEIPT_LIMITS, ReceiptConfirmation, ReceiptLimits, canonical_body_hash,
    valid_receipt_fields,
};

mod lease;
pub use lease::{
    ExpiryPolicy, HostLease, LEASE_LIMITS_JSON, LEASE_UNLIMITED_DEADLINE_MS, LeaseAction,
};

mod inventory;
pub use inventory::{
    CensusEntryOutcome, CensusEntryResult, EXPIRY_FAILURE_REASON_MAX_BYTES, ExpiryFailure,
    INVENTORY_MAX_PAGES, INVENTORY_PAGE_MAX_ENTRIES, InventoryEntry, InventoryLease,
    RootObservation, RootState, census_results_match, sanitize_expiry_reason,
    valid_inventory_entries, valid_inventory_page, valid_inventory_sandbox_id,
};

pub mod results;

mod wire_codes;
pub use wire_codes::{SpelledFrame, WireCodes};

/// Strict capacity and storage contract.
pub mod capacity_v11;

#[cfg(test)]
mod sharing_v11_tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    #[derive(Deserialize)]
    struct Case {
        name: String,
        kind: String,
        input: serde_json::Value,
        valid: bool,
    }
    fn decode<T: for<'de> Deserialize<'de> + Serialize>(
        value: &serde_json::Value,
        valid: impl Fn(&T) -> bool,
    ) -> Option<serde_json::Value> {
        let parsed: T = serde_json::from_value(value.clone()).ok()?;
        valid(&parsed).then(|| serde_json::to_value(parsed).unwrap())
    }
    #[test]
    fn typed_binary_targets_are_distinct_strict_and_bounded() {
        let cases: Vec<Case> =
            serde_json::from_str(include_str!("../fixtures/sharing_cases.json")).unwrap();
        for case in cases.into_iter().filter(|c| c.kind == "fence" && c.valid) {
            let fence: TerminalFenceV11 = serde_json::from_value(case.input).unwrap();
            let metadata = TerminalDataMetadataV11 {
                r#type: TerminalDataKind::Data,
                fence,
                sequence: 0,
            };
            let frame = encode_terminal_frame_v11(&metadata, b"x").unwrap();
            assert_eq!(
                parse_terminal_frame_v11(&frame).unwrap(),
                (metadata.clone(), b"x".to_vec())
            );
            assert!(encode_terminal_frame_v11(&metadata, &[]).is_err());
            assert!(
                encode_terminal_frame_v11(&metadata, &vec![0; TERMINAL_DATA_MAX_BYTES + 1])
                    .is_err()
            );
            let mut mixed = serde_json::to_value(&metadata).unwrap();
            mixed["fence"]["target"] =
                serde_json::json!({"kind":"host", "sandboxId":"sandbox-a", "generation":1});
            let bytes = serde_json::to_vec(&mixed).unwrap();
            let mut frame = (bytes.len() as u32).to_be_bytes().to_vec();
            frame.extend(bytes);
            frame.push(b'x');
            assert!(parse_terminal_frame_v11(&frame).is_err());
        }
    }

    #[test]
    fn final_contracts_match_typescript_and_preserve_both_principals() {
        let cases: Vec<Case> =
            serde_json::from_str(include_str!("../fixtures/sharing_cases.json")).unwrap();
        for case in cases {
            let result = match case.kind.as_str() {
                "transport" => {
                    decode::<TransportBindingV11>(&case.input, TransportBindingV11::is_valid)
                }
                "workload" => {
                    decode::<WorkloadBindingV11>(&case.input, WorkloadBindingV11::is_valid)
                }
                "fence" => decode::<TerminalFenceV11>(&case.input, TerminalFenceV11::is_valid),
                "terminal" => {
                    decode::<TerminalControlV11>(&case.input, TerminalControlV11::is_valid)
                }
                "policy" => decode::<HostTerminalPolicyControlV11>(
                    &case.input,
                    HostTerminalPolicyControlV11::is_valid,
                ),
                _ => panic!("unclassified fixture {}", case.kind),
            };
            assert_eq!(result.is_some(), case.valid, "{}", case.name);
            if let Some(output) = result {
                assert_eq!(output, case.input, "{}", case.name);
            }
        }
    }
}
