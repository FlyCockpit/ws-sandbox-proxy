use sandbox_protocol::{
    DaemonControlMessage, ServerControlMessage, StreamBinaryMetadata, parse_daemon_control,
    parse_server_control,
};

fn fixture(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name);
    std::fs::read_to_string(path).expect("read fixture")
}

#[test]
fn hello_daemon_fixture_round_trips() {
    let raw = fixture("control_hello_daemon.json");
    let parsed = parse_daemon_control(&raw).expect("parse daemon hello");
    match parsed {
        DaemonControlMessage::Hello { id, daemon, .. } => {
            assert_eq!(id, "hello-fixture-1");
            assert_eq!(daemon.host_id, "host-fixture");
            assert!(daemon.capabilities.egress_policy);
            assert_eq!(daemon.capabilities.host_managed_sandbox_ceiling, 250);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn hello_ok_server_fixture_round_trips() {
    let raw = fixture("control_hello_ok_server.json");
    let parsed = parse_server_control(&raw).expect("parse server hello.ok");
    match parsed {
        ServerControlMessage::HelloOk {
            protocol_version,
            capabilities,
            ..
        } => {
            assert_eq!(protocol_version, "1.0");
            assert_eq!(capabilities.stream_window_chunks, 4);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn stream_metadata_fixture_deserializes() {
    let raw = fixture("stream_binary_metadata.json");
    let metadata: StreamBinaryMetadata =
        serde_json::from_str(&raw).expect("deserialize stream metadata");
    assert_eq!(metadata.stream_id, "stream-fixture-1");
    assert_eq!(metadata.sequence, 2);
    assert_eq!(metadata.generation, 1);
    assert_eq!(metadata.attempt, 1);
}

#[test]
fn operation_progress_fixture_round_trips() {
    let raw = fixture("control_operation_progress.json");
    let parsed = parse_daemon_control(&raw).expect("parse progress");
    match parsed {
        DaemonControlMessage::OperationProgress {
            operation_id,
            sandbox_id,
            generation,
            attempt,
            state,
            ..
        } => {
            assert_eq!(operation_id, "op-fixture-1");
            assert_eq!(sandbox_id, "sbx-fixture-1");
            assert_eq!(generation, 3);
            assert_eq!(attempt, 2);
            assert_eq!(state, sandbox_protocol::OperationState::Running);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn operation_result_fixture_round_trips() {
    let raw = fixture("control_operation_result.json");
    let parsed = parse_daemon_control(&raw).expect("parse result");
    match parsed {
        DaemonControlMessage::OperationResult {
            operation_id,
            sandbox_id,
            generation,
            attempt,
            state,
            ..
        } => {
            assert_eq!(operation_id, "op-fixture-1");
            assert_eq!(sandbox_id, "sbx-fixture-1");
            assert_eq!(generation, 3);
            assert_eq!(attempt, 2);
            assert_eq!(state, sandbox_protocol::OperationState::Succeeded);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn absent_cleanup_result_fixtures_carry_the_host_end_state() {
    use sandbox_protocol::{OperationState, SandboxLifecycleState};
    let cases: Vec<serde_json::Value> =
        serde_json::from_str(&fixture("control_absent_cleanup_results.json")).unwrap();
    for case in cases {
        let frame = &case["frame"];
        let parsed = parse_daemon_control(&frame.to_string()).unwrap();
        assert_eq!(daemon_value(&parsed), *frame);
        let DaemonControlMessage::OperationResult { state, result, .. } = parsed else {
            panic!("expected result");
        };
        assert_eq!(state, OperationState::Succeeded);
        let end_state: SandboxLifecycleState =
            serde_json::from_value(result.unwrap()["state"].clone()).unwrap();
        assert_eq!(
            end_state,
            if case["kind"] == "sandbox.stop" {
                SandboxLifecycleState::Absent
            } else {
                SandboxLifecycleState::Deleted
            }
        );
    }
}

#[test]
fn operation_cancel_fixture_round_trips() {
    let raw = fixture("control_operation_cancel.json");
    let parsed = parse_server_control(&raw).expect("parse cancel");
    match parsed {
        ServerControlMessage::OperationCancel {
            operation_id,
            generation,
            attempt,
            ..
        } => {
            assert_eq!(operation_id, "op-fixture-1");
            assert_eq!(generation, 3);
            assert_eq!(attempt, 2);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn c15_operation_dispatch_script_fixture_round_trips() {
    let raw = fixture("control_operation_dispatch_script.json");
    let parsed = parse_server_control(&raw).expect("dispatch");
    match parsed {
        ServerControlMessage::OperationDispatch(ref dispatch) => {
            assert!(dispatch.argv.is_none());
            let script = dispatch.script.as_deref().unwrap();
            assert!(script.len() > 512);
            assert!(script.contains("世界"));
            assert!(script.ends_with("  \n"));
            let encoded = serde_json::to_value(&parsed).expect("encode");
            let original: serde_json::Value = serde_json::from_str(&raw).unwrap();
            assert_eq!(encoded["script"], original["script"]);
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn operation_dispatch_fixture_carries_attempt_stdin_start() {
    let parsed =
        parse_server_control(&fixture("control_operation_dispatch.json")).expect("dispatch");
    match parsed {
        ServerControlMessage::OperationDispatch(dispatch) => {
            assert_eq!(dispatch.attempt, 2);
            assert_eq!(dispatch.stdin_sequence, Some(7));
        }
        other => panic!("unexpected message: {other:?}"),
    }
}

#[test]
fn v3_receipt_reconciliation_fixtures() {
    for file in [
        "control_operation_receipt.json",
        "control_reconcile_complete.json",
    ] {
        let raw = fixture(file);
        let parsed = parse_daemon_control(&raw).unwrap();
        assert_eq!(
            daemon_value(&parsed),
            serde_json::from_str::<serde_json::Value>(&raw).unwrap()
        );
    }
    assert!(matches!(
        parse_server_control(&fixture("control_receipt_ack.json")).unwrap(),
        ServerControlMessage::ReceiptAck { .. }
    ));
    for name in [
        "control_receipt_confirmed.json",
        "control_receipt_settled.json",
    ] {
        let raw = fixture(name);
        let ServerControlMessage::ReceiptConfirmed(confirmed) = parse_server_control(&raw).unwrap()
        else {
            panic!("expected receipt confirmation");
        };
        let mut expected: serde_json::Value = serde_json::from_str(&raw).unwrap();
        expected.as_object_mut().unwrap().remove("type");
        assert_eq!(serde_json::to_value(confirmed).unwrap(), expected);
    }
}
#[test]
fn paired_receipt_field_and_total_bounds() {
    let template: serde_json::Value =
        serde_json::from_str(&fixture("control_operation_receipt.json")).unwrap();
    let cases: Vec<serde_json::Value> =
        serde_json::from_str(&fixture("receipt_bound_cases.json")).unwrap();
    for case in cases {
        let mut value = template.clone();
        value[case["field"].as_str().unwrap()] = case["value"].clone();
        assert_eq!(
            parse_daemon_control(&value.to_string()).is_ok(),
            case["valid"].as_bool().unwrap(),
            "{case}"
        );
    }
    let mut value = template;
    value["result"] =
        serde_json::json!({"data": "x".repeat(sandbox_protocol::RECEIPT_LIMITS.result_bytes)});
    assert!(parse_daemon_control(&value.to_string()).is_err());
    value["result"] = serde_json::json!({});
    let oversized = format!(
        "{}{}",
        value,
        " ".repeat(sandbox_protocol::RECEIPT_LIMITS.receipt_bytes)
    );
    assert!(parse_daemon_control(&oversized).is_err());
    assert_eq!(
        sandbox_protocol::RECEIPT_LIMITS.kinds,
        sandbox_protocol::ALLOWED_HOST_DISPATCH_KINDS
    );
}

#[test]
fn template_observation_messages_round_trip_with_typescript() {
    let fixture: serde_json::Value =
        serde_json::from_str(&fixture("control_template_observations.json")).unwrap();
    for message in fixture["server"].as_array().unwrap() {
        let parsed = parse_server_control(&message.to_string()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), *message);
    }
    for message in fixture["daemon"].as_array().unwrap() {
        let parsed = parse_daemon_control(&message.to_string()).unwrap();
        assert_eq!(daemon_value(&parsed), *message);
    }
}

#[test]
fn command_output_binary_fixture_matches_typescript() {
    let fixture: serde_json::Value = serde_json::from_str(&fixture("command_output.json")).unwrap();
    let metadata: StreamBinaryMetadata =
        serde_json::from_value(fixture["metadata"].clone()).unwrap();
    let encoded = sandbox_protocol::encode_binary_frame(&metadata, &[0xe2, 0x82]).unwrap();
    let hex: String = encoded.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(hex, fixture["frameHex"].as_str().unwrap());
    let (parsed, body) = sandbox_protocol::parse_binary_frame(&encoded).unwrap();
    assert_eq!(parsed.offset, Some(9));
    assert_eq!(parsed.gap_start, Some(2));
    assert_eq!(body, [0xe2, 0x82]);
}

#[test]
fn inventory_census_fixtures_round_trip_with_typescript() {
    let raw = fixture("control_sandbox_inventory.json");
    let parsed = parse_daemon_control(&raw).unwrap();
    assert_eq!(
        daemon_value(&parsed),
        serde_json::from_str::<serde_json::Value>(&raw).unwrap()
    );
    let DaemonControlMessage::SandboxInventory { entries, .. } = parsed else {
        panic!("expected inventory");
    };
    assert_eq!(entries.len(), 2);
    assert!(entries[0].lease.as_ref().unwrap().expiry_complete);
    let ack = fixture("control_inventory_ack.json");
    assert!(matches!(
        parse_server_control(&ack).unwrap(),
        ServerControlMessage::InventoryAck {
            page: 0,
            entry_results: None
        }
    ));
    let mut unordered: serde_json::Value = serde_json::from_str(&raw).unwrap();
    unordered["entries"].as_array_mut().unwrap().reverse();
    assert!(parse_daemon_control(&unordered.to_string()).is_err());
}

#[test]
fn expiry_status_fixture_round_trips_and_rejects_failure_on_settled_expiry() {
    let raw = fixture("control_sandbox_expiry_status.json");
    let parsed = parse_daemon_control(&raw).unwrap();
    assert_eq!(
        daemon_value(&parsed),
        serde_json::from_str::<serde_json::Value>(&raw).unwrap()
    );
    let DaemonControlMessage::SandboxExpiryStatus { entries, .. } = parsed else {
        panic!("expected expiry status");
    };
    let lease = entries[0].lease.as_ref().unwrap();
    assert!(lease.timer_expired);
    assert_eq!(lease.expiry_failure.as_ref().unwrap().attempts, 3);
    let mut settled: serde_json::Value = serde_json::from_str(&raw).unwrap();
    settled["entries"][0]["lease"]["expiryComplete"] = true.into();
    assert!(parse_daemon_control(&settled.to_string()).is_err());
    let mut empty: serde_json::Value = serde_json::from_str(&raw).unwrap();
    empty["entries"] = serde_json::json!([]);
    assert!(parse_daemon_control(&empty.to_string()).is_err());
}

#[test]
fn terminal_frames_round_trip_with_typescript() {
    let fixture: serde_json::Value =
        serde_json::from_str(&fixture("control_terminal.json")).unwrap();
    for message in fixture["server"].as_array().unwrap() {
        let parsed = parse_server_control(&message.to_string()).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), *message);
        let encoded = sandbox_protocol::encode_server_control(&parsed).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&encoded).unwrap(),
            *message
        );
    }
    for message in fixture["daemon"].as_array().unwrap() {
        let parsed = parse_daemon_control(&message.to_string()).unwrap();
        assert_eq!(daemon_value(&parsed), *message);
    }
    for message in fixture["rejected"]["server"].as_array().unwrap() {
        assert!(
            parse_server_control(&message.to_string()).is_err(),
            "{message}"
        );
    }
    for message in fixture["rejected"]["daemon"].as_array().unwrap() {
        assert!(
            parse_daemon_control(&message.to_string()).is_err(),
            "{message}"
        );
    }
    let metadata: sandbox_protocol::TerminalDataMetadata =
        serde_json::from_value(fixture["dataFrame"]["metadata"].clone()).unwrap();
    let body = [0x6c, 0x73, 0x0d];
    let encoded = sandbox_protocol::encode_terminal_frame(&metadata, &body).unwrap();
    let meta_len = u32::from_be_bytes(encoded[..4].try_into().unwrap()) as usize;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&encoded[4..4 + meta_len]).unwrap(),
        fixture["dataFrame"]["metadata"]
    );
    let hex: String = encoded[4 + meta_len..]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(hex, fixture["dataFrame"]["bodyHex"].as_str().unwrap());
    let (parsed, parsed_body) = sandbox_protocol::parse_terminal_frame(&encoded)
        .unwrap()
        .unwrap();
    assert_eq!(parsed, metadata);
    assert_eq!(parsed_body, body);
}

#[test]
fn admission_availability_frozen_fixtures_and_bounds() {
    let cases: Vec<serde_json::Value> =
        serde_json::from_str(&fixture("control_admission_availability.json")).expect("fixtures");
    for case in &cases {
        let frame = &case["frame"];
        let encoded = if case["direction"] == "daemon" {
            sandbox_protocol::WireCodes::CURRENT
                .encode(
                    &parse_daemon_control(&frame.to_string()).expect("daemon"),
                    None,
                )
                .expect("encode")
                .text
        } else {
            sandbox_protocol::encode_server_control(
                &parse_server_control(&frame.to_string()).expect("server"),
            )
            .expect("encode")
        };
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&encoded).expect("json"),
            *frame
        );
    }
    let request = &cases[1]["frame"];
    for (key, value) in [
        ("connectionEpoch", serde_json::json!(0)),
        ("page", serde_json::json!(100)),
        ("requestId", serde_json::json!("")),
    ] {
        let mut bad = request.clone();
        bad[key] = value;
        assert!(parse_server_control(&bad.to_string()).is_err(), "{key}");
    }
    let mut oversized = request.clone();
    oversized["bindings"] = serde_json::json!(vec![request["bindings"][0].clone(); 101]);
    assert!(parse_server_control(&oversized.to_string()).is_err());
    let mut duplicate = cases[3]["frame"].clone();
    duplicate["entries"] = serde_json::json!(vec![duplicate["entries"][0].clone(); 2]);
    assert!(parse_daemon_control(&duplicate.to_string()).is_err());
}

fn daemon_value(frame: &DaemonControlMessage) -> serde_json::Value {
    let text = sandbox_protocol::WireCodes::negotiated("1.0")
        .encode(frame, None)
        .unwrap()
        .text;
    serde_json::from_str(&text).unwrap()
}

/// Required host lease ceiling (finite or null for unlimited) and live policy,
/// parsed from the same fixture as the TypeScript peer.
#[test]
fn host_lease_policy_fixtures_match_typescript() {
    let cases: serde_json::Value =
        serde_json::from_str(&fixture("control_host_lease_policy.json")).expect("fixture");
    let hello: serde_json::Value =
        serde_json::from_str(&fixture("control_hello_daemon.json")).expect("hello");
    for case in cases["helloCeilings"].as_array().expect("hello cases") {
        let mut frame = hello.clone();
        let capabilities = frame["daemon"]["capabilities"]
            .as_object_mut()
            .expect("capabilities");
        if case["absent"] == true {
            capabilities.remove("maxLeaseMs");
        } else {
            capabilities.insert("maxLeaseMs".into(), case["maxLeaseMs"].clone());
        }
        let parsed = parse_daemon_control(&frame.to_string()).expect("hello with ceiling");
        let DaemonControlMessage::Hello { daemon, .. } = parsed else {
            panic!("not a hello");
        };
        assert_eq!(daemon.capabilities.max_lease_ms, case["stored"].as_u64());
        // The daemon always writes the field, `null` included.
        let encoded = serde_json::to_value(&daemon.capabilities).expect("encode capabilities");
        assert_eq!(encoded["maxLeaseMs"], case["stored"]);
    }
    for invalid in cases["invalidHelloCeilings"].as_array().expect("invalid") {
        let mut frame = hello.clone();
        frame["daemon"]["capabilities"]["maxLeaseMs"] = invalid.clone();
        assert!(
            parse_daemon_control(&frame.to_string()).is_err(),
            "{invalid}"
        );
    }
    for report in cases["reports"].as_array().expect("reports") {
        let parsed = parse_daemon_control(&report.to_string()).expect("report");
        let DaemonControlMessage::HostLeasePolicy(policy) = parsed else {
            panic!("not a lease report");
        };
        assert_eq!(policy.max_lease_ms, report["maxLeaseMs"].as_u64());
    }
    for report in cases["invalidReports"].as_array().expect("invalid reports") {
        let refused = parse_daemon_control(&report.to_string()).is_err()
            || !matches!(
                parse_daemon_control(&report.to_string()),
                Ok(DaemonControlMessage::HostLeasePolicy(ref p)) if p.is_valid()
            );
        assert!(refused, "{report}");
    }
}

/// The dispatch lease, including the additive `shortenOnly` flag (only on the
/// server's lease-policy system renewals), parsed like the TypeScript peer.
#[test]
fn lease_wire_cases_match_typescript() {
    let cases: serde_json::Value =
        serde_json::from_str(&fixture("lease_wire_cases.json")).expect("fixture");
    for case in cases["valid"].as_array().expect("valid") {
        let lease: sandbox_protocol::HostLease =
            serde_json::from_value(case.clone()).expect("valid lease");
        assert_eq!(lease.shorten_only, case["shortenOnly"] == true);
        // Round-trips byte-identically: the flag is omitted when false.
        assert_eq!(serde_json::to_value(&lease).unwrap(), *case);
    }
    for case in cases["invalid"].as_array().expect("invalid") {
        assert!(serde_json::from_value::<sandbox_protocol::HostLease>(case.clone()).is_err());
    }
}

#[test]
fn operation_adopt_frames_match_the_shared_fixture() {
    let fixture: serde_json::Value =
        serde_json::from_str(&fixture("control_operation_adopt.json")).unwrap();
    for frame in fixture["daemon"].as_array().unwrap() {
        let parsed = parse_daemon_control(&frame.to_string()).unwrap();
        assert!(matches!(
            parsed,
            DaemonControlMessage::OperationAdopt { .. }
        ));
        assert_eq!(&daemon_value(&parsed), frame);
    }
    for frame in fixture["server"].as_array().unwrap() {
        let parsed = parse_server_control(&frame.to_string()).unwrap();
        assert!(matches!(
            parsed,
            ServerControlMessage::OperationAdoptResult { .. }
        ));
        assert_eq!(&serde_json::to_value(&parsed).unwrap(), frame);
    }
    let template = fixture["daemon"][0].clone();
    for patch in fixture["rejectedDaemon"].as_array().unwrap() {
        let mut frame = template.clone();
        for (key, value) in patch.as_object().unwrap() {
            frame[key] = value.clone();
        }
        assert!(parse_daemon_control(&frame.to_string()).is_err(), "{patch}");
    }
    for frame in fixture["rejectedServer"].as_array().unwrap() {
        assert!(parse_server_control(&frame.to_string()).is_err(), "{frame}");
    }
}

#[test]
fn dispatch_audit_frames_match_the_shared_fixture() {
    let fixture: serde_json::Value =
        serde_json::from_str(&fixture("control_dispatch_audit.json")).unwrap();
    for frame in fixture["daemon"].as_array().unwrap() {
        let parsed = parse_daemon_control(&frame.to_string()).unwrap();
        assert_eq!(&daemon_value(&parsed), frame);
    }
    for frame in fixture["server"].as_array().unwrap() {
        let parsed = parse_server_control(&frame.to_string()).unwrap();
        assert_eq!(&serde_json::to_value(&parsed).unwrap(), frame);
    }
    for frame in fixture["rejectedDaemon"].as_array().unwrap() {
        assert!(parse_daemon_control(&frame.to_string()).is_err(), "{frame}");
    }
    for frame in fixture["rejectedServer"].as_array().unwrap() {
        assert!(parse_server_control(&frame.to_string()).is_err(), "{frame}");
    }
}

#[test]
fn image_frames_match_the_shared_fixture() {
    let fixture: serde_json::Value = serde_json::from_str(&fixture("control_image.json")).unwrap();
    for frame in fixture["daemon"].as_array().unwrap() {
        let parsed =
            parse_daemon_control(&frame.to_string()).unwrap_or_else(|e| panic!("{frame}: {e}"));
        assert_eq!(&daemon_value(&parsed), frame);
    }
    for frame in fixture["server"].as_array().unwrap() {
        let parsed =
            parse_server_control(&frame.to_string()).unwrap_or_else(|e| panic!("{frame}: {e}"));
        assert_eq!(&serde_json::to_value(&parsed).unwrap(), frame);
        // Grants are redacted in Debug output.
        let debug = format!("{parsed:?}");
        assert!(
            !debug.contains("AAAAAAAA") && !debug.contains("BBBBBBBB"),
            "{debug}"
        );
    }
    for frame in fixture["rejectedDaemon"].as_array().unwrap() {
        assert!(parse_daemon_control(&frame.to_string()).is_err(), "{frame}");
    }
    for frame in fixture["rejectedServer"].as_array().unwrap() {
        assert!(parse_server_control(&frame.to_string()).is_err(), "{frame}");
    }
}

#[test]
fn image_fields_on_existing_frames_are_additive_and_omitted_when_absent() {
    // A hello without the image capability is byte-identical to a pre-image hello.
    let caps = sandbox_protocol::DaemonCapabilities::default();
    let value = serde_json::to_value(&caps).unwrap();
    assert!(value.get("image").is_none());
    let lease = sandbox_protocol::HostLease::for_test();
    let value = serde_json::to_value(&lease).unwrap();
    assert!(value.get("fromReadyMs").is_none());
    // An image plan only rides on a create; a capture body only on a capture.
    let fp = format!("sha256:{}", "a".repeat(64));
    let dispatch = |kind: &str, extra: serde_json::Value| {
        let mut value = serde_json::json!({
            "type": "operation.dispatch",
            "sandboxOwnerId": "owner", "operationId": "op", "sandboxId": "sbx",
            "idempotencyKey": "k", "kind": kind, "generation": 1, "attempt": 1,
        });
        for (k, v) in extra.as_object().unwrap() {
            value[k] = v.clone();
        }
        value.to_string()
    };
    let image = serde_json::json!({"image": {"fingerprint": fp, "sizeBytes": 10, "format": "unified", "source": "fetch"}});
    assert!(parse_server_control(&dispatch("sandbox.create", image.clone())).is_ok());
    assert!(parse_server_control(&dispatch("command.run", image)).is_err());
    let capture = serde_json::json!({"capture": {"scrubPaths": ["/home/user/secret.txt"], "stopped": false, "upload": false}});
    assert!(parse_server_control(&dispatch("sandbox.capture", capture.clone())).is_ok());
    assert!(parse_server_control(&dispatch("sandbox.capture", serde_json::json!({}))).is_err());
    assert!(parse_server_control(&dispatch("sandbox.create", capture)).is_err());
    let bad = serde_json::json!({"capture": {"scrubPaths": ["../etc"], "stopped": false, "upload": false}});
    assert!(parse_server_control(&dispatch("sandbox.capture", bad)).is_err());
    // Snapshot, restore and fork stay fail-closed.
    for kind in ["snapshot.create", "snapshot.restore", "sandbox.fork"] {
        assert_eq!(
            sandbox_protocol::classify_dispatch_kind(kind),
            sandbox_protocol::DispatchKindClass::UnsupportedCapability
        );
    }
    assert_eq!(
        sandbox_protocol::classify_dispatch_kind("sandbox.capture"),
        sandbox_protocol::DispatchKindClass::Allowed
    );
}

#[test]
fn credential_frames_match_the_shared_fixture() {
    let fixture: serde_json::Value =
        serde_json::from_str(&fixture("control_credentials.json")).unwrap();
    for frame in fixture["daemon"].as_array().unwrap() {
        let parsed =
            parse_daemon_control(&frame.to_string()).unwrap_or_else(|e| panic!("{frame}: {e}"));
        assert_eq!(&daemon_value(&parsed), frame);
        let debug = format!("{parsed:?}");
        assert!(!debug.contains("U0VOVElORUw"), "{debug}");
    }
    for frame in fixture["server"].as_array().unwrap() {
        let parsed =
            parse_server_control(&frame.to_string()).unwrap_or_else(|e| panic!("{frame}: {e}"));
        assert_eq!(&serde_json::to_value(&parsed).unwrap(), frame);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                &sandbox_protocol::encode_server_control(&parsed).unwrap()
            )
            .unwrap(),
            *frame
        );
        // Bundle chunks carry plaintext: never in Debug output.
        let debug = format!("{parsed:?}");
        assert!(!debug.contains("U0VOVElORUw"), "{debug}");
    }
    for frame in fixture["rejectedDaemon"].as_array().unwrap() {
        assert!(parse_daemon_control(&frame.to_string()).is_err(), "{frame}");
    }
    for frame in fixture["rejectedServer"].as_array().unwrap() {
        assert!(parse_server_control(&frame.to_string()).is_err(), "{frame}");
    }
}

#[test]
fn credential_fields_on_existing_frames_are_additive_and_kind_bound() {
    let caps = sandbox_protocol::DaemonCapabilities::default();
    assert!(
        serde_json::to_value(&caps)
            .unwrap()
            .get("credentials")
            .is_none()
    );
    let dispatch = |kind: &str, extra: serde_json::Value| {
        let mut value = serde_json::json!({
            "type": "operation.dispatch",
            "sandboxOwnerId": "owner", "operationId": "op", "sandboxId": "sbx",
            "idempotencyKey": "k", "kind": kind, "generation": 1, "attempt": 1,
        });
        for (k, v) in extra.as_object().unwrap() {
            value[k] = v.clone();
        }
        value.to_string()
    };
    let spec = serde_json::json!({"credentialSpec": {"digest": "a".repeat(64), "bytes": 1024}});
    assert!(parse_server_control(&dispatch("file.get", serde_json::json!({}))).is_ok());
    assert!(parse_server_control(&dispatch("file.get", spec.clone())).is_err());
    let over =
        serde_json::json!({"credentialSpec": {"digest": "a".repeat(64), "bytes": 1_179_649}});
    assert!(parse_server_control(&dispatch("sandbox.capture", over)).is_err());
    let skip = serde_json::json!({"credentialCapture": "skip"});
    assert!(parse_server_control(&dispatch("command.run", skip)).is_err());
    let bad = serde_json::json!({"credentialCapture": "maybe"});
    assert!(parse_server_control(&dispatch("command.run", bad)).is_err());
    // sandbox.capture also needs its capture body; the spec rides beside it.
    let both = serde_json::json!({
        "capture": {"scrubPaths": [], "stopped": true, "upload": false},
        "credentialSpec": {"digest": "a".repeat(64), "bytes": 1024},
    });
    assert!(parse_server_control(&dispatch("sandbox.capture", both)).is_ok());
}

#[test]
fn hello_credential_capability_is_strict() {
    let mut hello: serde_json::Value =
        serde_json::from_str(&fixture("control_hello_daemon.json")).unwrap();
    let caps = serde_json::json!({
        "files": true, "env": true, "proxy": false, "sealedReturn": true,
        "checkpoint": true, "specTransfer": true, "maxBundleBytes": 4_823_129,
        "returnKeyEpoch": 0,
    });
    hello["daemon"]["capabilities"]["credentials"] = caps.clone();
    let parsed = parse_daemon_control(&hello.to_string()).expect("credential hello");
    assert_eq!(daemon_value(&parsed), hello);
    for (key, bad) in [
        ("maxBundleBytes", serde_json::json!(4_823_130)),
        (
            "returnKeyEpoch",
            serde_json::json!(9_007_199_254_740_992u64),
        ),
        ("extra", serde_json::json!(true)),
    ] {
        let mut wrong = hello.clone();
        wrong["daemon"]["capabilities"]["credentials"][key] = bad;
        assert!(parse_daemon_control(&wrong.to_string()).is_err(), "{key}");
    }
}

/// Egress launch policy (relay 1.0, additive): every normalized case of the
/// shared contract fixture round-trips through `EgressPolicy` and a launch
/// dispatch byte-for-byte, and its canonical JSON (the hashed text) matches
/// the TypeScript `canonicalEgressPolicyJson`. Allowlist omits `mode`.
#[test]
fn egress_policy_cases_match_typescript() {
    let cases: serde_json::Value =
        serde_json::from_str(&fixture("egress_policy_cases.json")).expect("fixture");
    let wires: serde_json::Value =
        serde_json::from_str(&fixture("control_host_egress_state.json")).expect("wire");
    for case in cases["normalize"].as_array().expect("normalize") {
        let name = case["name"].as_str().unwrap();
        let policy: sandbox_protocol::EgressPolicy =
            serde_json::from_value(case["wire"].clone()).expect(name);
        let open = case["normalized"]["mode"] == "open";
        assert_eq!(
            policy.mode,
            if open {
                sandbox_protocol::EgressMode::Open
            } else {
                sandbox_protocol::EgressMode::Allowlist
            },
            "{name}"
        );
        assert_eq!(
            serde_json::to_value(&policy).unwrap(),
            case["wire"],
            "{name}"
        );
        assert_eq!(
            policy.canonical_json(),
            case["canonicalJson"].as_str().unwrap(),
            "{name}"
        );
        let mut frame = wires["launchDispatch"].clone();
        frame["egressPolicy"] = case["wire"].clone();
        let parsed = parse_server_control(&frame.to_string()).expect(name);
        let ServerControlMessage::OperationDispatch(ref dispatch) = parsed else {
            panic!("not a dispatch");
        };
        assert_eq!(dispatch.egress_policy.as_ref(), Some(&policy), "{name}");
        let encoded: serde_json::Value = serde_json::from_str(
            &sandbox_protocol::encode_server_control(&parsed).expect("encode"),
        )
        .unwrap();
        assert_eq!(encoded["egressPolicy"], case["wire"], "{name}");
        assert_eq!(encoded.get("mode"), None);
    }
    for case in cases["wireInvalid"].as_array().expect("wireInvalid") {
        assert!(
            serde_json::from_value::<sandbox_protocol::EgressPolicy>(case["wire"].clone()).is_err(),
            "{}",
            case["name"]
        );
        let mut frame = wires["launchDispatch"].clone();
        frame["egressPolicy"] = case["wire"].clone();
        assert!(
            parse_server_control(&frame.to_string()).is_err(),
            "{}",
            case["name"]
        );
    }
}

/// Egress capability (hello), `egressOpen` admission bit and the
/// `host.egress-state` report, parsed and re-encoded from the same fixture as
/// the TypeScript peer, for every capability combination.
#[test]
fn host_egress_state_fixtures_match_typescript() {
    let cases: serde_json::Value =
        serde_json::from_str(&fixture("control_host_egress_state.json")).expect("fixture");
    let hello: serde_json::Value =
        serde_json::from_str(&fixture("control_hello_daemon.json")).expect("hello");
    for case in cases["helloEgress"].as_array().expect("hello cases") {
        let mut frame = hello.clone();
        let capabilities = frame["daemon"]["capabilities"]
            .as_object_mut()
            .expect("capabilities");
        if case["absent"] == true {
            capabilities.remove("egress");
        } else {
            capabilities.insert("egress".into(), case["egress"].clone());
        }
        let parsed = parse_daemon_control(&frame.to_string()).expect("hello with egress");
        let DaemonControlMessage::Hello { ref daemon, .. } = parsed else {
            panic!("not a hello");
        };
        let expected = sandbox_protocol::EgressCapabilitiesV11 {
            open: case["egress"]["open"].as_bool().unwrap(),
            guard: case["egress"]["guard"].as_bool().unwrap(),
        };
        assert_eq!(daemon.capabilities.egress, expected, "{}", case["name"]);
        assert_eq!(daemon_value(&parsed), frame, "{}", case["name"]);
        // The checked 1.0 hello shape accepts it too.
        serde_json::from_value::<sandbox_protocol::capacity_v11::HostHelloV11>(frame)
            .expect("checked hello");
    }
    for invalid in cases["invalidHelloEgress"].as_array().expect("invalid") {
        let mut frame = hello.clone();
        frame["daemon"]["capabilities"]["egress"] = invalid.clone();
        assert!(
            parse_daemon_control(&frame.to_string()).is_err(),
            "{invalid}"
        );
    }
    let admissions: Vec<serde_json::Value> =
        serde_json::from_str(&fixture("control_admission_availability.json")).expect("admission");
    let admission = admissions[0]["frame"].clone();
    assert_eq!(admission["type"], "host.admission");
    let admission_bit = |frame: &DaemonControlMessage| match frame {
        DaemonControlMessage::HostAdmission { egress_open, .. } => *egress_open,
        _ => panic!("not an admission"),
    };
    for case in cases["admissionEgressOpen"]
        .as_array()
        .expect("admission cases")
    {
        let mut frame = admission.clone();
        if case["absent"] != true {
            frame["egressOpen"] = case["egressOpen"].clone();
        }
        let parsed = parse_daemon_control(&frame.to_string()).expect("admission");
        assert_eq!(admission_bit(&parsed), case["stored"] == true);
        assert_eq!(daemon_value(&parsed), frame, "{}", case["name"]);
    }
    for case in cases["admissionEgressOpenNonCanonical"]
        .as_array()
        .expect("noncanonical")
    {
        let mut frame = admission.clone();
        frame["egressOpen"] = case["egressOpen"].clone();
        let parsed = parse_daemon_control(&frame.to_string()).expect("admission");
        assert_eq!(admission_bit(&parsed), case["stored"] == true);
        assert_eq!(daemon_value(&parsed), admission, "{}", case["name"]);
    }
    for invalid in cases["invalidAdmissionEgressOpen"]
        .as_array()
        .expect("invalid")
    {
        let mut frame = admission.clone();
        frame["egressOpen"] = invalid.clone();
        assert!(
            parse_daemon_control(&frame.to_string()).is_err(),
            "{invalid}"
        );
    }
    for report in cases["reports"].as_array().expect("reports") {
        let parsed = parse_daemon_control(&report.to_string()).expect("report");
        let DaemonControlMessage::HostEgressState(ref state) = parsed else {
            panic!("not an egress report");
        };
        assert!(state.is_valid(), "{report}");
        assert_eq!(daemon_value(&parsed), *report);
    }
    for report in cases["invalidReports"].as_array().expect("invalid reports") {
        assert!(
            parse_daemon_control(&report.to_string()).is_err(),
            "{report}"
        );
    }
}

/// E6 `egress.blocklist` frames and the typed egress refusal `reason`, from
/// the same fixture as the TypeScript peer (`egress_blocklist_cases.json`).
#[test]
fn egress_blocklist_and_refusal_reason_fixtures_match_typescript() {
    let cases: serde_json::Value =
        serde_json::from_str(&fixture("egress_blocklist_cases.json")).expect("fixture");
    for frame in cases["frames"]["valid"].as_array().expect("valid frames") {
        let parsed = sandbox_protocol::parse_server_control(&frame.to_string())
            .unwrap_or_else(|err| panic!("{frame}: {err}"));
        let sandbox_protocol::ServerControlMessage::EgressBlocklist(ref list) = parsed else {
            panic!("not an egress.blocklist");
        };
        assert!(list.is_valid());
        let encoded: serde_json::Value =
            serde_json::from_str(&sandbox_protocol::encode_server_control(&parsed).unwrap())
                .unwrap();
        assert_eq!(&encoded, frame);
    }
    for case in cases["frames"]["invalid"]
        .as_array()
        .expect("invalid frames")
    {
        assert!(
            sandbox_protocol::parse_server_control(&case["frame"].to_string()).is_err(),
            "{}",
            case["name"]
        );
    }
    // Encoding refuses an invalid frame too.
    let refused = sandbox_protocol::ServerControlMessage::EgressBlocklist(
        sandbox_protocol::EgressBlocklistV11 {
            configured: true,
            entries: vec![],
            digest: format!("sha256:{}", "0".repeat(64)),
            invalid: false,
        },
    );
    assert!(sandbox_protocol::encode_server_control(&refused).is_err());

    let reasons = &cases["errorReasons"];
    let result_with = |error: &serde_json::Value| {
        let mut frame = reasons["base"].clone();
        let mut error = error.clone();
        error["message"] = serde_json::json!("refused");
        frame["error"] = error;
        frame
    };
    for error in reasons["valid"].as_array().expect("valid reasons") {
        let frame = result_with(error);
        let parsed =
            parse_daemon_control(&frame.to_string()).unwrap_or_else(|err| panic!("{error}: {err}"));
        let DaemonControlMessage::OperationResult {
            error: Some(ref detail),
            ..
        } = parsed
        else {
            panic!("not a failed result");
        };
        assert_eq!(
            detail.reason.map(|r| serde_json::to_value(r).unwrap()),
            error.get("reason").cloned()
        );
        assert_eq!(daemon_value(&parsed), frame, "{error}");
    }
    for error in reasons["invalid"].as_array().expect("invalid reasons") {
        let frame = result_with(error);
        assert!(parse_daemon_control(&frame.to_string()).is_err(), "{error}");
    }
}

#[test]
fn hello_requires_current_safety_capabilities() {
    let hello: serde_json::Value =
        serde_json::from_str(&fixture("control_hello_daemon.json")).unwrap();
    for field in [
        "maxLeaseMs",
        "egress",
        "maxOutputChunkBytes",
        "censusEntryResults",
        "pendingReceipts",
        "expiryStatusResults",
        "observationFence",
        "commandRetire",
    ] {
        let mut missing = hello.clone();
        missing["daemon"]["capabilities"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(
            parse_daemon_control(&missing.to_string()).is_err(),
            "{field}"
        );
    }
}
