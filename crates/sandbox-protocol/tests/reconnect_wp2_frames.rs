//! Reconnect WP2 frames (`pendingReceipts`, `expiryStatusResults`,
//! `observationFence`) parity.
//! The shared fixture `reconnect_wp2_frames.json` is also consumed by
//! `apps/server/src/sandbox-relay/protocol-reconnect-wp2.test.ts`.

use sandbox_protocol::{
    CensusEntryOutcome, DaemonCapabilities, DaemonControlMessage, NegotiatedCapabilities,
    PENDING_RECEIPTS_MAX, ServerControlMessage, capacity_v11::DaemonCapabilitiesV11,
    parse_daemon_control, parse_server_control,
};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../fixtures/reconnect_wp2_frames.json")).expect("json")
}

fn hello_caps() -> serde_json::Value {
    serde_json::from_str::<serde_json::Value>(include_str!("../fixtures/control_hello_daemon.json"))
        .unwrap()["daemon"]["capabilities"]
        .clone()
}

fn encode(frame: &DaemonControlMessage) -> serde_json::Value {
    let text = sandbox_protocol::WireCodes::negotiated("1.0")
        .encode(frame, None)
        .unwrap()
        .text;
    serde_json::from_str(&text).unwrap()
}

#[test]
fn safety_capabilities_are_required_and_offered_by_default() {
    let fixture = fixture();
    let parsed: DaemonCapabilitiesV11 = serde_json::from_value(hello_caps()).unwrap();
    assert!(parsed.pending_receipts && parsed.expiry_status_results && parsed.observation_fence);
    let default = serde_json::to_string(&DaemonCapabilities::default()).unwrap();
    for name in fixture["capabilities"].as_array().unwrap() {
        let name = name.as_str().unwrap();
        assert!(default.contains(name), "{name}");
        for offer in fixture["validOffers"].as_array().unwrap() {
            let mut caps = hello_caps();
            caps[name] = offer.clone();
            let parsed: DaemonCapabilitiesV11 = serde_json::from_value(caps).unwrap();
            let offered = [
                parsed.pending_receipts,
                parsed.expiry_status_results,
                parsed.observation_fence,
            ];
            let expected = match name {
                "pendingReceipts" => [true, true, true],
                "expiryStatusResults" => [true, true, true],
                "observationFence" => [true, true, true],
                other => panic!("unknown capability {other}"),
            };
            assert_eq!(offered, expected, "{name}");
        }
        for offer in fixture["rejectedOffers"].as_array().unwrap() {
            let mut caps = hello_caps();
            caps[name] = offer.clone();
            assert!(
                serde_json::from_value::<DaemonCapabilitiesV11>(caps).is_err(),
                "{name}={offer}"
            );
        }
    }
}

#[test]
fn hello_ok_requires_the_current_receipt_capabilities() {
    let fixture = fixture();
    let parsed: NegotiatedCapabilities =
        serde_json::from_value(fixture["helloOkCapabilities"].clone()).unwrap();
    assert!(parsed.pending_receipts && parsed.expiry_status_results && parsed.observation_fence);
    let mut older = fixture["helloOkCapabilities"].clone();
    older.as_object_mut().unwrap().remove("pendingReceipts");
    older.as_object_mut().unwrap().remove("expiryStatusResults");
    older.as_object_mut().unwrap().remove("observationFence");
    assert!(serde_json::from_value::<NegotiatedCapabilities>(older).is_err());
}

#[test]
fn reconcile_complete_names_at_most_the_bounded_pending_receipts() {
    let fixture = fixture();
    assert_eq!(PENDING_RECEIPTS_MAX, 4);
    for frame in fixture["reconcileComplete"].as_array().unwrap() {
        let parsed = parse_daemon_control(&frame.to_string()).expect("reconcile.complete");
        assert!(matches!(
            parsed,
            DaemonControlMessage::ReconcileComplete { .. }
        ));
        assert_eq!(encode(&parsed), *frame);
    }
    for frame in fixture["rejectedReconcileComplete"].as_array().unwrap() {
        assert!(parse_daemon_control(&frame.to_string()).is_err(), "{frame}");
    }
    // An empty pending-receipt set may use the compact representation.
    assert_eq!(
        encode(&DaemonControlMessage::ReconcileComplete {
            pending_receipts: None
        }),
        serde_json::json!({ "type": "reconcile.complete" })
    );
}

#[test]
fn expiry_status_batches_and_acks_parse_strictly() {
    let fixture = fixture();
    let frame = &fixture["expiryStatus"];
    let parsed = parse_daemon_control(&frame.to_string()).expect("expiry status");
    let DaemonControlMessage::SandboxExpiryStatus {
        batch: Some(1),
        observation: Some(1),
        ref entries,
    } = parsed
    else {
        panic!("not a batched expiry status");
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(encode(&parsed), *frame);
    for batch in fixture["rejectedExpiryBatches"].as_array().unwrap() {
        let mut frame = frame.clone();
        frame["batch"] = batch.clone();
        assert!(parse_daemon_control(&frame.to_string()).is_err(), "{batch}");
    }
    for observation in fixture["rejectedObservations"].as_array().unwrap() {
        let mut frame = frame.clone();
        frame["observation"] = observation.clone();
        assert!(
            parse_daemon_control(&frame.to_string()).is_err(),
            "{observation}"
        );
    }
    // A batch without an observation is an expiryStatusResults-only peer's
    // frame (the server refuses it once the fence is negotiated).
    let mut unfenced = frame.clone();
    unfenced.as_object_mut().unwrap().remove("observation");
    assert!(matches!(
        parse_daemon_control(&unfenced.to_string()).unwrap(),
        DaemonControlMessage::SandboxExpiryStatus {
            batch: Some(1),
            observation: None,
            ..
        }
    ));
    // An observation numbers batches: never without one.
    let mut unbatched = frame.clone();
    unbatched.as_object_mut().unwrap().remove("batch");
    assert!(parse_daemon_control(&unbatched.to_string()).is_err());
    unbatched.as_object_mut().unwrap().remove("observation");
    assert!(matches!(
        parse_daemon_control(&unbatched.to_string()).unwrap(),
        DaemonControlMessage::SandboxExpiryStatus {
            batch: None,
            observation: None,
            ..
        }
    ));

    let ServerControlMessage::SandboxExpiryStatusAck {
        batch: 1,
        entry_results,
    } = parse_server_control(&fixture["ack"].to_string()).expect("ack")
    else {
        panic!("not an expiry-status ack");
    };
    assert_eq!(
        entry_results.iter().map(|r| r.outcome).collect::<Vec<_>>(),
        [
            CensusEntryOutcome::Converged,
            CensusEntryOutcome::StaleStorage,
            CensusEntryOutcome::NotConverged,
            CensusEntryOutcome::Superseded
        ]
    );
    // `superseded` answers expiry status only, never a census page.
    for ack in fixture["rejectedInventoryAcks"].as_array().unwrap() {
        assert!(parse_server_control(&ack.to_string()).is_err(), "{ack}");
        let mut judged = ack.clone();
        judged["entryResults"][0]["outcome"] = "not_converged".into();
        assert!(
            parse_server_control(&judged.to_string()).is_ok(),
            "{judged}"
        );
    }
    for ack in fixture["rejectedAcks"].as_array().unwrap() {
        assert!(parse_server_control(&ack.to_string()).is_err(), "{ack}");
    }
}
