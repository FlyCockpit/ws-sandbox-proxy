//! `commandRetire` parity. The shared fixture
//! `command_retire_frames.json` is also consumed by
//! `apps/server/src/sandbox-relay/protocol-command-retire.test.ts`.

use sandbox_protocol::{
    DaemonCapabilities, NegotiatedCapabilities, ServerControlMessage,
    capacity_v11::DaemonCapabilitiesV11, parse_server_control,
};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../fixtures/command_retire_frames.json")).expect("json")
}

fn hello_caps() -> serde_json::Value {
    serde_json::from_str::<serde_json::Value>(include_str!("../fixtures/control_hello_daemon.json"))
        .unwrap()["daemon"]["capabilities"]
        .clone()
}

#[test]
fn census_results_are_required_and_offered_by_default() {
    let fixture = fixture();
    let name = fixture["capability"].as_str().unwrap();
    let parsed: DaemonCapabilitiesV11 = serde_json::from_value(hello_caps()).unwrap();
    assert!(parsed.command_retire);
    let default = serde_json::to_string(&DaemonCapabilities::default()).unwrap();
    assert!(default.contains(name));
    let offered = DaemonCapabilities {
        command_retire: true,
        ..DaemonCapabilities::default()
    };
    assert!(
        serde_json::to_string(&offered)
            .unwrap()
            .contains("\"commandRetire\":true")
    );
    for offer in fixture["validOffers"].as_array().unwrap() {
        let mut caps = hello_caps();
        caps[name] = offer.clone();
        let parsed: DaemonCapabilitiesV11 = serde_json::from_value(caps).unwrap();
        assert!(parsed.command_retire);
    }
    for offer in fixture["rejectedOffers"].as_array().unwrap() {
        let mut caps = hello_caps();
        caps[name] = offer.clone();
        assert!(
            serde_json::from_value::<DaemonCapabilitiesV11>(caps).is_err(),
            "{offer}"
        );
    }
}

#[test]
fn hello_ok_requires_the_current_receipt_capabilities() {
    let fixture = fixture();
    let parsed: NegotiatedCapabilities =
        serde_json::from_value(fixture["helloOkCapabilities"].clone()).unwrap();
    assert!(parsed.command_retire);
    let mut older = fixture["helloOkCapabilities"].clone();
    older.as_object_mut().unwrap().remove("commandRetire");
    assert!(serde_json::from_value::<NegotiatedCapabilities>(older).is_err());
}

#[test]
fn receipt_confirmed_carries_retire_command_only_as_true() {
    let fixture = fixture();
    let frame = fixture["retireConfirmation"].clone();
    let Ok(ServerControlMessage::ReceiptConfirmed(confirmed)) =
        parse_server_control(&frame.to_string())
    else {
        panic!("receipt.confirmed");
    };
    assert!(confirmed.retire_command && confirmed.cleanup_generation.is_none());
    // Round trip: encoded exactly as the fixture, and absent when false.
    let encoded =
        serde_json::to_value(ServerControlMessage::ReceiptConfirmed(confirmed.clone())).unwrap();
    assert_eq!(encoded, frame);
    let mut plain = frame.clone();
    plain.as_object_mut().unwrap().remove("retireCommand");
    let Ok(ServerControlMessage::ReceiptConfirmed(ordinary)) =
        parse_server_control(&plain.to_string())
    else {
        panic!("ordinary receipt.confirmed");
    };
    assert!(!ordinary.retire_command);
    for value in fixture["rejectedRetireValues"].as_array().unwrap() {
        let mut bad = frame.clone();
        bad["retireCommand"] = value.clone();
        assert!(parse_server_control(&bad.to_string()).is_err(), "{value}");
    }
}
