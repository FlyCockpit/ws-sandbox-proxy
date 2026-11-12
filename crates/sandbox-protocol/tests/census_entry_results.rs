//! Per-entry census results (`censusEntryResults`) parity. The shared fixture
//! `census_entry_results.json` is also consumed by
//! `apps/server/src/sandbox-relay/protocol-census-results.test.ts`.

use sandbox_protocol::{
    CensusEntryOutcome, DaemonCapabilities, ServerControlMessage,
    capacity_v11::DaemonCapabilitiesV11, census_results_match, parse_server_control,
};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../fixtures/census_entry_results.json")).expect("json")
}

fn hello_caps() -> serde_json::Value {
    serde_json::from_str::<serde_json::Value>(include_str!("../fixtures/control_hello_daemon.json"))
        .unwrap()["daemon"]["capabilities"]
        .clone()
}

#[test]
fn the_offer_is_an_explicit_true_and_absent_by_default() {
    let fixture = fixture();
    let parsed: DaemonCapabilitiesV11 = serde_json::from_value(hello_caps()).unwrap();
    assert!(parsed.census_entry_results);
    assert!(
        serde_json::to_string(&DaemonCapabilities::default())
            .unwrap()
            .contains("censusEntryResults")
    );
    for offer in fixture["validOffers"].as_array().unwrap() {
        let mut caps = hello_caps();
        caps["censusEntryResults"] = offer.clone();
        let parsed: DaemonCapabilitiesV11 = serde_json::from_value(caps).unwrap();
        assert!(parsed.census_entry_results);
    }
    for offer in fixture["rejectedOffers"].as_array().unwrap() {
        let mut caps = hello_caps();
        caps["censusEntryResults"] = offer.clone();
        assert!(
            serde_json::from_value::<DaemonCapabilitiesV11>(caps).is_err(),
            "{offer}"
        );
    }
}

#[test]
fn hello_ok_answers_and_inventory_acks_parse_strictly() {
    let fixture = fixture();
    let hello_ok = serde_json::json!({
        "type": "hello.ok", "id": "hello-1", "protocolVersion": "1.0",
        "supportedProtocolVersions": ["1.0"], "connectionEpoch": 1, "hostOwnerId": "owner-1",
        "capabilities": fixture["helloOkCapabilities"],
    });
    match parse_server_control(&hello_ok.to_string()).expect("hello.ok") {
        ServerControlMessage::HelloOk { capabilities, .. } => {
            assert!(capabilities.census_entry_results)
        }
        other => panic!("unexpected {other:?}"),
    }
    let ServerControlMessage::InventoryAck {
        page: 0,
        entry_results: Some(results),
    } = parse_server_control(&fixture["ack"].to_string()).expect("ack")
    else {
        panic!("not an inventory.ack with results");
    };
    assert_eq!(
        results.iter().map(|r| r.outcome).collect::<Vec<_>>(),
        [
            CensusEntryOutcome::Converged,
            CensusEntryOutcome::StaleStorage,
            CensusEntryOutcome::NotConverged
        ]
    );
    for ack in fixture["rejectedAcks"].as_array().unwrap() {
        assert!(parse_server_control(&ack.to_string()).is_err(), "{ack}");
    }
}

#[test]
fn results_must_answer_their_page_exactly() {
    let entry = |id: &str| sandbox_protocol::InventoryEntry {
        sandbox_owner_id: Some("owner".into()),
        sandbox_id: id.into(),
        state: sandbox_protocol::SandboxLifecycleState::Stopped,
        lease: None,
        root: None,
    };
    let result = |id: &str| sandbox_protocol::CensusEntryResult {
        sandbox_id: id.into(),
        outcome: CensusEntryOutcome::Converged,
    };
    let page = [entry("sbx-a"), entry("sbx-b")];
    assert!(census_results_match(
        &page,
        &[result("sbx-a"), result("sbx-b")]
    ));
    assert!(!census_results_match(
        &page,
        &[result("sbx-b"), result("sbx-a")]
    ));
    assert!(!census_results_match(&page, &[result("sbx-a")]));
    assert!(!census_results_match(&[], &[result("sbx-a")]));
}
