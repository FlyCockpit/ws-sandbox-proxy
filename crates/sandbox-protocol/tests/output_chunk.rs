//! D3b output chunk negotiation parity. The shared fixture
//! `output_chunk_negotiation.json` is also consumed by
//! `apps/server/src/sandbox-relay/protocol-output-chunk.test.ts`.

use sandbox_protocol::{
    SANDBOX_OUTPUT_CHUNK_OFFER_BYTES, ServerControlMessage, capacity_v11::DaemonCapabilitiesV11,
    negotiated_output_chunk_bytes, parse_server_control,
};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../fixtures/output_chunk_negotiation.json")).expect("json")
}

fn hello_caps() -> serde_json::Value {
    serde_json::from_str::<serde_json::Value>(include_str!("../fixtures/control_hello_daemon.json"))
        .unwrap()["daemon"]["capabilities"]
        .clone()
}

fn answer_of(hello_ok: &serde_json::Value) -> Option<u32> {
    match parse_server_control(&hello_ok.to_string()).expect("hello.ok") {
        ServerControlMessage::HelloOk { capabilities, .. } => capabilities.output_chunk_bytes,
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn the_daemon_offers_the_shared_ceiling() {
    let fixture = fixture();
    assert_eq!(
        fixture["daemonOffer"].as_u64(),
        Some(SANDBOX_OUTPUT_CHUNK_OFFER_BYTES as u64)
    );
    let parsed: DaemonCapabilitiesV11 = serde_json::from_value(hello_caps()).unwrap();
    assert_eq!(
        parsed.max_output_chunk_bytes,
        Some(SANDBOX_OUTPUT_CHUNK_OFFER_BYTES as u32)
    );
    for value in fixture["validOffers"].as_array().unwrap() {
        let mut caps = hello_caps();
        caps["maxOutputChunkBytes"] = value.clone();
        let parsed: DaemonCapabilitiesV11 =
            serde_json::from_value(caps).unwrap_or_else(|e| panic!("{value}: {e}"));
        assert_eq!(parsed.max_output_chunk_bytes.map(u64::from), value.as_u64());
        assert_eq!(
            serde_json::to_value(&parsed).unwrap()["maxOutputChunkBytes"],
            *value
        );
    }
    for value in fixture["rejectedOffers"].as_array().unwrap() {
        let mut caps = hello_caps();
        caps["maxOutputChunkBytes"] = value.clone();
        assert!(
            serde_json::from_value::<DaemonCapabilitiesV11>(caps).is_err(),
            "{value}"
        );
    }
}

#[test]
fn hello_ok_answer_is_required_and_range_checked() {
    let fixture = fixture();
    let current: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/control_hello_ok_server.json")).unwrap();
    assert_eq!(answer_of(&current), Some(65_536));
    assert_eq!(
        answer_of(&fixture["helloOk"]).map(u64::from),
        fixture["serverMax"].as_u64()
    );
    for value in fixture["rejectedAnswers"].as_array().unwrap() {
        let mut frame = fixture["helloOk"].clone();
        frame["capabilities"]["outputChunkBytes"] = value.clone();
        assert!(parse_server_control(&frame.to_string()).is_err(), "{value}");
    }
}

#[test]
fn negotiation_matrix_matches_the_shared_fixture() {
    for row in fixture()["matrix"].as_array().unwrap() {
        let offer = row["offer"].as_u64().unwrap() as usize;
        let answer = row["answer"].as_u64().map(|v| u32::try_from(v).unwrap());
        let chunk = negotiated_output_chunk_bytes(offer, answer);
        assert_eq!(
            chunk as u64,
            row["chunkBytes"].as_u64().unwrap(),
            "{}",
            row["case"]
        );
    }
    // Never above the daemon's own offer, never below the minimum size.
    assert_eq!(
        negotiated_output_chunk_bytes(65_536, Some(1_048_576)),
        65_536
    );
    assert_eq!(negotiated_output_chunk_bytes(65_536, Some(8_192)), 8_192);
    assert_eq!(negotiated_output_chunk_bytes(65_536, Some(1)), 8_192);
}
