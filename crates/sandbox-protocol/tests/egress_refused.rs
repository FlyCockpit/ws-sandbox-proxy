//! B12 `egress.refused` and `egressRefusedHints` parity. The shared fixture
//! `egress_refused.json` is also consumed by
//! `apps/server/src/sandbox-relay/protocol-egress-refused.test.ts`.

use sandbox_protocol::{
    DaemonControlMessage, WireCodes, capacity_v11::DaemonCapabilitiesV11, parse_daemon_control,
    valid_hint_dns_name,
};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../fixtures/egress_refused.json")).expect("json")
}

#[test]
fn frames_match_the_shared_fixture() {
    let fixture = fixture();
    for frame in fixture["frames"].as_array().unwrap() {
        let parsed =
            parse_daemon_control(&frame.to_string()).unwrap_or_else(|e| panic!("{frame}: {e}"));
        assert!(matches!(parsed, DaemonControlMessage::EgressRefused(_)));
        let text = WireCodes::CURRENT.encode(&parsed, None).unwrap().text;
        assert_eq!(
            &serde_json::from_str::<serde_json::Value>(&text).unwrap(),
            frame
        );
    }
    for frame in fixture["rejectedFrames"].as_array().unwrap() {
        assert!(parse_daemon_control(&frame.to_string()).is_err(), "{frame}");
    }
}

#[test]
fn invalid_frames_never_encode() {
    let frame = DaemonControlMessage::EgressRefused(sandbox_protocol::EgressRefusedV11 {
        sandbox_id: "sbx".into(),
        names: vec!["bad\u{1b}name".into()],
    });
    assert!(WireCodes::CURRENT.encode(&frame, None).is_err());
}

#[test]
fn name_grammar_matches_the_shared_fixture() {
    let fixture = fixture();
    for name in fixture["validNames"].as_array().unwrap() {
        assert!(valid_hint_dns_name(name.as_str().unwrap()), "{name}");
    }
    for name in fixture["invalidNames"].as_array().unwrap() {
        assert!(!valid_hint_dns_name(name.as_str().unwrap()), "{name}");
    }
}

#[test]
fn capability_is_additive() {
    let fixture = fixture();
    let base = serde_json::from_str::<serde_json::Value>(include_str!(
        "../fixtures/control_hello_daemon.json"
    ))
    .unwrap()["daemon"]["capabilities"]
        .clone();
    // Optional diagnostics are omitted when disabled.
    let parsed: DaemonCapabilitiesV11 = serde_json::from_value(base.clone()).unwrap();
    assert!(!parsed.egress_refused_hints);
    assert!(
        !serde_json::to_string(&parsed)
            .unwrap()
            .contains("egressRefusedHints")
    );
    for value in fixture["capabilities"].as_array().unwrap() {
        let mut caps = base.clone();
        caps["egressRefusedHints"] = value.clone();
        let parsed: DaemonCapabilitiesV11 =
            serde_json::from_value(caps).unwrap_or_else(|e| panic!("{value}: {e}"));
        assert_eq!(parsed.egress_refused_hints, value.as_bool().unwrap());
        let encoded = serde_json::to_value(&parsed).unwrap();
        assert_eq!(
            encoded.get("egressRefusedHints").is_some(),
            parsed.egress_refused_hints
        );
    }
    for value in fixture["rejectedCapabilities"].as_array().unwrap() {
        let mut caps = base.clone();
        caps["egressRefusedHints"] = value.clone();
        assert!(
            serde_json::from_value::<DaemonCapabilitiesV11>(caps).is_err(),
            "{value}"
        );
    }
    // The daemon-side struct: omitted when false, present when true.
    let mut daemon = sandbox_protocol::DaemonCapabilities::default();
    assert!(
        !serde_json::to_string(&daemon)
            .unwrap()
            .contains("egressRefusedHints")
    );
    daemon.egress_refused_hints = true;
    assert!(
        serde_json::to_string(&daemon)
            .unwrap()
            .contains("\"egressRefusedHints\":true")
    );
}
