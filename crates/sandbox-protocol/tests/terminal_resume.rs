//! WP8 terminal reattach contract parity. The shared fixture
//! `terminal_resume.json` is also consumed by
//! `apps/server/src/sandbox-relay/protocol-terminal-resume.test.ts`.

use sandbox_protocol::{
    DaemonControlMessage, ServerControlMessage, TERMINAL_RESUME_GRACE_DEFAULT_MS,
    TERMINAL_RESUME_GRACE_MAX_MS, TerminalControlV11, TerminalResumeCapabilityV11,
    capacity_v11::DaemonCapabilitiesV11, parse_daemon_control, parse_server_control,
};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../fixtures/terminal_resume.json")).expect("json")
}

fn hello_caps() -> serde_json::Value {
    serde_json::from_str::<serde_json::Value>(include_str!("../fixtures/control_hello_daemon.json"))
        .unwrap()["daemon"]["capabilities"]
        .clone()
}

fn resume_answer(hello_ok: &serde_json::Value) -> bool {
    match parse_server_control(&hello_ok.to_string()).expect("hello.ok") {
        ServerControlMessage::HelloOk { capabilities, .. } => capabilities.terminal_resume,
        other => panic!("unexpected {other:?}"),
    }
}

fn typed(value: &serde_json::Value) -> Option<TerminalControlV11> {
    serde_json::from_value::<TerminalControlV11>(value.clone())
        .ok()
        .filter(TerminalControlV11::is_valid)
}

#[test]
fn grace_bounds_match_the_fixture() {
    let fixture = fixture();
    assert_eq!(
        fixture["graceDefaultMs"].as_u64(),
        Some(TERMINAL_RESUME_GRACE_DEFAULT_MS)
    );
    assert_eq!(
        fixture["graceMaxMs"].as_u64(),
        Some(TERMINAL_RESUME_GRACE_MAX_MS)
    );
}

#[test]
fn the_capability_is_optional_and_range_checked() {
    let fixture = fixture();
    // Absent when the runtime does not support terminal reattachment.
    let parsed: DaemonCapabilitiesV11 = serde_json::from_value(hello_caps()).unwrap();
    assert_eq!(parsed.terminal_resume, None);
    assert!(
        !serde_json::to_value(&parsed)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("terminalResume")
    );
    for value in fixture["validOffers"].as_array().unwrap() {
        let mut caps = hello_caps();
        caps["terminalResume"] = value.clone();
        let parsed: DaemonCapabilitiesV11 =
            serde_json::from_value(caps).unwrap_or_else(|e| panic!("{value}: {e}"));
        assert_eq!(
            parsed.terminal_resume,
            Some(TerminalResumeCapabilityV11 {
                grace_ms: value["graceMs"].as_u64().unwrap()
            })
        );
        assert_eq!(
            serde_json::to_value(&parsed).unwrap()["terminalResume"],
            *value
        );
    }
    for value in fixture["rejectedOffers"].as_array().unwrap() {
        let mut caps = hello_caps();
        caps["terminalResume"] = value.clone();
        assert!(
            serde_json::from_value::<DaemonCapabilitiesV11>(caps).is_err(),
            "{value}"
        );
    }
}

#[test]
fn hello_ok_answers_only_when_offered() {
    let fixture = fixture();
    let legacy: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/control_hello_ok_server.json")).unwrap();
    assert!(!resume_answer(&legacy));
    assert!(resume_answer(&fixture["helloOk"]));
    for value in fixture["rejectedAnswers"].as_array().unwrap() {
        let mut frame = fixture["helloOk"].clone();
        frame["capabilities"]["terminalResume"] = value.clone();
        assert!(parse_server_control(&frame.to_string()).is_err(), "{value}");
    }
}

#[test]
fn resume_frames_are_sandbox_only_and_strict() {
    let fixture = fixture();
    for frame in fixture["resume"].as_array().unwrap() {
        let parsed = typed(frame).unwrap_or_else(|| panic!("{frame}"));
        assert!(matches!(parsed, TerminalControlV11::Resume { .. }));
        assert_eq!(serde_json::to_value(&parsed).unwrap(), *frame);
    }
    for frame in fixture["rejectedResume"].as_array().unwrap() {
        assert!(typed(frame).is_none(), "{frame}");
    }
}

#[test]
fn resume_answers_carry_the_output_sequence() {
    let fixture = fixture();
    for frame in fixture["ready"].as_array().unwrap() {
        match parse_daemon_control(&frame.to_string()).unwrap_or_else(|e| panic!("{frame}: {e}")) {
            DaemonControlMessage::TerminalReady { output_seq, .. } => {
                assert_eq!(output_seq, frame["outputSeq"].as_u64());
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(serde_json::to_value(typed(frame).unwrap()).unwrap(), *frame);
    }
    for frame in fixture["rejectedReady"].as_array().unwrap() {
        assert!(parse_daemon_control(&frame.to_string()).is_err(), "{frame}");
        assert!(typed(frame).is_none(), "{frame}");
    }
}

/// The daemon's server-control decoder routes the same frames (sandbox only,
/// strict) and the daemon hello's `terminalResume` offer round-trips.
#[test]
fn daemon_decoder_routes_resume_frames_and_the_hello_offer() {
    let fixture = fixture();
    for frame in fixture["resume"].as_array().unwrap() {
        match parse_server_control(&frame.to_string()).unwrap_or_else(|e| panic!("{frame}: {e}")) {
            ServerControlMessage::TerminalResume {
                next_output_seq, ..
            } => assert_eq!(Some(next_output_seq), frame["nextOutputSeq"].as_u64()),
            other => panic!("unexpected {other:?}"),
        }
    }
    for frame in fixture["rejectedResume"].as_array().unwrap() {
        assert!(parse_server_control(&frame.to_string()).is_err(), "{frame}");
    }
    let offered = sandbox_protocol::DaemonCapabilities {
        terminal_resume: Some(TerminalResumeCapabilityV11 {
            grace_ms: TERMINAL_RESUME_GRACE_DEFAULT_MS,
        }),
        ..Default::default()
    };
    let value = serde_json::to_value(&offered).unwrap();
    assert_eq!(
        value["terminalResume"],
        serde_json::json!({ "graceMs": TERMINAL_RESUME_GRACE_DEFAULT_MS })
    );
    assert!(
        !serde_json::to_value(sandbox_protocol::DaemonCapabilities::default())
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("terminalResume")
    );
}
