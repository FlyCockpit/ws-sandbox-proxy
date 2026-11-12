//! WP7 graceful quiesce wire parity. The shared fixture
//! `control_host_quiesce.json` is also consumed by
//! `apps/server/src/sandbox-relay/protocol.test.ts`.
//!
//! The daemon's hello encoder (`DaemonControlMessage::Hello.quiescing`,
//! `DaemonCapabilities.quiesce`) is checked against the cross-language
//! validator (`HostHelloV11`), and `host.quiesce.ack` parses as the
//! `ServerControlMessage::HostQuiesceAck` variant.

use sandbox_protocol::{
    DaemonControlMessage, HostQuiesceAckV11, NegotiatedCapabilities, ServerControlMessage,
    WireCodes, capacity_v11::HostHelloV11, parse_daemon_control, parse_server_control,
};

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../fixtures/control_host_quiesce.json")).expect("json")
}

fn hello() -> serde_json::Value {
    serde_json::from_str(include_str!("../fixtures/control_hello_daemon.json")).expect("hello")
}

/// The ack frame as the daemon parses it.
fn ack(frame: &serde_json::Value) -> Option<HostQuiesceAckV11> {
    match parse_server_control(&frame.to_string()) {
        Ok(ServerControlMessage::HostQuiesceAck(ack)) => Some(ack),
        Ok(other) => panic!("not host.quiesce.ack: {other:?}"),
        Err(_) => None,
    }
}

#[test]
fn host_quiesce_reports_parse_and_bounds_hold() {
    let cases = fixture();
    for frame in cases["quiesce"].as_array().unwrap() {
        let parsed = parse_daemon_control(&frame.to_string()).expect("host.quiesce");
        let DaemonControlMessage::HostQuiesce(quiesce) = parsed else {
            panic!("not host.quiesce: {frame}");
        };
        assert_eq!(
            u64::from(quiesce.connection_epoch),
            frame["connectionEpoch"]
        );
        assert_eq!(quiesce.sequence, frame["sequence"]);
    }
    for frame in cases["invalidQuiesce"].as_array().unwrap() {
        assert!(parse_daemon_control(&frame.to_string()).is_err(), "{frame}");
    }
}

#[test]
fn host_quiesce_ack_parses_with_its_sequence() {
    let cases = fixture();
    for frame in cases["acks"].as_array().unwrap() {
        assert_eq!(
            ack(frame).expect("ack").sequence,
            frame["sequence"].as_u64().unwrap()
        );
    }
    for frame in cases["invalidAcks"].as_array().unwrap() {
        assert!(ack(frame).is_none(), "{frame}");
    }
}

#[test]
fn hello_quiescing_needs_the_capability() {
    for case in fixture()["hellos"].as_array().unwrap() {
        let mut frame = hello();
        if !case["capability"].is_null() {
            frame["daemon"]["capabilities"]["quiesce"] = case["capability"].clone();
        }
        if !case["quiescing"].is_null() {
            frame["quiescing"] = case["quiescing"].clone();
        }
        let parsed = serde_json::from_value::<HostHelloV11>(frame);
        assert_eq!(parsed.is_ok(), case["valid"] == true, "{}", case["case"]);
        if let Ok(parsed) = parsed {
            assert_eq!(
                parsed.quiescing,
                case["quiescingParsed"] == true,
                "{}",
                case["case"]
            );
            // The quiescing flag is omitted when false.
            let encoded = serde_json::to_value(&parsed).unwrap();
            assert_eq!(
                encoded.get("quiescing").is_some(),
                parsed.quiescing,
                "{}",
                case["case"]
            );
            assert_eq!(
                encoded["daemon"]["capabilities"].get("quiesce").is_some(),
                parsed.daemon.capabilities.quiesce,
                "{}",
                case["case"]
            );
        }
    }
}

#[test]
fn hello_ok_echoes_quiesce_only_when_set() {
    let cases = fixture();
    let ServerControlMessage::HelloOk { capabilities, .. } =
        parse_server_control(&cases["helloOk"].to_string()).expect("hello.ok")
    else {
        panic!("not hello.ok");
    };
    assert!(capabilities.quiesce);
    let mut older = cases["helloOk"].clone();
    older["capabilities"]
        .as_object_mut()
        .unwrap()
        .remove("quiesce");
    let ServerControlMessage::HelloOk { capabilities, .. } =
        parse_server_control(&older.to_string()).expect("older hello.ok")
    else {
        panic!("not hello.ok");
    };
    assert!(!capabilities.quiesce);
    let encoded = serde_json::to_value(NegotiatedCapabilities {
        quiesce: false,
        ..capabilities
    })
    .unwrap();
    assert!(encoded.get("quiesce").is_none());
}

/// The daemon's own encoder: `quiescing` and `quiesce` are emitted only when
/// set, a quiescing hello passes the cross-language validator, and the
/// encoder refuses `quiescing` without the capability.
#[test]
fn daemon_hello_encodes_quiescing_only_with_the_capability() {
    let mut parsed = parse_daemon_control(&hello().to_string()).expect("hello");
    let encode = |message: &DaemonControlMessage| {
        WireCodes::CURRENT
            .encode(message, None)
            .map(|frame| serde_json::from_str::<serde_json::Value>(&frame.text).unwrap())
    };
    let plain = encode(&parsed).expect("plain hello");
    assert!(plain.get("quiescing").is_none());
    assert!(plain["daemon"]["capabilities"].get("quiesce").is_none());
    let set = |message: &mut DaemonControlMessage, flag: bool, capability: bool| {
        let DaemonControlMessage::Hello {
            daemon, quiescing, ..
        } = message
        else {
            panic!("not a hello");
        };
        *quiescing = flag;
        daemon.capabilities.quiesce = capability;
    };
    set(&mut parsed, true, false);
    assert!(
        encode(&parsed).is_err(),
        "quiescing without the capability is refused"
    );
    set(&mut parsed, false, true);
    let capable = encode(&parsed).expect("capable hello");
    assert!(capable.get("quiescing").is_none());
    assert_eq!(capable["daemon"]["capabilities"]["quiesce"], true);
    set(&mut parsed, true, true);
    let encoded = encode(&parsed).expect("quiescing hello");
    assert_eq!(encoded["quiescing"], true);
    assert_eq!(encoded["daemon"]["capabilities"]["quiesce"], true);
    assert!(serde_json::from_value::<HostHelloV11>(encoded.clone()).is_ok());
    let DaemonControlMessage::Hello { quiescing, .. } =
        parse_daemon_control(&encoded.to_string()).expect("round trip")
    else {
        panic!("not a hello");
    };
    assert!(quiescing);
}
