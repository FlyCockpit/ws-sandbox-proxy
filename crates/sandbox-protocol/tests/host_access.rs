use sandbox_protocol::*;
use serde_json::{Value, json};
fn fixtures() -> Value {
    serde_json::from_str(include_str!("../fixtures/control_host_access.json")).unwrap()
}
#[test]
fn all_host_frames_round_trip_and_refuse_unknown_fields() {
    let f = fixtures();
    for v in f["server"].as_array().unwrap() {
        let frame = parse_server_control(&v.to_string()).unwrap_or_else(|e| panic!("{v}: {e}"));
        assert_eq!(
            serde_json::from_str::<Value>(&encode_server_control(&frame).unwrap()).unwrap(),
            *v
        );
        let mut extra = v.clone();
        extra["unexpected"] = json!(true);
        assert!(parse_server_control(&extra.to_string()).is_err(), "{v}");
    }
    for v in f["daemon"].as_array().unwrap() {
        let frame = parse_daemon_control(&v.to_string()).unwrap_or_else(|e| panic!("{v}: {e}"));
        let encoded = WireCodes::CURRENT.encode(&frame, None).unwrap().text;
        assert_eq!(serde_json::from_str::<Value>(&encoded).unwrap(), *v);
        let mut extra = v.clone();
        extra["unexpected"] = json!(true);
        assert!(parse_daemon_control(&extra.to_string()).is_err(), "{v}");
    }
}
#[test]
fn request_bounds_and_command_exclusivity_are_enforced() {
    let f = fixtures();
    let start = f["server"][2].clone();
    for (key, value) in [
        ("connectionEpoch", json!(0)),
        ("connectionEpoch", json!(2147483648u64)),
        ("requestId", json!("")),
        ("commandId", json!("short")),
        ("ownerId", json!("")),
        ("agentPolicyRevision", json!(9007199254740992u64)),
        ("argv", json!([])),
        ("argv", json!(["x\u{0000}y"])),
        ("argv", json!(["a".repeat(4097)])),
        ("argv", json!(vec!["a"; 257])),
        ("argv", json!(vec!["a".repeat(4096); 5])),
        ("cwd", json!("x\u{0000}")),
        ("timeoutMs", json!(0)),
        ("script", json!("also present")),
    ] {
        let mut bad = start.clone();
        bad[key] = value;
        assert!(
            parse_server_control(&bad.to_string()).is_err(),
            "{key}: {bad}"
        );
    }
    let mut bad = start.clone();
    bad.as_object_mut().unwrap().remove("argv");
    assert!(parse_server_control(&bad.to_string()).is_err());
    bad["script"] = json!("a".repeat(16385));
    assert!(parse_server_control(&bad.to_string()).is_err());
    for (index, key, value) in [
        (4, "maxBytes", json!(65537)),
        (4, "stdoutOffset", json!(9007199254740992u64)),
        (5, "data", json!("aGVsbG8")),
        (5, "data", json!(encode_host_data(&vec![0; 65537]))),
        (7, "maxBytes", json!(262145)),
        (9, "content", json!("a".repeat(262145))),
        (10, "edits", json!([])),
        (10, "edits", json!([{"oldText":"","newText":"x"}])),
    ] {
        let mut bad = f["server"][index].clone();
        bad[key] = value;
        assert!(parse_server_control(&bad.to_string()).is_err(), "{key}");
    }
}
#[test]
fn policy_and_result_combinations_are_strict() {
    let f = fixtures();
    for (key, value) in [
        ("hostCommands", json!(false)),
        ("hostCommandMaxMs", json!(999)),
        ("agentPolicyRevision", json!(9007199254740992u64)),
        ("sequence", json!(0)),
    ] {
        let mut bad = f["daemon"][0].clone();
        bad[key] = value;
        assert!(parse_daemon_control(&bad.to_string()).is_err());
    }
    let mut bad = f["daemon"].as_array().unwrap().last().unwrap().clone();
    bad["error"] = json!("path_denied");
    assert!(parse_daemon_control(&bad.to_string()).is_err());
    bad.as_object_mut().unwrap().remove("error");
    bad["ok"] = json!(false);
    assert!(parse_daemon_control(&bad.to_string()).is_err());
}
#[test]
fn larger_host_payloads_keep_other_frames_at_the_existing_limit() {
    let f = fixtures();
    let mut write = f["server"][9].clone();
    write["content"] = json!("\u{0001}".repeat(262144));
    let frame = parse_server_control(&write.to_string()).unwrap();
    assert!(encode_server_control(&frame).is_ok());
    let mut poll = f["server"][4].clone();
    poll["padding"] = json!("x".repeat(65536));
    assert!(parse_server_control(&poll.to_string()).is_err());
    let output = HostExecOutputV11 {
        offset: 0,
        data: encode_host_data(&vec![255; 65536]),
        dropped: false,
    };
    assert!(output.is_valid());
    assert_eq!(decode_host_data(&output.data).unwrap(), vec![255; 65536]);
    assert!(decode_host_data("YQ==").is_some());
    assert!(decode_host_data("YR==").is_none());
}

#[test]
fn hello_capabilities_accept_host_access_and_keep_old_fixtures_unchanged() {
    let original: Value =
        serde_json::from_str(include_str!("../fixtures/control_hello_daemon.json")).unwrap();
    let old = parse_daemon_control(&original.to_string()).unwrap();
    let old_encoded = WireCodes::CURRENT.encode(&old, None).unwrap().text;
    assert_eq!(
        serde_json::from_str::<Value>(&old_encoded).unwrap(),
        original
    );
    let mut value = original;
    let caps = &mut value["daemon"]["capabilities"];
    caps["hostCommands"] = json!(true);
    caps["hostFiles"] = json!(true);
    caps["hostCommandMaxMs"] = json!(600000);
    caps["agentPolicyRevision"] = json!(1);
    let frame = parse_daemon_control(&value.to_string()).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&WireCodes::CURRENT.encode(&frame, None).unwrap().text)
            .unwrap(),
        value
    );
    let _: capacity_v11::HostHelloV11 = serde_json::from_value(value.clone()).unwrap();
    for (key, bad) in [
        ("hostCommands", json!(false)),
        ("hostCommandMaxMs", json!(0)),
        ("agentPolicyRevision", json!(9007199254740992u64)),
    ] {
        let mut invalid = value.clone();
        invalid["daemon"]["capabilities"][key] = bad;
        assert!(parse_daemon_control(&invalid.to_string()).is_err());
        assert!(serde_json::from_value::<capacity_v11::HostHelloV11>(invalid).is_err());
    }
}

#[test]
fn host_etags_are_keyed_digest_identifiers() {
    assert!(valid_host_file_etag("h:abcdefghijklmnopqrstuv"));
    for invalid in [
        "",
        "h:short",
        "w:abcdefghijklmnopqrstuv",
        "h:abcdefghijklmnopqrstu!",
    ] {
        assert!(!valid_host_file_etag(invalid));
    }
}

#[test]
fn optional_host_fields_cannot_be_spelled_as_null() {
    let f = fixtures();
    for (index, key) in [
        (2, "cwd"),
        (2, "script"),
        (7, "offset"),
        (7, "maxBytes"),
        (9, "expectedEtag"),
        (9, "createOnly"),
    ] {
        let mut frame = f["server"][index].clone();
        frame[key] = Value::Null;
        assert!(parse_server_control(&frame.to_string()).is_err(), "{key}");
    }
    for (index, key) in [(1, "hostCommandMaxMs"), (4, "reason")] {
        let mut frame = f["daemon"][index].clone();
        frame[key] = Value::Null;
        assert!(parse_daemon_control(&frame.to_string()).is_err(), "{key}");
    }
    let mut status = f["daemon"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["type"] == "host.exec.status")
        .unwrap()
        .clone();
    status["exitCode"] = Value::Null;
    assert!(parse_daemon_control(&status.to_string()).is_err());
}
