//! Disk offload wire. The shared fixture
//! `control_disk.json` is also consumed by
//! `apps/server/src/sandbox-relay/protocol-disk.test.ts`.

use sandbox_protocol::{
    DaemonCapabilities, DaemonControlMessage, LaunchMode, ServerControlMessage, WireCodes,
    encode_server_control, parse_daemon_control, parse_server_control,
};

fn fixture(name: &str) -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).expect("read fixture")).expect("json")
}

fn without_nulls(mut value: serde_json::Value) -> serde_json::Value {
    if let Some(object) = value.as_object_mut() {
        object.retain(|_, v| !v.is_null());
    }
    value
}

fn daemon_value(frame: &DaemonControlMessage) -> serde_json::Value {
    let text = WireCodes::negotiated("1.0")
        .encode(frame, None)
        .unwrap()
        .text;
    serde_json::from_str(&text).unwrap()
}

#[test]
fn disk_frames_match_the_shared_fixture() {
    let fixture = fixture("control_disk.json");
    for frame in fixture["daemon"].as_array().unwrap() {
        let parsed =
            parse_daemon_control(&frame.to_string()).unwrap_or_else(|e| panic!("{frame}: {e}"));
        assert_eq!(&daemon_value(&parsed), frame);
    }
    for frame in fixture["server"].as_array().unwrap() {
        let parsed =
            parse_server_control(&frame.to_string()).unwrap_or_else(|e| panic!("{frame}: {e}"));
        let encoded: serde_json::Value =
            serde_json::from_str(&encode_server_control(&parsed).unwrap()).unwrap();
        // Dispatches serialize their legacy optional fields as null.
        assert_eq!(&without_nulls(encoded), frame);
        // The disk grant's key and URLs never reach Debug output.
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
fn restore_dispatch_carries_its_fields_and_guest_privilege() {
    let fixture = fixture("control_disk.json");
    let restore = fixture["server"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f.get("restore").is_some())
        .unwrap();
    let ServerControlMessage::OperationDispatch(d) =
        parse_server_control(&restore.to_string()).unwrap()
    else {
        panic!("dispatch");
    };
    assert_eq!(d.kind, "sandbox.reconnect");
    assert_eq!(d.launch_mode, Some(LaunchMode::NewRoot));
    let r = d.restore.as_ref().unwrap();
    assert_eq!((r.offload_id.as_str(), r.seq), ("off-1", 1));
    assert_eq!(d.image.as_ref().unwrap().fingerprint, r.fingerprint);
    assert_eq!(
        d.disk_base_fingerprint.as_deref(),
        Some(r.fingerprint.as_str())
    );
    // §4a: the restore dispatch carries guest privilege from the sandbox row.
    assert_eq!((d.guest_sudo, d.guest_root), (Some(true), Some(true)));
    assert!(sandbox_protocol::dispatch_has_disk_fields(&d));
}

/// I10: a reconnect without disk fields omits them from its encoding, and an
/// explicit null is not a second spelling.
#[test]
fn reconnect_without_disk_fields_is_byte_identical() {
    let fixture = fixture("control_startup.json");
    let reconnect = fixture["server"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["kind"] == "sandbox.reconnect")
        .unwrap();
    let parsed = parse_server_control(&reconnect.to_string()).unwrap();
    let ServerControlMessage::OperationDispatch(d) = &parsed else {
        panic!("dispatch");
    };
    assert!(!sandbox_protocol::dispatch_has_disk_fields(d));
    let text = encode_server_control(&parsed).unwrap();
    for key in [
        "\"restore\"",
        "\"launchMode\"",
        "\"expectDisk\"",
        "\"diskBaseFingerprint\"",
    ] {
        assert!(!text.contains(key), "{key} in {text}");
    }
    let encoded: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(&without_nulls(encoded), reconnect);
    for key in ["restore", "launchMode", "expectDisk", "diskBaseFingerprint"] {
        let mut frame = reconnect.clone();
        frame[key] = serde_json::Value::Null;
        assert!(parse_server_control(&frame.to_string()).is_err(), "{key}");
    }
}

#[test]
fn receipts_without_launch_mode_are_unchanged() {
    let fixture = fixture("control_disk.json");
    let mut receipt = fixture["daemon"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["type"] == "operation.receipt")
        .unwrap()
        .clone();
    receipt.as_object_mut().unwrap().remove("launchMode");
    let parsed = parse_daemon_control(&receipt.to_string()).unwrap();
    assert!(
        !WireCodes::negotiated("1.0")
            .encode(&parsed, None)
            .unwrap()
            .text
            .contains("launchMode")
    );
    receipt["launchMode"] = serde_json::Value::Null;
    assert!(parse_daemon_control(&receipt.to_string()).is_err());
}

#[test]
fn disk_offload_capability_is_omitted_when_false_and_requires_image_fetch() {
    let caps = DaemonCapabilities::default();
    assert!(
        serde_json::to_value(&caps)
            .unwrap()
            .get("diskOffload")
            .is_none()
    );
    let hello = fixture("control_hello_daemon.json");
    assert!(parse_daemon_control(&hello.to_string()).is_ok());
    let with = |image: Option<serde_json::Value>| {
        let mut hello = hello.clone();
        let caps = &mut hello["daemon"]["capabilities"];
        caps["diskOffload"] = serde_json::Value::Bool(true);
        match image {
            Some(image) => caps["image"] = image,
            None => {
                caps.as_object_mut().unwrap().remove("image");
            }
        }
        parse_daemon_control(&hello.to_string())
    };
    let image = |fetch: bool| {
        serde_json::json!({"fetch": fetch, "serve": false, "publish": false, "capture": false,
            "acceptForeign": false, "leaseFromReady": false, "formats": ["unified"]})
    };
    let parsed = with(Some(image(true))).expect("diskOffload with image.fetch");
    let DaemonControlMessage::Hello { daemon, .. } = parsed else {
        panic!("hello");
    };
    assert!(daemon.capabilities.disk_offload);
    assert!(with(Some(image(false))).is_err());
    assert!(with(None).is_err());
}
