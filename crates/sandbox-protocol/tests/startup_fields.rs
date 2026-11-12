//! Template start/ready dispatch field (B9). The shared fixture
//! `control_startup.json` is also consumed by
//! `apps/server/src/sandbox-relay/protocol-startup.test.ts`.

use sandbox_protocol::{ServerControlMessage, encode_server_control, parse_server_control};

fn fixture() -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("control_startup.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("read fixture")).expect("json")
}

#[test]
fn startup_matches_the_shared_fixture() {
    let fixture = fixture();
    for frame in fixture["server"].as_array().unwrap() {
        let parsed =
            parse_server_control(&frame.to_string()).unwrap_or_else(|e| panic!("{frame}: {e}"));
        let mut value = serde_json::to_value(&parsed).unwrap();
        value.as_object_mut().unwrap().retain(|_, v| !v.is_null());
        assert_eq!(&value, frame);
        assert!(encode_server_control(&parsed).is_ok(), "{frame}");
    }
    for frame in fixture["rejectedServer"].as_array().unwrap() {
        assert!(parse_server_control(&frame.to_string()).is_err(), "{frame}");
    }
}

#[test]
fn startup_rides_only_on_launches() {
    let fixture = fixture();
    let create = match parse_server_control(&fixture["server"][0].to_string()) {
        Ok(ServerControlMessage::OperationDispatch(d)) => d,
        other => panic!("{other:?}"),
    };
    let startup = create.startup.as_ref().unwrap();
    assert_eq!(startup.command, "npm start");
    assert_eq!(startup.ready_budget_ms(), Some(60_000));
    let reconnect = match parse_server_control(&fixture["server"][1].to_string()) {
        Ok(ServerControlMessage::OperationDispatch(d)) => d,
        other => panic!("{other:?}"),
    };
    assert_eq!(reconnect.kind, "sandbox.reconnect");
    assert_eq!(reconnect.startup.as_ref().unwrap().ready_budget_ms(), None);
    for kind in sandbox_protocol::ALLOWED_HOST_DISPATCH_KINDS {
        if matches!(*kind, "sandbox.create" | "sandbox.reconnect") {
            continue;
        }
        let frame = serde_json::json!({
            "type": "operation.dispatch", "sandboxOwnerId": "owner",
            "operationId": "op", "sandboxId": "sbx", "idempotencyKey": "k",
            "kind": kind, "generation": 1, "attempt": 1,
            "startup": {"command": "npm start"},
        });
        assert!(
            parse_server_control(&frame.to_string()).is_err(),
            "startup accepted on {kind}"
        );
    }
}

#[test]
fn template_startup_capability_is_omitted_when_false() {
    let caps = sandbox_protocol::DaemonCapabilities::default();
    assert!(
        !serde_json::to_value(&caps)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("templateStartup")
    );
    let caps = sandbox_protocol::DaemonCapabilities {
        template_startup: true,
        ..caps
    };
    assert_eq!(
        serde_json::to_value(&caps).unwrap()["templateStartup"],
        true
    );
}
