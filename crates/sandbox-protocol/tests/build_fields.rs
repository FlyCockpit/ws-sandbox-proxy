//! Template-build dispatch fields (D1: root only inside build VMs). The
//! shared fixture `control_build.json` is also consumed by
//! `apps/server/src/sandbox-relay/protocol-build.test.ts`.

use sandbox_protocol::{
    BuildCopyOwnerV11, RunAsV11, ServerControlMessage, build_context_path,
    build_id_of_context_path, capacity_v11::DaemonCapabilitiesV11, encode_server_control,
    parse_server_control,
};

fn fixture() -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("control_build.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("read fixture")).expect("json")
}

#[test]
fn build_fields_match_the_shared_fixture() {
    let fixture = fixture();
    for frame in fixture["server"].as_array().unwrap() {
        let parsed =
            parse_server_control(&frame.to_string()).unwrap_or_else(|e| panic!("{frame}: {e}"));
        // Legacy dispatch fields encode `null`; every build field round-trips.
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
fn build_fields_ride_only_on_their_kind() {
    let fixture = fixture();
    let server = fixture["server"].as_array().unwrap();
    let dispatch = |value: &serde_json::Value| match parse_server_control(&value.to_string()) {
        Ok(ServerControlMessage::OperationDispatch(d)) => d,
        other => panic!("{other:?}"),
    };
    let create = dispatch(&server[0]);
    assert_eq!(create.kind, "sandbox.create");
    assert_eq!(create.build.as_ref().unwrap().build_id, "build-1");
    let run = dispatch(&server[1]);
    assert_eq!(run.run_as, Some(RunAsV11::Root));
    assert!(run.build_copy.is_none() && run.build.is_none());
    let copy = dispatch(&server[2]);
    let body = copy.build_copy.as_ref().unwrap();
    assert_eq!(body.owner, BuildCopyOwnerV11::User);
    assert!(copy.run_as.is_none() && copy.argv.is_none() && copy.script.is_none());
    // Every other dispatch kind refuses each field, even when otherwise valid.
    for kind in sandbox_protocol::ALLOWED_HOST_DISPATCH_KINDS {
        for (field, value, allowed) in [
            (
                "build",
                serde_json::json!({"buildId": "build-1"}),
                "sandbox.create",
            ),
            ("runAs", serde_json::json!("root"), "command.run"),
            ("buildCopy", server[2]["buildCopy"].clone(), "command.run"),
        ] {
            if *kind == allowed {
                continue;
            }
            let mut frame = serde_json::json!({
                "type": "operation.dispatch", "sandboxOwnerId": "owner",
                "operationId": "op", "sandboxId": "sbx", "idempotencyKey": "k",
                "kind": kind, "generation": 1, "attempt": 1,
            });
            frame[field] = value;
            assert!(
                parse_server_control(&frame.to_string()).is_err(),
                "{field} accepted on {kind}"
            );
        }
    }
}

#[test]
fn absent_build_fields_are_omitted() {
    let frame = serde_json::json!({
        "type": "operation.dispatch", "sandboxOwnerId": "owner", "operationId": "op",
        "sandboxId": "sbx", "idempotencyKey": "k", "kind": "command.run",
        "generation": 1, "attempt": 1, "argv": ["true"],
    });
    let parsed = parse_server_control(&frame.to_string()).unwrap();
    let text = encode_server_control(&parsed).unwrap();
    for key in ["build", "runAs", "buildCopy"] {
        assert!(!text.contains(&format!("\"{key}\"")), "{text}");
    }
}

#[test]
fn context_paths_have_one_fixed_shape() {
    assert_eq!(
        build_context_path("build-1").as_deref(),
        Some("/var/tmp/wssp-build/build-1/context.tar")
    );
    assert_eq!(build_context_path("../x"), None);
    assert_eq!(
        build_id_of_context_path("/var/tmp/wssp-build/build-1/context.tar"),
        Some("build-1")
    );
    for bad in [
        "/var/tmp/wssp-build/context.tar",
        "/var/tmp/wssp-build//context.tar",
        "/var/tmp/wssp-build/a/b/context.tar",
        "/var/tmp/wssp-build/../context.tar",
        "/var/tmp/wssp-buildx/a/context.tar",
        "var/tmp/wssp-build/a/context.tar",
    ] {
        assert_eq!(build_id_of_context_path(bad), None, "{bad}");
    }
}

#[test]
fn build_capabilities_require_capture_and_build() {
    let fixture = fixture();
    let hello_caps = |image: &serde_json::Value| {
        let mut caps = serde_json::from_str::<serde_json::Value>(include_str!(
            "../fixtures/control_hello_daemon.json"
        ))
        .unwrap()["daemon"]["capabilities"]
            .clone();
        caps["image"] = image.clone();
        caps
    };
    for image in fixture["capabilities"].as_array().unwrap() {
        let parsed: DaemonCapabilitiesV11 =
            serde_json::from_value(hello_caps(image)).unwrap_or_else(|e| panic!("{image}: {e}"));
        assert_eq!(&serde_json::to_value(parsed.image.unwrap()).unwrap(), image);
    }
    for image in fixture["rejectedCapabilities"].as_array().unwrap() {
        assert!(
            serde_json::from_value::<DaemonCapabilitiesV11>(hello_caps(image)).is_err(),
            "{image}"
        );
    }
}

#[test]
fn upstream_image_bodies_match_the_shared_fixture() {
    let fixture = fixture();
    for body in fixture["upstreamImage"]["valid"].as_array().unwrap() {
        let parsed: sandbox_protocol::DispatchImageV11 =
            serde_json::from_value(body.clone()).unwrap_or_else(|e| panic!("{body}: {e}"));
        assert!(parsed.is_valid(), "{body}");
        assert_eq!(&serde_json::to_value(&parsed).unwrap(), body);
    }
    for body in fixture["upstreamImage"]["rejected"].as_array().unwrap() {
        let accepted = serde_json::from_value::<sandbox_protocol::DispatchImageV11>(body.clone())
            .is_ok_and(|parsed| parsed.is_valid());
        assert!(!accepted, "{body}");
    }
}

/// Community bases: an upstream image plan rides only on a create whose
/// build carries `bootstrap`; `bootstrap` alone (image already cached) is
/// fine, and it never rides anywhere but a create.
#[test]
fn an_upstream_plan_requires_a_bootstrap_build_create() {
    let fixture = fixture();
    let server = fixture["server"].as_array().unwrap();
    let dispatch = |value: &serde_json::Value| match parse_server_control(&value.to_string()) {
        Ok(ServerControlMessage::OperationDispatch(d)) => d,
        other => panic!("{other:?}"),
    };
    let upstream = dispatch(&server[4]);
    assert!(upstream.build.as_ref().unwrap().bootstrap);
    let image = upstream.image.as_ref().unwrap();
    let plan = image.upstream.as_ref().unwrap();
    assert_eq!(image.size_bytes, plan.meta_size + plan.disk_size);
    let cached = dispatch(&server[5]);
    assert!(cached.build.as_ref().unwrap().bootstrap && cached.image.is_none());
    // Without bootstrap, or without the build, the same plan is refused on
    // encode as on parse.
    let mut frame = server[4].clone();
    frame["build"] = serde_json::json!({"buildId": "build-1"});
    assert!(parse_server_control(&frame.to_string()).is_err());
    let mut parsed = upstream.clone();
    parsed.build.as_mut().unwrap().bootstrap = false;
    assert!(
        encode_server_control(&ServerControlMessage::OperationDispatch(parsed.clone())).is_err()
    );
    parsed.build = None;
    assert!(encode_server_control(&ServerControlMessage::OperationDispatch(parsed)).is_err());
    // A non-bootstrap build omits the key; a unified plan omits `upstream`.
    let plain = encode_server_control(&ServerControlMessage::OperationDispatch(dispatch(
        &server[0],
    )))
    .unwrap();
    assert!(!plain.contains("\"bootstrap\""), "{plain}");
    let mut unified = dispatch(&server[0]);
    unified.image = Some(sandbox_protocol::DispatchImageV11 {
        fingerprint: format!("sha256:{}", "a".repeat(64)),
        size_bytes: 10,
        format: "unified".into(),
        source: "fetch".into(),
        upstream: None,
    });
    let text = encode_server_control(&ServerControlMessage::OperationDispatch(unified)).unwrap();
    assert!(!text.contains("\"upstream\""), "{text}");
}
