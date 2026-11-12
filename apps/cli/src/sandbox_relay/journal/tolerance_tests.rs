//! Current journal extension and error-code preservation, with exact-byte checksums.
use super::*;
use sandbox_protocol::{WIRE_ERROR_CODE_MAX_BYTES, WireErrorCode};
use serde_json::json;
use std::net::{TcpListener, TcpStream};

fn binding() -> TransportBindingV11 {
    TransportBindingV11 {
        server: "wss://api.example".into(),
        host_owner_id: "owner-1".into(),
        host_id: "host-1".into(),
    }
}

fn open(dir: &Path) -> Result<HostJournal> {
    crate::sandbox_relay::test_support::open_journal(dir, &binding())
}

fn opaque_ext() -> JournalExt {
    // Nested keys exercise a stored ordering different from reserialization.
    [
        ("carryAnchor".to_owned(), json!({"z": 1, "a": [1, 2.5]})),
        ("hint".to_owned(), json!("x")),
    ]
    .into_iter()
    .collect()
}

fn other(code: &str) -> WireErrorCode {
    WireErrorCode::Other(code.into())
}

/// Store a record with a checksum over its exact serialized bytes.
fn write_raw_envelope(path: &Path, field: &str, record: &str, checksum: &str) {
    let text = format!(r#"{{"{field}":{record},"checksum":"{checksum}"}}"#);
    fs::write(path, text).unwrap();
}

fn stored_receipt_text(dir: &Path, id: &str) -> String {
    let envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join(format!("receipts/{id}.json"))).unwrap())
            .unwrap();
    serde_json::to_string(&envelope["receipt"]).unwrap()
}

fn sockets() -> (
    tungstenite::WebSocket<tungstenite::stream::MaybeTlsStream<TcpStream>>,
    tungstenite::WebSocket<TcpStream>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    (
        tungstenite::WebSocket::from_raw_socket(
            tungstenite::stream::MaybeTlsStream::Plain(tcp),
            tungstenite::protocol::Role::Client,
            None,
        ),
        tungstenite::WebSocket::from_raw_socket(peer, tungstenite::protocol::Role::Server, None),
    )
}

#[test]
fn receipt_extensions_and_other_error_codes_survive_rewrite_and_replay() {
    let dir = tempfile::tempdir().unwrap();
    let journal = open(dir.path()).unwrap();
    let mut intent = super::tests::receipt("next", 1);
    intent.ext = opaque_ext();
    intent.file_put = None;
    journal.record_intent(&intent).unwrap();
    drop(journal);

    // Field order and extension ordering are protected by the byte checksum.
    let path = dir.path().join("receipts/next.json");
    let mut value: serde_json::Value =
        serde_json::from_str(&stored_receipt_text(dir.path(), "next")).unwrap();
    value["ext"] = json!({"hint": "x", "carryAnchor": {"z": 1, "a": [1, 2.5]}});
    let raw = serde_json::to_string(&value).unwrap();
    let reserialized: HostReceipt = serde_json::from_str(&raw).unwrap();
    assert_ne!(
        sha256_hex(raw.as_bytes()),
        sha256_hex(&serde_json::to_vec(&reserialized).unwrap()),
        "fixture must exercise the raw-byte checksum"
    );
    write_raw_envelope(&path, "receipt", &raw, &sha256_hex(raw.as_bytes()));

    // Every subsequent effect and result rewrite preserves extensions.
    let journal = open(dir.path()).unwrap();
    assert_eq!(journal.lookup("next").unwrap().ext, opaque_ext());
    journal.record_effect("next").unwrap();
    journal
        .record_result_with_reason(
            "next",
            OperationState::Failed,
            None,
            (Some(other("future_code")), Some("newer".into()), None),
        )
        .unwrap();
    drop(journal);
    let journal = open(dir.path()).unwrap();
    let stored = journal.lookup("next").unwrap();
    assert_eq!(stored.ext, opaque_ext());
    assert_eq!(stored.error_code, Some(other("future_code")));
    assert!(stored.is_terminal(), "an Other code is a terminal failure");
    assert_eq!(stored.error_reason(), None);
    let journaled = stored_receipt_text(dir.path(), "next");
    assert!(journaled.contains(r#""errorCode":"future_code""#));

    // The replayed receipt carries the journaled code byte-identically.
    let (mut socket, mut wire) = sockets();
    crate::sandbox_relay::reconcile::send_receipt(
        &mut socket,
        sandbox_protocol::WireCodes::CURRENT,
        stored,
    )
    .unwrap();
    let frame = wire.read().unwrap();
    let text = frame.to_text().unwrap();
    assert!(text.contains(r#""code":"future_code""#), "{text}");
    let sent: serde_json::Value = serde_json::from_str(text).unwrap();
    let journaled: serde_json::Value = serde_json::from_str(&journaled).unwrap();
    assert_eq!(sent["error"]["code"], journaled["errorCode"]);
    match sandbox_protocol::parse_daemon_control(text).unwrap() {
        sandbox_protocol::DaemonControlMessage::OperationReceipt {
            error: Some(error), ..
        } => assert_eq!(error.code, other("future_code")),
        message => panic!("unexpected {message:?}"),
    }
}

#[test]
fn receipt_checksum_requires_the_exact_stored_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let journal = open(dir.path()).unwrap();
    journal
        .record_intent(&super::tests::receipt("sum", 1))
        .unwrap();
    drop(journal);
    let path = dir.path().join("receipts/sum.json");
    let value: serde_json::Value =
        serde_json::from_str(&stored_receipt_text(dir.path(), "sum")).unwrap();
    // Pretty, key-sorted bytes: raw and re-serialized hashes differ.
    let raw = serde_json::to_string_pretty(&value).unwrap();
    let parsed: HostReceipt = serde_json::from_str(&raw).unwrap();
    let reserialized = sha256_hex(&serde_json::to_vec(&parsed).unwrap());
    let raw_sum = sha256_hex(raw.as_bytes());
    assert_ne!(raw_sum, reserialized);
    for (checksum, ok) in [
        (raw_sum.as_str(), true),
        (reserialized.as_str(), false),
        (&*"0".repeat(64), false),
    ] {
        write_raw_envelope(&path, "receipt", &raw, checksum);
        let opened = open(dir.path());
        assert_eq!(opened.is_ok(), ok, "{checksum}");
        if let Ok(journal) = opened {
            assert_eq!(journal.lookup("sum").unwrap().operation_id, "sum");
        }
    }
}

#[test]
fn cleanup_watermark_requires_exact_bytes_and_preserves_extensions() {
    let dir = tempfile::tempdir().unwrap();
    let journal = open(dir.path()).unwrap();
    let cleanups_dir = journal.cleanups_dir.clone();
    drop(journal);
    let watermark = CleanupWatermark {
        version: JOURNAL_VERSION,
        binding: binding(),
        sandbox_owner_id: "owner".into(),
        sandbox_id: "sbx".into(),
        generation: 3,
        instance_absent: false,
        ext: opaque_ext(),
    };
    persist_cleanup(&IoLatch::default(), &cleanups_dir, &watermark).unwrap();
    let loaded = load_cleanups(&cleanups_dir).unwrap();
    assert_eq!(loaded["sbx"].ext, opaque_ext());

    let path = cleanups_dir.join(cleanup_file_name("sbx"));
    let mut value = serde_json::to_value(&watermark).unwrap();
    value["ext"] = json!({"hint": "x", "carryAnchor": {"z": 1, "a": [1, 2.5]}});
    let raw = serde_json::to_string_pretty(&value).unwrap();
    let parsed: CleanupWatermark = serde_json::from_str(&raw).unwrap();
    let reserialized = sha256_hex(&serde_json::to_vec(&parsed).unwrap());
    let raw_sum = sha256_hex(raw.as_bytes());
    assert_ne!(raw_sum, reserialized);
    for (checksum, ok) in [
        (raw_sum.as_str(), true),
        (reserialized.as_str(), false),
        (&*"0".repeat(64), false),
    ] {
        write_raw_envelope(&path, "watermark", &raw, checksum);
        let loaded = load_cleanups(&cleanups_dir);
        assert_eq!(loaded.is_ok(), ok, "{checksum}");
        if let Ok(loaded) = loaded {
            assert_eq!(loaded["sbx"].ext, opaque_ext());
            assert_eq!(loaded["sbx"].generation, 3);
        }
    }
}

#[test]
fn corrupt_ext_or_invalid_other_code_still_bails() {
    let many: serde_json::Map<String, serde_json::Value> = (0..=EXT_MAX_KEYS)
        .map(|i| (format!("k{i}"), json!(i)))
        .collect();
    let cases = [
        ("ext", json!(5)),
        ("ext", json!(["not", "an", "object"])),
        ("ext", json!({"Bad-Key": 1})),
        ("ext", json!({"": 1})),
        ("ext", json!({"big": "x".repeat(EXT_MAX_BYTES)})),
        ("ext", serde_json::Value::Object(many)),
        ("errorCode", json!("Bad-Code")),
        ("errorCode", json!("digit1")),
        (
            "errorCode",
            json!("x".repeat(WIRE_ERROR_CODE_MAX_BYTES + 1)),
        ),
        ("errorCode", json!("")),
        ("errorCode", json!(7)),
    ];
    for (field, bad) in cases {
        let dir = tempfile::tempdir().unwrap();
        let journal = open(dir.path()).unwrap();
        journal
            .record_intent(&super::tests::receipt("bad", 1))
            .unwrap();
        drop(journal);
        let mut value: serde_json::Value =
            serde_json::from_str(&stored_receipt_text(dir.path(), "bad")).unwrap();
        value[field] = bad.clone();
        let raw = serde_json::to_string(&value).unwrap();
        write_raw_envelope(
            &dir.path().join("receipts/bad.json"),
            "receipt",
            &raw,
            &sha256_hex(raw.as_bytes()),
        );
        assert!(open(dir.path()).is_err(), "{field}={bad}");
    }
    // A well-formed `ext` and Other code in the same position open fine.
    let dir = tempfile::tempdir().unwrap();
    let journal = open(dir.path()).unwrap();
    journal
        .record_intent(&super::tests::receipt("good", 1))
        .unwrap();
    drop(journal);
    let mut value: serde_json::Value =
        serde_json::from_str(&stored_receipt_text(dir.path(), "good")).unwrap();
    value["ext"] = json!({"hint": "x"});
    value["errorCode"] = json!("x".repeat(WIRE_ERROR_CODE_MAX_BYTES));
    let raw = serde_json::to_string(&value).unwrap();
    write_raw_envelope(
        &dir.path().join("receipts/good.json"),
        "receipt",
        &raw,
        &sha256_hex(raw.as_bytes()),
    );
    assert!(open(dir.path()).is_ok());

    // A watermark with a corrupt `ext` bails too.
    let dir = tempfile::tempdir().unwrap();
    let journal = open(dir.path()).unwrap();
    let cleanups_dir = journal.cleanups_dir.clone();
    drop(journal);
    let mut value = serde_json::to_value(CleanupWatermark {
        version: JOURNAL_VERSION,
        binding: binding(),
        sandbox_owner_id: "owner".into(),
        sandbox_id: "sbx".into(),
        generation: 3,
        instance_absent: false,
        ext: JournalExt::new(),
    })
    .unwrap();
    persist_cleanup(
        &IoLatch::default(),
        &cleanups_dir,
        &serde_json::from_value(value.clone()).unwrap(),
    )
    .unwrap();
    for bad in [json!(5), json!({"Bad-Key": 1})] {
        value["ext"] = bad.clone();
        let raw = serde_json::to_string(&value).unwrap();
        write_raw_envelope(
            &cleanups_dir.join(cleanup_file_name("sbx")),
            "watermark",
            &raw,
            &sha256_hex(raw.as_bytes()),
        );
        assert!(load_cleanups(&cleanups_dir).is_err(), "{bad}");
    }
}

#[test]
fn watermark_ext_survives_same_generation_rewrite_and_resets_on_new_generation() {
    let dir = tempfile::tempdir().unwrap();
    let journal = open(dir.path()).unwrap();
    let seeded = CleanupWatermark {
        version: JOURNAL_VERSION,
        binding: binding(),
        sandbox_owner_id: "owner".into(),
        sandbox_id: "sbx-1".into(),
        generation: 2,
        instance_absent: false,
        ext: opaque_ext(),
    };
    persist_cleanup(&journal.io, &journal.cleanups_dir, &seeded).unwrap();
    journal
        .state
        .lock()
        .unwrap()
        .cleanups
        .insert("sbx-1".into(), seeded);
    let settle = |id: &str, kind: &str, generation: u64, end: &str| {
        let mut r = super::tests::receipt(id, 1);
        r.kind = kind.into();
        r.generation = generation;
        journal.record_intent(&r).unwrap();
        journal
            .record_result(
                id,
                OperationState::Succeeded,
                Some(json!({"state": end})),
                None,
                None,
            )
            .unwrap();
        assert!(
            journal
                .confirm(&binding(), &super::tests::confirmation(&r))
                .unwrap()
        );
        journal.state.lock().unwrap().cleanups["sbx-1"].clone()
    };
    // Same generation (instance_absent flips): a rewrite keeps `ext`.
    let same = settle("kill", "sandbox.kill", 2, "deleted");
    assert_eq!((same.generation, same.instance_absent), (2, true));
    assert_eq!(same.ext, opaque_ext());
    // A new generation starts with an empty `ext`, durably.
    let next = settle("stop", "sandbox.stop", 3, "stopped");
    assert_eq!(next.generation, 3);
    assert!(next.ext.is_empty());
    assert!(
        load_cleanups(&journal.cleanups_dir).unwrap()["sbx-1"]
            .ext
            .is_empty()
    );
}
