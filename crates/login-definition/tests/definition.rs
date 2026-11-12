//! Behaviour beyond the shared vectors: defaults, digest recompute, redaction.

use login_definition::bundle::{BundleFile, BundleFileKind};
use login_definition::canonical::{DOCUMENT_TOO_LARGE, definition_digest};
use login_definition::definition::{Rotates, Sharing};
use login_definition::limits::DOCUMENT_TEXT_MAX_BYTES;
use login_definition::{
    Bundle, BundleEnv, DefinitionErrorCode, decode_bundle, encode_bundle, load_verified_definition,
    missing_required_paths, parse_definition, parse_definition_str, serialize_bundle_unchecked,
};
use serde_json::{Value, json};

fn minimal() -> Value {
    json!({
        "schemaVersion": 1,
        "id": "tool",
        "displayName": "Tool",
        "login": { "command": "tool login", "method": "device-code" },
        "credentials": {
            "files": { "required": [".tool/auth.json"], "optional": [".tool/extra"] },
            "env": [{ "name": "B_TOKEN", "required": false }, { "name": "A_TOKEN", "required": true }],
            "maxBytes": 64
        }
    })
}

#[test]
fn defaults_apply() {
    let parsed = parse_definition(&json!({
        "schemaVersion": 1.0,
        "id": "t",
        "displayName": "T",
        "login": { "command": "x", "method": "paste" },
        "credentials": { "env": [{ "name": "A", "required": true }] }
    }))
    .unwrap();
    let d = parsed.definition;
    assert!(d.login.done_when_command_exits);
    assert_eq!(d.credentials.sharing, Sharing::Exclusive);
    assert_eq!(d.credentials.rotates, Rotates::Unknown);
    assert_eq!(d.credentials.max_bytes(), 1_048_576);
}

#[test]
fn stored_document_must_match_its_digest() {
    let document = minimal();
    let pinned = definition_digest(&document).unwrap();
    assert!(load_verified_definition(&document, &pinned).is_ok());
    let mut tampered = minimal();
    tampered["credentials"]["files"]["required"] = json!([".ssh/id_ed25519"]);
    let error = load_verified_definition(&tampered, &pinned).unwrap_err();
    assert_eq!(error.code, DefinitionErrorCode::Corrupt);
    let mut annotated = minimal();
    annotated["x-note"] = json!("changed");
    assert_eq!(
        load_verified_definition(&annotated, &pinned)
            .unwrap_err()
            .code,
        DefinitionErrorCode::Corrupt
    );
}

#[test]
fn bundles_are_canonical_and_redacted() {
    let definition = parse_definition(&minimal()).unwrap().definition;
    let digest = [7u8; 32];
    let secret: &[u8] = b"s3cr3t-value";
    let with_nul = [secret, b"\0"].concat();
    let bundle = Bundle {
        definition_digest: digest,
        files: vec![
            BundleFile {
                kind: BundleFileKind::File,
                path: ".tool/extra/b",
                mode: 0o755,
                data: b"b",
            },
            BundleFile {
                kind: BundleFileKind::Dir,
                path: ".tool/extra",
                mode: 0o750,
                data: &[],
            },
            BundleFile {
                kind: BundleFileKind::File,
                path: ".tool/auth.json",
                mode: 0o640,
                data: secret,
            },
        ],
        env: vec![
            BundleEnv {
                name: "B_TOKEN",
                value: b"b",
            },
            BundleEnv {
                name: "A_TOKEN",
                value: secret,
            },
        ],
    };
    let encoded = encode_bundle(&bundle, &definition).unwrap();
    assert!(!format!("{encoded:?}").contains("s3cr3t"));
    let bytes = encoded.as_bytes();
    assert_eq!(&bytes[..4], b"WSCB");
    assert_eq!(&bytes[37..41], &[0, 3, 0, 2]);
    let decoded = decode_bundle(bytes, &definition, &digest).unwrap();
    let modes: Vec<u16> = decoded.files.iter().map(|f| f.mode).collect();
    assert_eq!(modes, vec![0o600, 0o700, 0o700]);
    let names: Vec<&str> = decoded.env.iter().map(|e| e.name).collect();
    assert_eq!(names, vec!["A_TOKEN", "B_TOKEN"]);
    let debug = format!("{decoded:?}");
    assert!(
        !debug.contains("s3cr3t"),
        "Debug must not print values: {debug}"
    );
    assert!(missing_required_paths(&decoded, &definition).is_empty());

    let mut partial = decoded.clone();
    partial.files.remove(0);
    assert_eq!(
        missing_required_paths(&partial, &definition),
        vec![".tool/auth.json"]
    );

    let nul = Bundle {
        definition_digest: digest,
        files: vec![],
        env: vec![BundleEnv {
            name: "A_TOKEN",
            value: &with_nul,
        }],
    };
    let error = decode_bundle(
        serialize_bundle_unchecked(&nul).as_bytes(),
        &definition,
        &digest,
    )
    .unwrap_err();
    assert_eq!(error.reason.as_str(), "env_value_nul");
    assert!(!error.to_string().contains("s3cr3t"));
}

#[test]
fn oversize_documents_fail_at_the_byte_budget() {
    // 50 000 strings of 10 bytes pass the cheap container bound (2n + 1 bytes)
    // but need ~650 KB. The fraction at the end is never reached: the walk
    // stops at the budget instead of materializing everything first.
    let mut items: Vec<Value> = (0..50_000).map(|_| json!("0123456789")).collect();
    items.push(json!(1.5));
    let mut document = minimal();
    document["x-probe"] = Value::Array(items);
    let error = parse_definition(&document).unwrap_err();
    assert_eq!(error.code, DefinitionErrorCode::Invalid);
    assert_eq!(error.issues[0].path, "");
    assert_eq!(error.issues[0].message, DOCUMENT_TOO_LARGE);

    // Containers and strings too large to fit are refused before they are walked.
    let mut huge = minimal();
    huge["x-probe"] = json!("p".repeat(64 << 20));
    assert_eq!(
        parse_definition(&huge).unwrap_err().issues[0].message,
        DOCUMENT_TOO_LARGE
    );
    let mut wide = minimal();
    wide["x-probe"] = Value::Array(vec![json!(0); 1 << 20]);
    assert_eq!(
        parse_definition(&wide).unwrap_err().issues[0].message,
        DOCUMENT_TOO_LARGE
    );

    // A stored document past the bound can never match a digest.
    assert_eq!(
        load_verified_definition(&huge, &[0; 32]).unwrap_err().code,
        DefinitionErrorCode::Corrupt
    );
}

#[test]
fn oversize_text_is_refused_before_parsing() {
    // Not JSON at all: refused for its size, so the parser never ran.
    let text = format!("{{{}", " ".repeat(DOCUMENT_TEXT_MAX_BYTES));
    let error = parse_definition_str(&text).unwrap_err();
    assert_eq!(
        error.issues[0].message,
        format!("definition text exceeds {DOCUMENT_TEXT_MAX_BYTES} bytes")
    );
    // The bound is in UTF-8 bytes: 3-byte characters count three times.
    let text = "€".repeat(DOCUMENT_TEXT_MAX_BYTES / 3 + 1);
    assert!(
        parse_definition_str(&text).unwrap_err().issues[0]
            .message
            .starts_with("definition text exceeds")
    );
}

#[test]
fn parse_reports_the_digest_it_canonicalized() {
    let document = minimal();
    let parsed = parse_definition(&document).unwrap();
    assert_eq!(parsed.digest, definition_digest(&document).unwrap());
    let loaded = load_verified_definition(&document, &parsed.digest).unwrap();
    assert_eq!(loaded.digest, parsed.digest);
}
