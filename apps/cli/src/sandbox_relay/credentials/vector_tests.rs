//! Cross-language vectors shared with `packages/api/src/credentials/vault`
//! (every key in them is a fixed TEST value). Rust must reproduce each TS seal
//! and envelope byte for byte from the same (ephemeral, nonce) draws, and open
//! them; the TS suite does the same for the bytes Rust produces here.

use serde::Deserialize;

use super::envelope;
use super::seal::{ReturnAad, ReturnPublicKey, SEAL_OVERHEAD, SealError, seal, testing};

const VECTORS: &str =
    include_str!("../../../../../packages/api/src/credentials/vault/fixtures/seal-v1.json");

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Recipient {
    private_key: String,
    public_key: String,
    kid_r: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    name: String,
    plaintext: String,
    aad: ReturnAad,
    aad_encoded: String,
    ephemeral_private_key: String,
    ephemeral_public_key: String,
    nonce: String,
    seal: String,
    created_at: u64,
    header_json: String,
    envelope: String,
    envelope_digest: String,
}

#[derive(Deserialize)]
struct NamedKey {
    name: String,
    #[serde(rename = "publicKey")]
    public_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    recipient: Recipient,
    cases: Vec<Case>,
    invalid_public_keys: Vec<NamedKey>,
    low_order_public_keys: Vec<NamedKey>,
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn array<const N: usize>(text: &str) -> [u8; N] {
    unhex(text).try_into().expect("length")
}

fn vectors() -> Vectors {
    serde_json::from_str(VECTORS).expect("vector file parses")
}

fn recipient(v: &Vectors) -> ([u8; 32], ReturnPublicKey) {
    let key = ReturnPublicKey::parse(&v.recipient.public_key, &v.recipient.kid_r).expect("key");
    (array(&v.recipient.private_key), key)
}

#[test]
fn rust_reproduces_ts_seals_and_envelopes_byte_for_byte() {
    let v = vectors();
    let (_, key) = recipient(&v);
    assert_eq!(key.to_base64url(), v.recipient.public_key);
    assert!(!v.cases.is_empty());
    for case in &v.cases {
        let plaintext = unhex(&case.plaintext);
        assert_eq!(
            case.aad.encode(key.kid_r()).expect("aad"),
            unhex(&case.aad_encoded),
            "{}",
            case.name
        );
        let sealed = testing::seal_deterministic(
            &array(&case.ephemeral_private_key),
            &array(&case.nonce),
            &plaintext,
            &key,
            &case.aad,
        )
        .expect("seal");
        assert_eq!(sealed, unhex(&case.seal), "{}", case.name);
        assert_eq!(
            super::seal::to_base64url(&sealed[..32]),
            case.ephemeral_public_key,
            "{}",
            case.name
        );
        let env = envelope::build(&key, &case.aad, &sealed, case.created_at).expect("envelope");
        assert_eq!(env.bytes, unhex(&case.envelope), "{}", case.name);
        assert_eq!(env.digest_hex(), case.envelope_digest, "{}", case.name);
        assert_eq!(
            serde_json::to_string(&env.header).expect("json"),
            case.header_json,
            "{}",
            case.name
        );
    }
}

#[test]
fn rust_opens_ts_seals_and_parses_ts_envelopes() {
    let v = vectors();
    let (private, key) = recipient(&v);
    for case in &v.cases {
        let opened = testing::open(&private, &key, &unhex(&case.seal), &case.aad).expect("open");
        assert_eq!(
            opened.expose(),
            unhex(&case.plaintext).as_slice(),
            "{}",
            case.name
        );
        let parsed = envelope::parse(unhex(&case.envelope)).expect("parse");
        assert_eq!(parsed.header.aad, case.aad);
        assert_eq!(parsed.seal(), unhex(&case.seal).as_slice());
        assert_eq!(parsed.digest_hex(), case.envelope_digest);
    }
}

#[derive(Deserialize)]
struct ExtraCase {
    name: String,
    plaintext: String,
    envelope: String,
}

#[derive(Deserialize)]
struct ExtraVectors {
    recipient: Recipient,
    cases: Vec<ExtraCase>,
}

/// Envelopes from the end-to-end harness (fresh, randomly sealed TS bundles)
/// when `WSSP_CRED_SEAL_EXTRA_VECTORS` names such a file. Unset in CI.
#[test]
fn rust_opens_extra_ts_vectors_when_provided() {
    let Some(path) = std::env::var_os("WSSP_CRED_SEAL_EXTRA_VECTORS") else {
        return;
    };
    let text = std::fs::read_to_string(path).expect("extra vectors");
    let v: ExtraVectors = serde_json::from_str(&text).expect("extra vectors parse");
    let key = ReturnPublicKey::parse(&v.recipient.public_key, &v.recipient.kid_r).expect("key");
    let private: [u8; 32] = array(&v.recipient.private_key);
    assert!(!v.cases.is_empty());
    for case in &v.cases {
        let parsed = envelope::parse(unhex(&case.envelope)).expect("parse");
        assert_eq!(parsed.header.kid_r, key.kid_r());
        let opened =
            testing::open(&private, &key, parsed.seal(), &parsed.header.aad).expect("open");
        assert_eq!(
            opened.expose(),
            unhex(&case.plaintext).as_slice(),
            "{}",
            case.name
        );
        eprintln!(
            "opened extra vector {} ({} bytes, digest {})",
            case.name,
            opened.len(),
            parsed.digest_hex()
        );
    }
}

#[test]
fn random_seals_round_trip_with_fresh_ephemeral_keys() {
    let v = vectors();
    let (private, key) = recipient(&v);
    let aad = &v.cases[0].aad;
    let a = seal(b"bundle", &key, aad).expect("seal");
    let b = seal(b"bundle", &key, aad).expect("seal");
    assert_eq!(a.len(), 6 + SEAL_OVERHEAD);
    assert_ne!(a[..44], b[..44]);
    let opened = testing::open(&private, &key, &a, aad).expect("open");
    assert_eq!(opened.expose(), b"bundle");
}

#[test]
fn every_aad_field_is_bound() {
    let v = vectors();
    let (private, key) = recipient(&v);
    let case = &v.cases[1];
    let sealed = unhex(&case.seal);
    type Mutation = Box<dyn Fn(&mut ReturnAad)>;
    let mutations: Vec<Mutation> = vec![
        Box::new(|a| a.server_origin.push('x')),
        Box::new(|a| a.host_owner_id.push('x')),
        Box::new(|a| a.host_id.push('x')),
        Box::new(|a| a.sandbox_owner_id.push('x')),
        Box::new(|a| a.sandbox_id.push('x')),
        Box::new(|a| a.lease_id.push('x')),
        Box::new(|a| a.binding_id.push('x')),
        Box::new(|a| a.instance_id.push('x')),
        Box::new(|a| a.credential_id.push('x')),
        Box::new(|a| a.capture_seq += 1),
        Box::new(|a| a.capture_id.push('x')),
        Box::new(|a| a.kind.push('x')),
        Box::new(|a| a.residue_id.push('x')),
    ];
    for (i, mutate) in mutations.iter().enumerate() {
        let mut aad = case.aad.clone();
        mutate(&mut aad);
        assert_eq!(
            testing::open(&private, &key, &sealed, &aad).map(|_| ()),
            Err(SealError::Crypto),
            "field {i}"
        );
    }
}

#[test]
fn wrong_recipient_kid_truncation_and_tamper_fail() {
    let v = vectors();
    let (private, key) = recipient(&v);
    let case = &v.cases[1];
    let sealed = unhex(&case.seal);
    let other_kid = "0000000000000000";
    assert_eq!(
        ReturnPublicKey::parse(&v.recipient.public_key, other_kid),
        Err(SealError::KeyIdMismatch)
    );
    let mut wrong_private = private;
    // Byte 0 bits 0-2 are clamped away by X25519; flip a bit that matters.
    wrong_private[1] ^= 1;
    assert_eq!(
        testing::open(&wrong_private, &key, &sealed, &case.aad).map(|_| ()),
        Err(SealError::KeyIdMismatch)
    );
    assert_eq!(
        testing::open(&private, &key, &sealed[..SEAL_OVERHEAD - 1], &case.aad).map(|_| ()),
        Err(SealError::Malformed)
    );
    assert_eq!(
        testing::open(&private, &key, &sealed[..sealed.len() - 1], &case.aad).map(|_| ()),
        Err(SealError::Crypto)
    );
    for at in [33usize, 44, sealed.len() - 1] {
        let mut copy = sealed.clone();
        copy[at] ^= 0x40;
        assert!(
            testing::open(&private, &key, &copy, &case.aad).is_err(),
            "{at}"
        );
    }
}

#[test]
fn invalid_and_low_order_keys_are_refused() {
    let v = vectors();
    let aad = &v.cases[0].aad;
    for bad in &v.invalid_public_keys {
        let kid = "0000000000000000";
        assert_eq!(
            ReturnPublicKey::parse(&bad.public_key, kid),
            Err(SealError::InvalidKey),
            "{}",
            bad.name
        );
    }
    for low in &v.low_order_public_keys {
        // Canonical encodings, so they load; the X25519 result is all-zero.
        let bytes: [u8; 32] = decode_any(&low.public_key).try_into().expect("32 bytes");
        let recipient = ReturnPublicKey::from_bytes(bytes).expect("canonical");
        assert_eq!(
            seal(b"x", &recipient, aad).map(|_| ()),
            Err(SealError::InvalidKey),
            "{}",
            low.name
        );
    }
}

fn decode_any(text: &str) -> Vec<u8> {
    // Test helper: standard library-free base64url decode for 43-char keys.
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = Vec::new();
    for c in text.bytes() {
        bits = (bits << 6) | A.iter().position(|&a| a == c).expect("alphabet") as u32;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    out
}

#[test]
fn aad_bounds_match_ts() {
    let v = vectors();
    let (_, key) = recipient(&v);
    let base = v.cases[0].aad.clone();
    let mut cases: Vec<ReturnAad> = Vec::new();
    let mut a = base.clone();
    a.capture_seq = 0;
    cases.push(a);
    let mut a = base.clone();
    a.capture_seq = 1 << 63;
    cases.push(a);
    let mut a = base.clone();
    a.kind = "STOP".into();
    cases.push(a);
    let mut a = base.clone();
    a.host_id = String::new();
    cases.push(a);
    let mut a = base.clone();
    a.host_id = "a".repeat(257);
    cases.push(a);
    for aad in cases {
        assert_eq!(
            seal(b"x", &key, &aad).map(|_| ()),
            Err(SealError::InvalidAad)
        );
    }
    let mut max = base;
    max.capture_seq = i64::MAX as u64;
    assert!(seal(b"x", &key, &max).is_ok());
}

#[test]
fn envelope_parse_refuses_non_canonical_and_mismatched_input() {
    let v = vectors();
    let case = &v.cases[1];
    let good = unhex(&case.envelope);
    let seal_bytes = unhex(&case.seal);
    let mutate = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut copy = good.clone();
        f(&mut copy);
        envelope::parse(copy).map(|_| ())
    };
    assert_eq!(mutate(&|b| b[0] = b'X'), Err(SealError::Malformed));
    assert_eq!(mutate(&|b| b[4] = 2), Err(SealError::Malformed));
    assert_eq!(
        mutate(&|b| b[5..9].copy_from_slice(&4097u32.to_be_bytes())),
        Err(SealError::Malformed)
    );
    assert_eq!(
        mutate(&|b| {
            b.pop();
        }),
        Err(SealError::Malformed)
    );
    assert_eq!(mutate(&|b| b.push(0)), Err(SealError::Malformed));
    assert_eq!(
        mutate(&|b| {
            let last = b.len() - 1;
            b[last] ^= 1;
        }),
        Err(SealError::Malformed)
    );
    let json = &case.header_json;
    let respelled = [
        json.replacen("{\"kidR\"", "{ \"kidR\"", 1),
        json.replacen("\"createdAt\":", "\"extra\":1,\"createdAt\":", 1),
        json.replacen(
            &format!("\"captureSeq\":\"{}\"", case.aad.capture_seq),
            &format!("\"captureSeq\":\"0{}\"", case.aad.capture_seq),
            1,
        ),
        json.replacen("{\"kidR\"", "{\"kidR\":\"aaaaaaaaaaaaaaaa\",\"kidR\"", 1),
    ];
    for text in respelled {
        assert_ne!(&text, json);
        let mut framed = b"WSCO\x01".to_vec();
        framed.extend_from_slice(&u32::try_from(text.len()).expect("len").to_be_bytes());
        framed.extend_from_slice(text.as_bytes());
        framed.extend_from_slice(&seal_bytes);
        assert_eq!(
            envelope::parse(framed).map(|_| ()),
            Err(SealError::Malformed),
            "{text}"
        );
    }
}
