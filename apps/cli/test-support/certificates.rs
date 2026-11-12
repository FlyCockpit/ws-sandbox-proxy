//! Minimal X.509 builder used only by tests. Fresh keys never leave memory.
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
};

pub struct Certificates {
    pub ca_pem: String,
    pub leaf: Vec<u8>,
    pub leaf_key: Vec<u8>,
}

fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 128 {
        out.push(body.len() as u8);
    } else {
        let bytes = body.len().to_be_bytes();
        let bytes = &bytes[bytes.iter().position(|b| *b != 0).unwrap()..];
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out.extend(body);
    out
}
fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    der(0x30, &parts.concat())
}
fn oid(bytes: &[u8]) -> Vec<u8> {
    der(6, bytes)
}
fn name(text: &str) -> Vec<u8> {
    seq(&[der(
        0x31,
        &seq(&[oid(&[0x55, 4, 3]), der(0x0c, text.as_bytes())]),
    )])
}
fn algorithm() -> Vec<u8> {
    seq(&[oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2])])
}
fn extension(id: u8, critical: bool, value: Vec<u8>) -> Vec<u8> {
    let mut fields = vec![oid(&[0x55, 0x1d, id])];
    if critical {
        fields.push(der(1, &[0xff]));
    }
    fields.push(der(4, &value));
    seq(&fields)
}
fn certificate(key: &EcdsaKeyPair, signer: &EcdsaKeyPair, ca: bool, rng: &SystemRandom) -> Vec<u8> {
    let spki = seq(&[
        seq(&[
            oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1]),
            oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7]),
        ]),
        der(3, &[&[0][..], key.public_key().as_ref()].concat()),
    ]);
    let extensions = if ca {
        vec![
            extension(19, true, seq(&[der(1, &[0xff])])),
            extension(15, true, der(3, &[1, 6])),
        ]
    } else {
        vec![
            extension(19, true, seq(&[])),
            extension(
                17,
                false,
                seq(&[der(0x82, b"localhost"), der(0x87, &[127, 0, 0, 1])]),
            ),
        ]
    };
    let tbs = seq(&[
        der(0xa0, &der(2, &[2])),
        der(2, &[if ca { 1 } else { 2 }]),
        algorithm(),
        name("wssp ephemeral test CA"),
        // Fixed validity bounds avoid dependence on the host clock at creation.
        seq(&[der(0x17, b"240101000000Z"), der(0x18, b"21240101000000Z")]),
        name(if ca {
            "wssp ephemeral test CA"
        } else {
            "localhost"
        }),
        spki,
        der(0xa3, &seq(&extensions)),
    ]);
    let signature = signer.sign(rng, &tbs).unwrap();
    seq(&[
        tbs,
        algorithm(),
        der(3, &[&[0][..], signature.as_ref()].concat()),
    ])
}
fn pem(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut body = String::new();
    for chunk in bytes.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
            | chunk.get(2).copied().unwrap_or(0) as u32;
        body.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        body.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        body.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        body.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n")
}
pub fn generate() -> Certificates {
    let rng = SystemRandom::new();
    let ca_doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let ca =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, ca_doc.as_ref(), &rng).unwrap();
    let leaf_doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let leaf =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, leaf_doc.as_ref(), &rng).unwrap();
    Certificates {
        ca_pem: pem(&certificate(&ca, &ca, true, &rng)),
        leaf: certificate(&leaf, &ca, false, &rng),
        leaf_key: leaf_doc.as_ref().to_vec(),
    }
}
