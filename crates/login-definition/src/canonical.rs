//! Canonical JSON v1 and the definition digest, byte-identical to
//! `packages/login-definition/src/canonical-json.ts`:
//!
//! - object keys sorted by Unicode code point (UTF-8 byte order), no whitespace;
//! - strings escaped exactly as ECMAScript `JSON.stringify` escapes them (`\"`,
//!   `\\`, `\b \f \n \r \t`, other C0 controls as lowercase `\u00xx`, nothing
//!   else), encoded as UTF-8;
//! - numbers are integers in the IEEE-754 safe range written in plain decimal
//!   (`-0` and integral floats such as `1.0` or `1e2` normalize); any
//!   fractional or unsafe number is refused. Text is parsed correctly rounded
//!   (serde_json `float_roundtrip`), as `JSON.parse` does, so `1000000000000000.1`
//!   is a fraction and `9007199254740991.0` is exactly 2^53 - 1;
//! - at most [`DOCUMENT_MAX_DEPTH`](crate::limits::DOCUMENT_MAX_DEPTH) nested arrays/objects;
//! - at most [`DOCUMENT_MAX_BYTES`] bytes of output. The budget is enforced
//!   while writing (and before sorting an object's keys or escaping a string),
//!   so an oversized document is refused after at most that much work.

use std::fmt::Write as _;

use serde_json::Value;

use crate::limits::{DOCUMENT_MAX_BYTES, DOCUMENT_MAX_DEPTH};

/// The refusal past [`DOCUMENT_MAX_BYTES`] (path `""`), worded as in TS.
pub const DOCUMENT_TOO_LARGE: &str = "canonical JSON exceeds 262144 bytes";

/// `Number.MAX_SAFE_INTEGER`.
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{path}: {message}")]
pub struct CanonicalJsonError {
    pub path: String,
    pub message: &'static str,
}

/// The safe integer a JSON number denotes, if it denotes one.
#[must_use]
pub fn safe_integer(number: &serde_json::Number) -> Option<i64> {
    if let Some(i) = number.as_i64() {
        return (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER)
            .contains(&i)
            .then_some(i);
    }
    if number.is_u64() {
        return None;
    }
    let float = number.as_f64()?;
    let bound = MAX_SAFE_INTEGER as f64;
    if float.is_finite() && float.fract() == 0.0 && (-bound..=bound).contains(&float) {
        // Exact: an integral f64 within ±(2^53 - 1) converts losslessly.
        #[allow(clippy::cast_possible_truncation)]
        return Some(float as i64);
    }
    None
}

fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_owned()
    } else {
        format!("{path}.{key}")
    }
}

const fn short_escape(ch: char) -> Option<&'static str> {
    match ch {
        '"' => Some("\\\""),
        '\\' => Some("\\\\"),
        '\u{8}' => Some("\\b"),
        '\u{c}' => Some("\\f"),
        '\n' => Some("\\n"),
        '\r' => Some("\\r"),
        '\t' => Some("\\t"),
        _ => None,
    }
}

/// Bytes `text` takes once quoted and escaped.
fn quoted_len(text: &str) -> usize {
    2 + text
        .chars()
        .map(|ch| match short_escape(ch) {
            Some(escape) => escape.len(),
            None if (ch as u32) < 0x20 => 6,
            None => ch.len_utf8(),
        })
        .sum::<usize>()
}

/// Canonical output under a byte budget: nothing is written past `max`.
struct Writer {
    out: String,
    max: usize,
}

impl Writer {
    /// Refuses before work whose output would need at least `bytes` more bytes.
    fn reserve(&self, bytes: usize) -> Result<(), CanonicalJsonError> {
        if self.out.len().saturating_add(bytes) > self.max {
            return Err(CanonicalJsonError {
                path: String::new(),
                message: DOCUMENT_TOO_LARGE,
            });
        }
        Ok(())
    }

    fn push(&mut self, text: &str) -> Result<(), CanonicalJsonError> {
        self.reserve(text.len())?;
        self.out.push_str(text);
        Ok(())
    }

    fn string(&mut self, text: &str) -> Result<(), CanonicalJsonError> {
        // Escaping only grows the text: check the cheap bound before scanning it.
        self.reserve(text.len() + 2)?;
        self.reserve(quoted_len(text))?;
        self.out.push('"');
        for ch in text.chars() {
            match short_escape(ch) {
                Some(escape) => self.out.push_str(escape),
                None if (ch as u32) < 0x20 => {
                    let _ = write!(self.out, "\\u{:04x}", ch as u32);
                }
                None => self.out.push(ch),
            }
        }
        self.out.push('"');
        Ok(())
    }

    fn value(&mut self, node: &Value, path: &str, depth: usize) -> Result<(), CanonicalJsonError> {
        let fail = |message| CanonicalJsonError {
            path: path.to_owned(),
            message,
        };
        match node {
            Value::Null => self.push("null")?,
            Value::Bool(b) => self.push(if *b { "true" } else { "false" })?,
            Value::Number(n) => {
                let int = safe_integer(n).ok_or_else(|| fail("numbers must be safe integers"))?;
                self.push(&int.to_string())?;
            }
            Value::String(s) => self.string(s)?,
            Value::Array(items) => {
                if depth + 1 > DOCUMENT_MAX_DEPTH {
                    return Err(fail("nesting is too deep"));
                }
                // `[` + n values of at least one byte + n - 1 commas + `]`.
                self.reserve(items.len().saturating_mul(2).saturating_add(1))?;
                self.push("[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        self.push(",")?;
                    }
                    self.value(item, &format!("{path}[{i}]"), depth + 1)?;
                }
                self.push("]")?;
            }
            Value::Object(map) => {
                if depth + 1 > DOCUMENT_MAX_DEPTH {
                    return Err(fail("nesting is too deep"));
                }
                // `{` + n members of at least `"":0` (4 bytes) + n - 1 commas + `}`.
                self.reserve(map.len().saturating_mul(5).saturating_add(1))?;
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                self.push("{")?;
                for (i, key) in keys.into_iter().enumerate() {
                    if i > 0 {
                        self.push(",")?;
                    }
                    self.string(key)?;
                    self.push(":")?;
                    self.value(&map[key], &join(path, key), depth + 1)?;
                }
                self.push("}")?;
            }
        }
        Ok(())
    }
}

/// Canonical JSON text of `value`, refused past [`DOCUMENT_MAX_BYTES`].
pub fn canonical_json(value: &Value) -> Result<String, CanonicalJsonError> {
    let mut writer = Writer {
        out: String::new(),
        max: DOCUMENT_MAX_BYTES,
    };
    writer.value(value, "", 0)?;
    Ok(writer.out)
}

/// SHA-256 of `bytes`.
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// Definition digest: SHA-256 of the canonical JSON of the stored document
/// exactly as submitted (`x-*` extensions included, defaults not filled in).
/// [`ParsedDefinition::digest`](crate::ParsedDefinition) already holds it for
/// a parsed document.
pub fn definition_digest(document: &Value) -> Result<[u8; 32], CanonicalJsonError> {
    Ok(sha256(canonical_json(document)?.as_bytes()))
}

/// Lowercase hex.
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Parses exactly 64 lowercase hex digits.
#[must_use]
pub fn digest_from_hex(hex: &str) -> Option<[u8; 32]> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let nibble = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (i, [hi, lo]) in bytes.as_chunks::<2>().0.iter().enumerate() {
        out[i] = nibble(*hi)? << 4 | nibble(*lo)?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn too_large_message_names_the_limit() {
        assert_eq!(
            DOCUMENT_TOO_LARGE,
            format!("canonical JSON exceeds {DOCUMENT_MAX_BYTES} bytes")
        );
    }

    #[test]
    fn quoted_len_matches_the_written_string() {
        for text in [
            "",
            "plain",
            "q\" b\\ \t\n\r\u{8}\u{c}",
            "\u{0}\u{1f}\u{7f}",
            "é😀\u{2028}",
        ] {
            let written = canonical_json(&Value::String(text.to_owned())).unwrap();
            assert_eq!(quoted_len(text), written.len(), "{text:?}");
        }
    }
}
