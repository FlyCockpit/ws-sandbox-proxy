//! DNS names, proxy upstreams, header names, formats and constructed header
//! values (same rules as `net.ts`).

use std::fmt;

use crate::limits::{
    DNS_NAME_MAX_BYTES, ENV_VALUE_MAX_BYTES, HEADER_VALUE_MAX_BYTES, PROXY_BASEPATH_MAX_BYTES,
    PROXY_FORMAT_MAX_BYTES, PROXY_HEADER_MAX_BYTES, PROXY_UPSTREAM_MAX_BYTES,
};
use crate::secret::SecretBuf;

fn label_ok(label: &str) -> bool {
    let b = label.as_bytes();
    let ldh = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-';
    !b.is_empty() && b.len() <= 63 && b.iter().all(ldh) && b[0] != b'-' && b[b.len() - 1] != b'-'
}

/// An exact, lowercase ASCII DNS name with at least two labels whose last
/// label starts with a letter (no IP literal or numeric look-alike).
#[must_use]
pub fn dns_name_problem(name: &str) -> Option<&'static str> {
    if name.is_empty() {
        return Some("name is empty");
    }
    if name.len() > DNS_NAME_MAX_BYTES {
        return Some("name is too long");
    }
    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() < 2 {
        return Some("name needs at least two labels");
    }
    if !labels.iter().all(|l| label_ok(l)) {
        return Some("name must be lowercase ASCII letters, digits and hyphens");
    }
    if !labels
        .last()
        .is_some_and(|l| l.as_bytes()[0].is_ascii_lowercase())
    {
        return Some("the last label must start with a letter (IP literals are not allowed)");
    }
    None
}

fn unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn segment_char(byte: u8) -> bool {
    unreserved(byte)
        || matches!(
            byte,
            b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
        )
}

fn upper_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn segment_problem(segment: &str) -> Option<&'static str> {
    if segment.is_empty() {
        return Some("basepath has an empty segment");
    }
    if segment == "." || segment == ".." {
        return Some("basepath has a dot segment");
    }
    let b = segment.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let (Some(hi), Some(lo)) = (
                b.get(i + 1).and_then(|c| upper_hex(*c)),
                b.get(i + 2).and_then(|c| upper_hex(*c)),
            ) else {
                return Some("basepath percent-escapes must be two uppercase hex digits");
            };
            let byte = hi << 4 | lo;
            if unreserved(byte) {
                return Some("basepath must not percent-encode an unreserved character");
            }
            if byte == b'/' || byte == b'\\' || byte < 0x20 || byte == 0x7f {
                return Some("basepath must not percent-encode a slash, backslash or control byte");
            }
            i += 3;
        } else if segment_char(b[i]) {
            i += 1;
        } else {
            return Some("basepath contains a character outside the allowed set");
        }
    }
    None
}

/// A proxy upstream in its one normalized form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub host: String,
    pub port: Option<u16>,
    /// Empty, or `/segment(/segment)*` without a trailing slash.
    pub basepath: String,
}

/// Parses `https://host[:port][/basepath]`: lowercase scheme and host, no
/// userinfo, query or fragment, no trailing slash, port without leading zeros.
pub fn parse_upstream(text: &str) -> Result<Upstream, &'static str> {
    if text.len() > PROXY_UPSTREAM_MAX_BYTES {
        return Err("upstream is too long");
    }
    let Some(rest) = text.strip_prefix("https://") else {
        return Err("upstream must start with https://");
    };
    if text.contains('?') || text.contains('#') {
        return Err("upstream must not have a query or fragment");
    }
    let (authority, basepath) = match rest.find('/') {
        Some(slash) => rest.split_at(slash),
        None => (rest, ""),
    };
    if authority.contains('@') {
        return Err("upstream must not have userinfo");
    }
    if authority.contains('[') {
        return Err("upstream must be a DNS name, not an IP literal");
    }
    let mut parts = authority.split(':');
    let host = parts.next().unwrap_or_default();
    let port_text = parts.next();
    if parts.next().is_some() {
        return Err("upstream authority is malformed");
    }
    if let Some(problem) = dns_name_problem(host) {
        return Err(problem);
    }
    let port = match port_text {
        None => None,
        Some(raw) => {
            let b = raw.as_bytes();
            let digits = !b.is_empty() && b.len() <= 5 && b.iter().all(u8::is_ascii_digit);
            if !digits || b[0] == b'0' {
                return Err("upstream port must be 1-65535 without leading zeros");
            }
            Some(
                raw.parse::<u16>()
                    .map_err(|_| "upstream port must be 1-65535")?,
            )
        }
    };
    if !basepath.is_empty() {
        if basepath.len() > PROXY_BASEPATH_MAX_BYTES {
            return Err("upstream basepath is too long");
        }
        if basepath.ends_with('/') {
            return Err("upstream basepath must not end with a slash");
        }
        for segment in basepath[1..].split('/') {
            if let Some(problem) = segment_problem(segment) {
                return Err(problem);
            }
        }
    }
    Ok(Upstream {
        host: host.to_owned(),
        port,
        basepath: basepath.to_owned(),
    })
}

fn tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

const FORBIDDEN_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "te",
    "trailer",
    "keep-alive",
    "expect",
    "forwarded",
    "via",
];
const FORBIDDEN_HEADER_PREFIXES: &[&str] = &["proxy-", "x-forwarded-"];

#[must_use]
pub fn header_name_problem(name: &str) -> Option<&'static str> {
    if name.is_empty() {
        return Some("header is empty");
    }
    if name.len() > PROXY_HEADER_MAX_BYTES {
        return Some("header is too long");
    }
    if !name.bytes().all(tchar) {
        return Some("header must be an HTTP token");
    }
    let lower = name.to_ascii_lowercase();
    if FORBIDDEN_HEADERS.contains(&lower.as_str())
        || FORBIDDEN_HEADER_PREFIXES
            .iter()
            .any(|p| lower.starts_with(p))
    {
        return Some("header is reserved for the proxy");
    }
    None
}

pub const VALUE_PLACEHOLDER: &str = "{value}";

/// RFC 9110 field-value byte: visible ASCII, obs-text, SP or HTAB.
#[must_use]
pub const fn is_field_value_byte(byte: u8) -> bool {
    matches!(byte, 0x21..=0x7e | 0x80..=0xff | b' ' | b'\t')
}

const fn is_whitespace(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

#[must_use]
pub fn format_problem(format: &str) -> Option<&'static str> {
    if format.len() > PROXY_FORMAT_MAX_BYTES {
        return Some("format is too long");
    }
    if format.matches(VALUE_PLACEHOLDER).count() != 1 {
        return Some("format must contain {value} exactly once");
    }
    let b = format.as_bytes();
    if is_whitespace(b[0]) || is_whitespace(b[b.len() - 1]) {
        return Some("format must not start or end with whitespace");
    }
    if !format
        .replacen(VALUE_PLACEHOLDER, "", 1)
        .bytes()
        .all(is_field_value_byte)
    {
        return Some("format contains a byte that is not allowed in a header");
    }
    None
}

/// Refusal of a constructed header value. Deliberately carries nothing about
/// the value; callers name the env entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("credential header value is not a valid HTTP field value")]
pub struct HeaderValueError;

/// `format(value)` proven to be an RFC 9110 §5.5 field-value: 1 to
/// [`HEADER_VALUE_MAX_BYTES`] bytes of visible ASCII, obs-text, SP or HTAB with
/// no leading or trailing whitespace. The only type a proxy header writer
/// should accept. The bytes live in a [`SecretBuf`] (wiped on drop, not
/// `Clone`), and `Debug` never prints them.
pub struct ValidatedHeaderValue(SecretBuf);

impl ValidatedHeaderValue {
    /// Checks `prefix ‖ value ‖ suffix` in place and allocates only when it is
    /// valid, so a refused value is never copied.
    pub fn new(format: &str, value: &[u8]) -> Result<Self, HeaderValueError> {
        if format_problem(format).is_some() {
            return Err(HeaderValueError);
        }
        let (prefix, suffix) = format
            .split_once(VALUE_PLACEHOLDER)
            .ok_or(HeaderValueError)?;
        let parts = [prefix.as_bytes(), value, suffix.as_bytes()];
        let total: usize = parts.iter().map(|p| p.len()).sum();
        if total == 0 || total > HEADER_VALUE_MAX_BYTES {
            return Err(HeaderValueError);
        }
        let mut bytes = parts.iter().flat_map(|p| p.iter().copied());
        let first = bytes.clone().next();
        let last = bytes.clone().next_back();
        let ok = first.is_some_and(|b| !is_whitespace(b))
            && last.is_some_and(|b| !is_whitespace(b))
            && bytes.all(is_field_value_byte);
        if !ok {
            return Err(HeaderValueError);
        }
        let mut out = SecretBuf::with_capacity(total);
        for part in parts {
            out.extend_from_slice(part);
        }
        Ok(Self(out))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for ValidatedHeaderValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ValidatedHeaderValue(<{} bytes redacted>)", self.0.len())
    }
}

/// Env values for every delivery: at most [`ENV_VALUE_MAX_BYTES`] bytes, no NUL.
#[must_use]
pub fn env_value_acceptable(value: &[u8]) -> bool {
    value.len() <= ENV_VALUE_MAX_BYTES && !value.contains(&0)
}
