//! Blocked-name hints (template-builds B12, §6.3): the daemon reports names a
//! sandbox's allowlist-mode resolver refused, so a build log can say which
//! host to grant. Additive inside 1.0: the capability is omitted when
//! `false`, and the frame is sent only to a server that saw it advertised.
//!
//! Names are operator-reported text. The wire carries only lowercase DNS
//! names (`valid_hint_dns_name`), at most `EGRESS_REFUSED_NAMES_MAX` per
//! frame and unique; anything else refuses the frame. The shared fixture
//! `fixtures/egress_refused.json` pins the same grammar for the server.

use serde::{Deserialize, Serialize};

/// Names per `egress.refused` frame.
pub const EGRESS_REFUSED_NAMES_MAX: usize = 16;
/// A DNS name's presentation length (no trailing dot).
pub const HINT_DNS_NAME_MAX_BYTES: usize = 253;
/// One label's length.
pub const HINT_DNS_LABEL_MAX_BYTES: usize = 63;
/// Daemon-side frame rate per sandbox (≤ 1 frame / 2 s / sandbox).
pub const EGRESS_REFUSED_MIN_INTERVAL_MS: u64 = 2_000;

/// Lowercase DNS name grammar: dot-separated labels of `[a-z0-9_-]`, each
/// 1..=63 bytes, not starting or ending with `-`, at most 253 bytes in all,
/// no trailing dot. `_` is allowed for service labels (`_dmarc`). Never
/// admits a control character, space, or non-ASCII byte.
pub fn valid_hint_dns_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= HINT_DNS_NAME_MAX_BYTES
        && name.split('.').all(|label| {
            let bytes = label.as_bytes();
            !bytes.is_empty()
                && bytes.len() <= HINT_DNS_LABEL_MAX_BYTES
                && bytes.first() != Some(&b'-')
                && bytes.last() != Some(&b'-')
                && bytes.iter().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-' || *b == b'_'
                })
        })
}

/// Daemon → server `egress.refused`: names the sandbox's allowlist resolver
/// refused since the last report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EgressRefusedV11 {
    pub sandbox_id: String,
    pub names: Vec<String>,
}

impl EgressRefusedV11 {
    pub fn is_valid(&self) -> bool {
        crate::valid_inventory_sandbox_id(&self.sandbox_id)
            && !self.names.is_empty()
            && self.names.len() <= EGRESS_REFUSED_NAMES_MAX
            && self.names.iter().all(|name| valid_hint_dns_name(name))
            && self
                .names
                .iter()
                .enumerate()
                .all(|(i, name)| !self.names[..i].contains(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grammar_bounds_names() {
        assert!(valid_hint_dns_name("pypi.org"));
        assert!(valid_hint_dns_name("_dmarc.example.com"));
        assert!(valid_hint_dns_name(&format!("{}.com", "a".repeat(63))));
        assert!(!valid_hint_dns_name(&format!("{}.com", "a".repeat(64))));
        let long = vec!["a".repeat(63); 4].join(".");
        assert_eq!(long.len(), 255);
        assert!(!valid_hint_dns_name(&long));
        for bad in [
            "", ".", "a..b", "a.", "-a.com", "a-.com", "A.com", "a b", "a\u{7}b", "é.com", "a\nb",
            "a/b",
        ] {
            assert!(!valid_hint_dns_name(bad), "{bad:?}");
        }
    }
}
