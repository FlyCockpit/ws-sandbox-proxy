//! Streaming masking, before bytes enter output rings or file responses.
use zeroize::Zeroizing;

pub(super) const MARKER: &str = "⟦redacted⟧";
const TOKEN_PREFIXES: &[&[u8]] = &[b"wssp_sdk_", b"wssp_host_", b"wssp_device_", b"wssp_agent_"];
#[derive(Default)]
enum Mode {
    #[default]
    Text,
    Token,
    Pem {
        tail: Vec<u8>,
        end_header: bool,
    },
}
pub(super) struct Masker {
    base: Vec<Zeroizing<Vec<u8>>>,
    values: Vec<Zeroizing<Vec<u8>>>,
    pending: Zeroizing<Vec<u8>>,
    mode: Mode,
    covered: usize,
    opaque: bool,
    live: bool,
}
impl Masker {
    pub fn new(daemon_secret: &[u8]) -> Self {
        let mut values = Vec::new();
        if !daemon_secret.is_empty() {
            values.push(Zeroizing::new(daemon_secret.to_vec()));
        }
        for (name, value) in std::env::vars_os() {
            let name = name.to_string_lossy();
            if ["_TOKEN", "_KEY", "_SECRET", "_PASSWORD"]
                .iter()
                .any(|s| name.ends_with(s))
            {
                let bytes = value.as_encoded_bytes();
                if bytes.len() >= 8 {
                    values.push(Zeroizing::new(bytes.to_vec()));
                }
            }
        }
        let mut masker = Self {
            base: values.iter().map(|v| Zeroizing::new(v.to_vec())).collect(),
            values,
            pending: Zeroizing::new(Vec::new()),
            mode: Mode::Text,
            covered: 0,
            opaque: false,
            live: true,
        };
        masker.refresh();
        masker
    }
    fn refresh(&mut self) {
        if !self.live {
            return;
        }
        let (values, dirty) = super::credentials::masking_snapshot();
        self.opaque |= dirty;
        // Release snapshots of settled leases as soon as no buffered prefix
        // still needs them. Long-running commands must not retain retired logins.
        self.values.retain(|value| {
            self.base.iter().any(|base| **base == **value)
                || (!self.pending.is_empty() && value.starts_with(&self.pending))
        });
        for value in values {
            if !value.is_empty() && !self.values.iter().any(|v| **v == *value) {
                self.values.push(value);
            }
        }
        self.values.sort_by_key(|v| std::cmp::Reverse(v.len()));
    }
    pub fn push(&mut self, bytes: &[u8], finish: bool) -> Vec<u8> {
        self.refresh();
        if self.opaque {
            let nonempty = !bytes.is_empty() || !self.pending.is_empty();
            self.pending.clear();
            return if nonempty {
                MARKER.as_bytes().to_vec()
            } else {
                Vec::new()
            };
        }
        self.pending.extend_from_slice(bytes);
        let mut output = Vec::new();
        let (value_starts, hold_from) = value_matches(&self.values, &self.pending);
        let mut at = 0;
        while at < self.pending.len() {
            let rest = &self.pending[at..];
            let byte = rest[0];
            if matches!(self.mode, Mode::Token) && !token_byte(byte) {
                self.mode = Mode::Text;
            }
            let was_covered = self.covered > 0 || !matches!(self.mode, Mode::Text);
            // Inspect every raw position, even inside another redacted span:
            // one value can overlap a token/PEM prefix or another value.
            if !finish && at >= hold_from {
                break;
            }
            let value_len = value_starts[at];
            let mut token_start = false;
            if !matches!(self.mode, Mode::Pem { .. }) {
                if !finish && TOKEN_PREFIXES.iter().any(|p| p.starts_with(rest)) {
                    break;
                }
                token_start = TOKEN_PREFIXES.iter().any(|p| {
                    rest.starts_with(p) && rest.get(p.len()).is_some_and(|b| token_byte(*b))
                });
            }
            const BEGIN: &[u8] = b"-----BEGIN ";
            let mut pem_start = false;
            if !matches!(self.mode, Mode::Pem { .. }) {
                if !finish && BEGIN.starts_with(rest) {
                    break;
                }
                if rest.starts_with(BEGIN) {
                    let newline = rest.iter().take(4096).position(|b| *b == b'\n');
                    let header = &rest[..newline.unwrap_or(rest.len().min(4096))];
                    pem_start = find(header, b"PRIVATE KEY-----").is_some() || header.len() == 4096;
                    if !pem_start && !finish && newline.is_none() && rest.len() < 4096 {
                        break;
                    }
                }
            }
            if pem_start {
                self.mode = Mode::Pem {
                    tail: Vec::new(),
                    end_header: false,
                };
            } else if token_start && matches!(self.mode, Mode::Text) {
                self.mode = Mode::Token;
            }
            self.covered = self.covered.max(value_len);
            let covered = self.covered > 0 || !matches!(self.mode, Mode::Text);
            if covered {
                if !was_covered {
                    output.extend_from_slice(MARKER.as_bytes());
                }
            } else {
                output.push(byte);
            }
            self.covered = self.covered.saturating_sub(1);
            if let Mode::Pem { tail, end_header } = &mut self.mode {
                tail.push(byte);
                if tail.ends_with(b"-----END ") {
                    *end_header = true;
                }
                let ended = *end_header && tail.ends_with(b"PRIVATE KEY-----");
                if byte == b'\n' {
                    *end_header = false;
                }
                if tail.len() > 64 {
                    tail.remove(0);
                }
                if ended {
                    self.mode = Mode::Text;
                }
            }
            at += 1;
        }
        self.pending.drain(..at);
        output
    }
    pub fn whole(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.push(bytes, true)
    }
    #[cfg(test)]
    fn fixture(values: &[&[u8]]) -> Self {
        Self {
            base: Vec::new(),
            values: values.iter().map(|v| Zeroizing::new(v.to_vec())).collect(),
            pending: Zeroizing::new(Vec::new()),
            mode: Mode::Text,
            covered: 0,
            opaque: false,
            live: false,
        }
    }
}
// KMP finds overlapping value spans in linear time, including highly repetitive
// credential files. The final partial prefix is the only raw suffix held back.
fn value_matches(values: &[Zeroizing<Vec<u8>>], bytes: &[u8]) -> (Vec<usize>, usize) {
    let mut starts = vec![0; bytes.len()];
    let mut hold = bytes.len();
    for value in values {
        if value.is_empty() {
            continue;
        }
        let mut prefix = vec![0; value.len()];
        for i in 1..value.len() {
            let mut j = prefix[i - 1];
            while j > 0 && value[i] != value[j] {
                j = prefix[j - 1];
            }
            if value[i] == value[j] {
                j += 1;
            }
            prefix[i] = j;
        }
        let mut matched = 0;
        for (i, byte) in bytes.iter().enumerate() {
            while matched > 0 && value[matched] != *byte {
                matched = prefix[matched - 1];
            }
            if value[matched] == *byte {
                matched += 1;
            }
            if matched == value.len() {
                let start = i + 1 - value.len();
                starts[start] = starts[start].max(value.len());
                matched = prefix[matched - 1];
            }
        }
        if matched > 0 {
            hold = hold.min(bytes.len() - matched);
        }
    }
    (starts, hold)
}
fn token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_split_has_identical_masking() {
        for (input, expected) in [
            (
                "before secret-value after",
                format!("before {MARKER} after"),
            ),
            ("secret-valuesecret-value", format!("{MARKER}{MARKER}")),
            (
                "wssp_agent_fixture-token! wssp_sdk_test",
                format!("{MARKER}! {MARKER}"),
            ),
            (
                "a -----BEGIN RSA PRIVATE KEY-----\nprivate\n-----END RSA PRIVATE KEY----- z",
                format!("a {MARKER} z"),
            ),
            ("wssp_host_", format!("{MARKER}host_")),
            ("ordinary UTF-8: 日本", "ordinary UTF-8: 日本".to_string()),
        ] {
            for split in 0..=input.len() {
                let mut m = Masker::fixture(&[b"secret-value", b"wssp_", b"-----BEGIN "]);
                let mut got = m.push(&input.as_bytes()[..split], false);
                got.extend(m.push(&input.as_bytes()[split..], false));
                got.extend(m.push(&[], true));
                assert_eq!(got, expected.as_bytes(), "split {split} of {input}");
            }
            let mut m = Masker::fixture(&[b"secret-value", b"wssp_", b"-----BEGIN "]);
            let mut got = Vec::new();
            for b in input.as_bytes() {
                got.extend(m.push(&[*b], false));
            }
            got.extend(m.push(&[], true));
            assert_eq!(got, expected.as_bytes());
        }
    }
    #[test]
    fn longest_overlapping_secret_is_held() {
        let mut m = Masker::fixture(&[b"abc", b"abcdef"]);
        assert!(m.push(b"abc", false).is_empty());
        assert_eq!(m.push(b"def!", true), format!("{MARKER}!").as_bytes());
    }
}

#[cfg(test)]
mod snapshot_lifetime_tests {
    use super::*;
    #[test]
    fn retired_values_are_retained_only_to_finish_a_buffered_prefix() {
        let secret = crate::sandbox_relay::credentials::SecretBytes::copy_from(
            b"mask-lifetime-fixture-unique",
        );
        let mut mask = Masker::new(b"daemon-fixture");
        assert!(mask.push(b"mask-lifetime-fixture-", false).is_empty());
        drop(secret);
        let output = mask.push(b"unique!", false);
        assert_eq!(output, format!("{MARKER}!").as_bytes());
        mask.push(b"ordinary", false);
        assert!(
            !mask
                .values
                .iter()
                .any(|v| v.as_slice() == b"mask-lifetime-fixture-unique")
        );
    }
}

#[cfg(test)]
mod overlap_tests {
    use super::*;
    #[test]
    fn overlapping_values_and_pattern_prefixes_are_redacted_as_a_union_at_every_split() {
        let long = "X".repeat(100);
        for (input, values, expected) in [
            (
                "abcde".to_string(),
                vec![b"abc".as_slice(), b"bcd".as_slice()],
                format!("{MARKER}e"),
            ),
            (
                "hello wssp_agent_fixture-token!".to_string(),
                vec![b"hello wssp_".as_slice()],
                format!("{MARKER}!"),
            ),
            (
                "hello -----BEGIN RSA PRIVATE KEY-----\nbody\n-----END RSA PRIVATE KEY----- after"
                    .to_string(),
                vec![b"hello -----BEGIN ".as_slice()],
                format!("{MARKER} after"),
            ),
            (
                format!(
                    "-----BEGIN {long} PRIVATE KEY-----\nbody\n-----END {long} PRIVATE KEY----- after"
                ),
                vec![],
                format!("{MARKER} after"),
            ),
        ] {
            for split in 0..=input.len() {
                let mut masker = Masker::fixture(&values);
                let mut output = masker.push(&input.as_bytes()[..split], false);
                output.extend(masker.push(&input.as_bytes()[split..], false));
                output.extend(masker.push(&[], true));
                assert_eq!(output, expected.as_bytes(), "split {split}");
            }
        }
    }
}
