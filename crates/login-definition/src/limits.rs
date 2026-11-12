//! Login definition and bundle v1 bounds. `packages/login-definition/src/limits.json`
//! is the single source; a unit test pins every constant here to that file.

pub const SCHEMA_VERSION: i64 = 1;
pub const ID_MAX_BYTES: usize = 63;
pub const DISPLAY_NAME_MAX_CHARS: usize = 80;
pub const DESCRIPTION_MAX_CHARS: usize = 500;
pub const INSTALL_NOTES_MAX_CHARS: usize = 2000;
pub const COMMAND_MAX_BYTES: usize = 4096;
pub const EGRESS_DOMAINS_MAX: usize = 32;
pub const DNS_NAME_MAX_BYTES: usize = 253;
pub const FILE_PATHS_MAX: usize = 64;
pub const DEFINITION_PATH_MAX_BYTES: usize = 255;
pub const ENV_ENTRIES_MAX: usize = 16;
pub const ENV_NAME_MAX_BYTES: usize = 128;
pub const ENV_DESCRIPTION_MAX_CHARS: usize = 500;
pub const ENV_VALUE_MAX_BYTES: usize = 4096;
pub const MAX_BYTES_MIN: i64 = 1;
pub const MAX_BYTES_MAX: i64 = 4_194_304;
pub const MAX_BYTES_DEFAULT: i64 = 1_048_576;
pub const PROXY_UPSTREAM_MAX_BYTES: usize = 512;
pub const PROXY_BASEPATH_MAX_BYTES: usize = 240;
pub const PROXY_HEADER_MAX_BYTES: usize = 64;
pub const PROXY_FORMAT_MAX_BYTES: usize = 256;
pub const HEADER_VALUE_MAX_BYTES: usize = 8192;
pub const DOCUMENT_MAX_BYTES: usize = 262_144;
/// Raw definition text, checked before JSON parsing (whitespace counts).
pub const DOCUMENT_TEXT_MAX_BYTES: usize = 1_048_576;
pub const DOCUMENT_MAX_DEPTH: usize = 32;
pub const BUNDLE_HEADER_BYTES: usize = 41;
pub const BUNDLE_FILE_COUNT_MAX: usize = 4096;
pub const BUNDLE_PATH_MAX_BYTES: usize = 1024;
pub const BUNDLE_PATH_TOTAL_MAX_BYTES: usize = 524_288;
pub const BUNDLE_ENV_COUNT_MAX: usize = 16;
/// `41 + 9·4096 + 524 288 + 16·(3 + 128 + 4096)`: the bundle bound minus `maxBytes`.
pub const BUNDLE_FIXED_MAX_BYTES: usize = 628_825;

/// Exact upper bound of an encoded bundle v1 for a definition's `maxBytes`.
#[must_use]
pub const fn bundle_max_encoded_bytes(max_bytes: usize) -> usize {
    BUNDLE_FIXED_MAX_BYTES + max_bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_the_shared_limits_file() {
        let raw = include_str!("../../../packages/login-definition/src/limits.json");
        let json: serde_json::Value = serde_json::from_str(raw).unwrap();
        let get = |key: &str| {
            json[key]
                .as_i64()
                .unwrap_or_else(|| panic!("missing {key}"))
        };
        let pairs: &[(&str, i64)] = &[
            ("schemaVersion", SCHEMA_VERSION),
            ("idMaxBytes", ID_MAX_BYTES as i64),
            ("displayNameMaxChars", DISPLAY_NAME_MAX_CHARS as i64),
            ("descriptionMaxChars", DESCRIPTION_MAX_CHARS as i64),
            ("installNotesMaxChars", INSTALL_NOTES_MAX_CHARS as i64),
            ("commandMaxBytes", COMMAND_MAX_BYTES as i64),
            ("egressDomainsMax", EGRESS_DOMAINS_MAX as i64),
            ("dnsNameMaxBytes", DNS_NAME_MAX_BYTES as i64),
            ("filePathsMax", FILE_PATHS_MAX as i64),
            ("definitionPathMaxBytes", DEFINITION_PATH_MAX_BYTES as i64),
            ("envEntriesMax", ENV_ENTRIES_MAX as i64),
            ("envNameMaxBytes", ENV_NAME_MAX_BYTES as i64),
            ("envDescriptionMaxChars", ENV_DESCRIPTION_MAX_CHARS as i64),
            ("envValueMaxBytes", ENV_VALUE_MAX_BYTES as i64),
            ("maxBytesMin", MAX_BYTES_MIN),
            ("maxBytesMax", MAX_BYTES_MAX),
            ("maxBytesDefault", MAX_BYTES_DEFAULT),
            ("proxyUpstreamMaxBytes", PROXY_UPSTREAM_MAX_BYTES as i64),
            ("proxyBasepathMaxBytes", PROXY_BASEPATH_MAX_BYTES as i64),
            ("proxyHeaderMaxBytes", PROXY_HEADER_MAX_BYTES as i64),
            ("proxyFormatMaxBytes", PROXY_FORMAT_MAX_BYTES as i64),
            ("headerValueMaxBytes", HEADER_VALUE_MAX_BYTES as i64),
            ("documentMaxBytes", DOCUMENT_MAX_BYTES as i64),
            ("documentTextMaxBytes", DOCUMENT_TEXT_MAX_BYTES as i64),
            ("documentMaxDepth", DOCUMENT_MAX_DEPTH as i64),
            ("bundleHeaderBytes", BUNDLE_HEADER_BYTES as i64),
            ("bundleFileCountMax", BUNDLE_FILE_COUNT_MAX as i64),
            ("bundlePathMaxBytes", BUNDLE_PATH_MAX_BYTES as i64),
            (
                "bundlePathTotalMaxBytes",
                BUNDLE_PATH_TOTAL_MAX_BYTES as i64,
            ),
            ("bundleEnvCountMax", BUNDLE_ENV_COUNT_MAX as i64),
            ("bundleFixedMaxBytes", BUNDLE_FIXED_MAX_BYTES as i64),
        ];
        for (key, value) in pairs {
            assert_eq!(get(key), *value, "{key}");
        }
        assert_eq!(
            json.as_object().unwrap().len(),
            pairs.len(),
            "every limit is pinned"
        );
    }

    #[test]
    fn fixed_bundle_bound_is_the_plan_formula() {
        let entry = 3 + ENV_NAME_MAX_BYTES + ENV_VALUE_MAX_BYTES;
        let fixed = BUNDLE_HEADER_BYTES
            + 9 * BUNDLE_FILE_COUNT_MAX
            + BUNDLE_PATH_TOTAL_MAX_BYTES
            + BUNDLE_ENV_COUNT_MAX * entry;
        assert_eq!(fixed, BUNDLE_FIXED_MAX_BYTES);
        assert_eq!(bundle_max_encoded_bytes(4_194_304), 4_823_129);
    }
}
