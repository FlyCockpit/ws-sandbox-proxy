//! Shared conformance vectors from `packages/login-definition/vectors/`,
//! also consumed by `packages/login-definition/src/vectors.test.ts`. Every file
//! is embedded with `include_str!`/`include_bytes!`; `listings_match_disk`
//! fails when a vector is added without being listed here.

use std::collections::BTreeMap;

use login_definition::bundle::{BundleFile, BundleFileKind};
use login_definition::canonical::{canonical_json, definition_digest, digest_from_hex, to_hex};
use login_definition::limits::{BUNDLE_PATH_MAX_BYTES, ENV_NAME_MAX_BYTES};
use login_definition::{
    Bundle, BundleEnv, DefinitionErrorCode, LoginDefinition, ValidatedHeaderValue, decode_bundle,
    encode_bundle, parse_definition, parse_definition_str, serialize_bundle_unchecked,
};
use serde_json::Value;

const VALID: &[(&str, &str)] = &[
    (
        "claude-code.json",
        include_str!("../../../packages/login-definition/vectors/valid/claude-code.json"),
    ),
    (
        "codex-cli.json",
        include_str!("../../../packages/login-definition/vectors/valid/codex-cli.json"),
    ),
    (
        "extension-integral-floats.json",
        include_str!(
            "../../../packages/login-definition/vectors/valid/extension-integral-floats.json"
        ),
    ),
    (
        "extensions.json",
        include_str!("../../../packages/login-definition/vectors/valid/extensions.json"),
    ),
    (
        "files-exclude.json",
        include_str!("../../../packages/login-definition/vectors/valid/files-exclude.json"),
    ),
    (
        "minimal-env.json",
        include_str!("../../../packages/login-definition/vectors/valid/minimal-env.json"),
    ),
    (
        "proxy-bearer.json",
        include_str!("../../../packages/login-definition/vectors/valid/proxy-bearer.json"),
    ),
];

const INVALID: &[(&str, &str)] = &[
    (
        "bare-x-key.json",
        include_str!("../../../packages/login-definition/vectors/invalid/bare-x-key.json"),
    ),
    (
        "credentials-missing.json",
        include_str!("../../../packages/login-definition/vectors/invalid/credentials-missing.json"),
    ),
    (
        "display-name-control.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/display-name-control.json"
        ),
    ),
    (
        "display-name-empty.json",
        include_str!("../../../packages/login-definition/vectors/invalid/display-name-empty.json"),
    ),
    (
        "done-when-string.json",
        include_str!("../../../packages/login-definition/vectors/invalid/done-when-string.json"),
    ),
    (
        "egress-duplicate.json",
        include_str!("../../../packages/login-definition/vectors/invalid/egress-duplicate.json"),
    ),
    (
        "egress-ip.json",
        include_str!("../../../packages/login-definition/vectors/invalid/egress-ip.json"),
    ),
    (
        "egress-missing-domains.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/egress-missing-domains.json"
        ),
    ),
    (
        "egress-single-label.json",
        include_str!("../../../packages/login-definition/vectors/invalid/egress-single-label.json"),
    ),
    (
        "egress-uppercase.json",
        include_str!("../../../packages/login-definition/vectors/invalid/egress-uppercase.json"),
    ),
    (
        "egress-url.json",
        include_str!("../../../packages/login-definition/vectors/invalid/egress-url.json"),
    ),
    (
        "egress-wildcard.json",
        include_str!("../../../packages/login-definition/vectors/invalid/egress-wildcard.json"),
    ),
    (
        "env-duplicate.json",
        include_str!("../../../packages/login-definition/vectors/invalid/env-duplicate.json"),
    ),
    (
        "env-name-digit.json",
        include_str!("../../../packages/login-definition/vectors/invalid/env-name-digit.json"),
    ),
    (
        "env-name-empty.json",
        include_str!("../../../packages/login-definition/vectors/invalid/env-name-empty.json"),
    ),
    (
        "env-name-home.json",
        include_str!("../../../packages/login-definition/vectors/invalid/env-name-home.json"),
    ),
    (
        "env-name-hyphen.json",
        include_str!("../../../packages/login-definition/vectors/invalid/env-name-hyphen.json"),
    ),
    (
        "env-name-ld.json",
        include_str!("../../../packages/login-definition/vectors/invalid/env-name-ld.json"),
    ),
    (
        "env-name-path.json",
        include_str!("../../../packages/login-definition/vectors/invalid/env-name-path.json"),
    ),
    (
        "env-name-shell.json",
        include_str!("../../../packages/login-definition/vectors/invalid/env-name-shell.json"),
    ),
    (
        "env-name-term.json",
        include_str!("../../../packages/login-definition/vectors/invalid/env-name-term.json"),
    ),
    (
        "env-required-missing.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/env-required-missing.json"
        ),
    ),
    (
        "exclude-equals-included.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/exclude-equals-included.json"
        ),
    ),
    (
        "exclude-not-below.json",
        include_str!("../../../packages/login-definition/vectors/invalid/exclude-not-below.json"),
    ),
    (
        "exclude-overlap.json",
        include_str!("../../../packages/login-definition/vectors/invalid/exclude-overlap.json"),
    ),
    (
        "exclude-sibling-prefix.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/exclude-sibling-prefix.json"
        ),
    ),
    (
        "format-cr.json",
        include_str!("../../../packages/login-definition/vectors/invalid/format-cr.json"),
    ),
    (
        "format-crlf-injection.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/format-crlf-injection.json"
        ),
    ),
    (
        "format-del.json",
        include_str!("../../../packages/login-definition/vectors/invalid/format-del.json"),
    ),
    (
        "format-leading-space.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/format-leading-space.json"
        ),
    ),
    (
        "format-lf.json",
        include_str!("../../../packages/login-definition/vectors/invalid/format-lf.json"),
    ),
    (
        "format-no-value.json",
        include_str!("../../../packages/login-definition/vectors/invalid/format-no-value.json"),
    ),
    (
        "format-nul.json",
        include_str!("../../../packages/login-definition/vectors/invalid/format-nul.json"),
    ),
    (
        "format-trailing-tab.json",
        include_str!("../../../packages/login-definition/vectors/invalid/format-trailing-tab.json"),
    ),
    (
        "format-two-values.json",
        include_str!("../../../packages/login-definition/vectors/invalid/format-two-values.json"),
    ),
    (
        "fraction-in-extension.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/fraction-in-extension.json"
        ),
    ),
    (
        "header-colon.json",
        include_str!("../../../packages/login-definition/vectors/invalid/header-colon.json"),
    ),
    (
        "header-connection.json",
        include_str!("../../../packages/login-definition/vectors/invalid/header-connection.json"),
    ),
    (
        "header-content-length.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/header-content-length.json"
        ),
    ),
    (
        "header-empty.json",
        include_str!("../../../packages/login-definition/vectors/invalid/header-empty.json"),
    ),
    (
        "header-expect.json",
        include_str!("../../../packages/login-definition/vectors/invalid/header-expect.json"),
    ),
    (
        "header-forwarded.json",
        include_str!("../../../packages/login-definition/vectors/invalid/header-forwarded.json"),
    ),
    (
        "header-host.json",
        include_str!("../../../packages/login-definition/vectors/invalid/header-host.json"),
    ),
    (
        "header-keep-alive.json",
        include_str!("../../../packages/login-definition/vectors/invalid/header-keep-alive.json"),
    ),
    (
        "header-proxy-prefix.json",
        include_str!("../../../packages/login-definition/vectors/invalid/header-proxy-prefix.json"),
    ),
    (
        "header-space.json",
        include_str!("../../../packages/login-definition/vectors/invalid/header-space.json"),
    ),
    (
        "header-te.json",
        include_str!("../../../packages/login-definition/vectors/invalid/header-te.json"),
    ),
    (
        "header-trailer.json",
        include_str!("../../../packages/login-definition/vectors/invalid/header-trailer.json"),
    ),
    (
        "header-transfer-encoding.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/header-transfer-encoding.json"
        ),
    ),
    (
        "header-upgrade.json",
        include_str!("../../../packages/login-definition/vectors/invalid/header-upgrade.json"),
    ),
    (
        "header-via.json",
        include_str!("../../../packages/login-definition/vectors/invalid/header-via.json"),
    ),
    (
        "header-x-forwarded.json",
        include_str!("../../../packages/login-definition/vectors/invalid/header-x-forwarded.json"),
    ),
    (
        "id-empty.json",
        include_str!("../../../packages/login-definition/vectors/invalid/id-empty.json"),
    ),
    (
        "id-leading-hyphen.json",
        include_str!("../../../packages/login-definition/vectors/invalid/id-leading-hyphen.json"),
    ),
    (
        "id-underscore.json",
        include_str!("../../../packages/login-definition/vectors/invalid/id-underscore.json"),
    ),
    (
        "id-uppercase.json",
        include_str!("../../../packages/login-definition/vectors/invalid/id-uppercase.json"),
    ),
    (
        "install-needs-root-string.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/install-needs-root-string.json"
        ),
    ),
    (
        "login-command-empty.json",
        include_str!("../../../packages/login-definition/vectors/invalid/login-command-empty.json"),
    ),
    (
        "login-command-nul.json",
        include_str!("../../../packages/login-definition/vectors/invalid/login-command-nul.json"),
    ),
    (
        "login-method-unknown.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/login-method-unknown.json"
        ),
    ),
    (
        "login-missing.json",
        include_str!("../../../packages/login-definition/vectors/invalid/login-missing.json"),
    ),
    (
        "lone-surrogate.json",
        include_str!("../../../packages/login-definition/vectors/invalid/lone-surrogate.json"),
    ),
    (
        "max-bytes-string.json",
        include_str!("../../../packages/login-definition/vectors/invalid/max-bytes-string.json"),
    ),
    (
        "max-bytes-zero.json",
        include_str!("../../../packages/login-definition/vectors/invalid/max-bytes-zero.json"),
    ),
    (
        "near-integer-fraction-in-extension.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/near-integer-fraction-in-extension.json"
        ),
    ),
    (
        "no-files-no-env.json",
        include_str!("../../../packages/login-definition/vectors/invalid/no-files-no-env.json"),
    ),
    (
        "not-an-object.json",
        include_str!("../../../packages/login-definition/vectors/invalid/not-an-object.json"),
    ),
    (
        "null-optional.json",
        include_str!("../../../packages/login-definition/vectors/invalid/null-optional.json"),
    ),
    (
        "only-excludes.json",
        include_str!("../../../packages/login-definition/vectors/invalid/only-excludes.json"),
    ),
    (
        "path-absolute.json",
        include_str!("../../../packages/login-definition/vectors/invalid/path-absolute.json"),
    ),
    (
        "path-backslash.json",
        include_str!("../../../packages/login-definition/vectors/invalid/path-backslash.json"),
    ),
    (
        "path-colon.json",
        include_str!("../../../packages/login-definition/vectors/invalid/path-colon.json"),
    ),
    (
        "path-del.json",
        include_str!("../../../packages/login-definition/vectors/invalid/path-del.json"),
    ),
    (
        "path-dot.json",
        include_str!("../../../packages/login-definition/vectors/invalid/path-dot.json"),
    ),
    (
        "path-dotdot.json",
        include_str!("../../../packages/login-definition/vectors/invalid/path-dotdot.json"),
    ),
    (
        "path-double-slash.json",
        include_str!("../../../packages/login-definition/vectors/invalid/path-double-slash.json"),
    ),
    (
        "path-duplicate.json",
        include_str!("../../../packages/login-definition/vectors/invalid/path-duplicate.json"),
    ),
    (
        "path-empty.json",
        include_str!("../../../packages/login-definition/vectors/invalid/path-empty.json"),
    ),
    (
        "path-newline.json",
        include_str!("../../../packages/login-definition/vectors/invalid/path-newline.json"),
    ),
    (
        "path-nul.json",
        include_str!("../../../packages/login-definition/vectors/invalid/path-nul.json"),
    ),
    (
        "path-overlap.json",
        include_str!("../../../packages/login-definition/vectors/invalid/path-overlap.json"),
    ),
    (
        "path-staging-directory.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/path-staging-directory.json"
        ),
    ),
    (
        "path-staging-nested.json",
        include_str!("../../../packages/login-definition/vectors/invalid/path-staging-nested.json"),
    ),
    (
        "path-staging-prefix.json",
        include_str!("../../../packages/login-definition/vectors/invalid/path-staging-prefix.json"),
    ),
    (
        "path-trailing-slash.json",
        include_str!("../../../packages/login-definition/vectors/invalid/path-trailing-slash.json"),
    ),
    (
        "path-wssp-prefix.json",
        include_str!("../../../packages/login-definition/vectors/invalid/path-wssp-prefix.json"),
    ),
    (
        "path-wssp.json",
        include_str!("../../../packages/login-definition/vectors/invalid/path-wssp.json"),
    ),
    (
        "proto-key-credentials-env-entry.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/proto-key-credentials-env-entry.json"
        ),
    ),
    (
        "proto-key-credentials-env-proxy.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/proto-key-credentials-env-proxy.json"
        ),
    ),
    (
        "proto-key-credentials-files.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/proto-key-credentials-files.json"
        ),
    ),
    (
        "proto-key-credentials.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/proto-key-credentials.json"
        ),
    ),
    (
        "proto-key-document.json",
        include_str!("../../../packages/login-definition/vectors/invalid/proto-key-document.json"),
    ),
    (
        "proto-key-install.json",
        include_str!("../../../packages/login-definition/vectors/invalid/proto-key-install.json"),
    ),
    (
        "proto-key-login-egress.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/proto-key-login-egress.json"
        ),
    ),
    (
        "proto-key-login.json",
        include_str!("../../../packages/login-definition/vectors/invalid/proto-key-login.json"),
    ),
    (
        "proxy-base-url-duplicate.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/proxy-base-url-duplicate.json"
        ),
    ),
    (
        "proxy-base-url-is-entry.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/proxy-base-url-is-entry.json"
        ),
    ),
    (
        "proxy-base-url-reserved.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/proxy-base-url-reserved.json"
        ),
    ),
    (
        "proxy-missing-format.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/proxy-missing-format.json"
        ),
    ),
    (
        "proxy-mixed.json",
        include_str!("../../../packages/login-definition/vectors/invalid/proxy-mixed.json"),
    ),
    (
        "proxy-placeholder-equals-base-url.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/proxy-placeholder-equals-base-url.json"
        ),
    ),
    (
        "proxy-placeholder-other-entry.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/proxy-placeholder-other-entry.json"
        ),
    ),
    (
        "proxy-with-files.json",
        include_str!("../../../packages/login-definition/vectors/invalid/proxy-with-files.json"),
    ),
    (
        "rotates-boolean.json",
        include_str!("../../../packages/login-definition/vectors/invalid/rotates-boolean.json"),
    ),
    (
        "schema-version-0.json",
        include_str!("../../../packages/login-definition/vectors/invalid/schema-version-0.json"),
    ),
    (
        "schema-version-2.json",
        include_str!("../../../packages/login-definition/vectors/invalid/schema-version-2.json"),
    ),
    (
        "schema-version-99-otherwise-invalid.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/schema-version-99-otherwise-invalid.json"
        ),
    ),
    (
        "schema-version-fraction.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/schema-version-fraction.json"
        ),
    ),
    (
        "schema-version-missing.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/schema-version-missing.json"
        ),
    ),
    (
        "schema-version-string.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/schema-version-string.json"
        ),
    ),
    (
        "sharing-unknown.json",
        include_str!("../../../packages/login-definition/vectors/invalid/sharing-unknown.json"),
    ),
    (
        "string-document.json",
        include_str!("../../../packages/login-definition/vectors/invalid/string-document.json"),
    ),
    (
        "unknown-key-credentials.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/unknown-key-credentials.json"
        ),
    ),
    (
        "unknown-key-egress.json",
        include_str!("../../../packages/login-definition/vectors/invalid/unknown-key-egress.json"),
    ),
    (
        "unknown-key-env.json",
        include_str!("../../../packages/login-definition/vectors/invalid/unknown-key-env.json"),
    ),
    (
        "unknown-key-files.json",
        include_str!("../../../packages/login-definition/vectors/invalid/unknown-key-files.json"),
    ),
    (
        "unknown-key-install.json",
        include_str!("../../../packages/login-definition/vectors/invalid/unknown-key-install.json"),
    ),
    (
        "unknown-key-login.json",
        include_str!("../../../packages/login-definition/vectors/invalid/unknown-key-login.json"),
    ),
    (
        "unknown-key-proxy.json",
        include_str!("../../../packages/login-definition/vectors/invalid/unknown-key-proxy.json"),
    ),
    (
        "unknown-key-top.json",
        include_str!("../../../packages/login-definition/vectors/invalid/unknown-key-top.json"),
    ),
    (
        "unsafe-integer-in-extension.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/unsafe-integer-in-extension.json"
        ),
    ),
    (
        "uppercase-x-key.json",
        include_str!("../../../packages/login-definition/vectors/invalid/uppercase-x-key.json"),
    ),
    (
        "upstream-backslash.json",
        include_str!("../../../packages/login-definition/vectors/invalid/upstream-backslash.json"),
    ),
    (
        "upstream-bad-escape.json",
        include_str!("../../../packages/login-definition/vectors/invalid/upstream-bad-escape.json"),
    ),
    (
        "upstream-dot-segment.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/upstream-dot-segment.json"
        ),
    ),
    (
        "upstream-double-slash.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/upstream-double-slash.json"
        ),
    ),
    (
        "upstream-encoded-dot.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/upstream-encoded-dot.json"
        ),
    ),
    (
        "upstream-encoded-slash-lower.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/upstream-encoded-slash-lower.json"
        ),
    ),
    (
        "upstream-encoded-slash.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/upstream-encoded-slash.json"
        ),
    ),
    (
        "upstream-encoded-unreserved.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/upstream-encoded-unreserved.json"
        ),
    ),
    (
        "upstream-fragment.json",
        include_str!("../../../packages/login-definition/vectors/invalid/upstream-fragment.json"),
    ),
    (
        "upstream-http.json",
        include_str!("../../../packages/login-definition/vectors/invalid/upstream-http.json"),
    ),
    (
        "upstream-ipv4-lookalike.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/upstream-ipv4-lookalike.json"
        ),
    ),
    (
        "upstream-ipv4.json",
        include_str!("../../../packages/login-definition/vectors/invalid/upstream-ipv4.json"),
    ),
    (
        "upstream-ipv6.json",
        include_str!("../../../packages/login-definition/vectors/invalid/upstream-ipv6.json"),
    ),
    (
        "upstream-port-empty.json",
        include_str!("../../../packages/login-definition/vectors/invalid/upstream-port-empty.json"),
    ),
    (
        "upstream-port-high.json",
        include_str!("../../../packages/login-definition/vectors/invalid/upstream-port-high.json"),
    ),
    (
        "upstream-port-leading-zero.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/upstream-port-leading-zero.json"
        ),
    ),
    (
        "upstream-port-zero.json",
        include_str!("../../../packages/login-definition/vectors/invalid/upstream-port-zero.json"),
    ),
    (
        "upstream-query.json",
        include_str!("../../../packages/login-definition/vectors/invalid/upstream-query.json"),
    ),
    (
        "upstream-single-label.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/upstream-single-label.json"
        ),
    ),
    (
        "upstream-space.json",
        include_str!("../../../packages/login-definition/vectors/invalid/upstream-space.json"),
    ),
    (
        "upstream-trailing-dot.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/upstream-trailing-dot.json"
        ),
    ),
    (
        "upstream-trailing-slash.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/upstream-trailing-slash.json"
        ),
    ),
    (
        "upstream-uppercase-host.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/upstream-uppercase-host.json"
        ),
    ),
    (
        "upstream-uppercase-scheme.json",
        include_str!(
            "../../../packages/login-definition/vectors/invalid/upstream-uppercase-scheme.json"
        ),
    ),
    (
        "upstream-userinfo.json",
        include_str!("../../../packages/login-definition/vectors/invalid/upstream-userinfo.json"),
    ),
];

const BUNDLES: &[(&str, &[u8])] = &[
    (
        "absolute.bin",
        include_bytes!("../../../packages/login-definition/vectors/bundles/absolute.bin"),
    ),
    (
        "bad-kind.bin",
        include_bytes!("../../../packages/login-definition/vectors/bundles/bad-kind.bin"),
    ),
    (
        "bad-magic.bin",
        include_bytes!("../../../packages/login-definition/vectors/bundles/bad-magic.bin"),
    ),
    (
        "codex-auth.bin",
        include_bytes!("../../../packages/login-definition/vectors/bundles/codex-auth.bin"),
    ),
    (
        "data-over-max-bytes.bin",
        include_bytes!(
            "../../../packages/login-definition/vectors/bundles/data-over-max-bytes.bin"
        ),
    ),
    (
        "digest-mismatch.bin",
        include_bytes!("../../../packages/login-definition/vectors/bundles/digest-mismatch.bin"),
    ),
    (
        "dir-mode-0755.bin",
        include_bytes!("../../../packages/login-definition/vectors/bundles/dir-mode-0755.bin"),
    ),
    (
        "dir-with-data.bin",
        include_bytes!("../../../packages/login-definition/vectors/bundles/dir-with-data.bin"),
    ),
    (
        "dot-dot.bin",
        include_bytes!("../../../packages/login-definition/vectors/bundles/dot-dot.bin"),
    ),
    (
        "duplicate.bin",
        include_bytes!("../../../packages/login-definition/vectors/bundles/duplicate.bin"),
    ),
    (
        "empty-path.bin",
        include_bytes!("../../../packages/login-definition/vectors/bundles/empty-path.bin"),
    ),
    (
        "empty.bin",
        include_bytes!("../../../packages/login-definition/vectors/bundles/empty.bin"),
    ),
    (
        "env-duplicate.bin",
        include_bytes!("../../../packages/login-definition/vectors/bundles/env-duplicate.bin"),
    ),
    (
        "env-nul.bin",
        include_bytes!("../../../packages/login-definition/vectors/bundles/env-nul.bin"),
    ),
    (
        "excluded-path.bin",
        include_bytes!("../../../packages/login-definition/vectors/bundles/excluded-path.bin"),
    ),
    (
        "mode-0644.bin",
        include_bytes!("../../../packages/login-definition/vectors/bundles/mode-0644.bin"),
    ),
    (
        "non-utf8-path.bin",
        include_bytes!("../../../packages/login-definition/vectors/bundles/non-utf8-path.bin"),
    ),
    (
        "tool-mixed.bin",
        include_bytes!("../../../packages/login-definition/vectors/bundles/tool-mixed.bin"),
    ),
    (
        "trailing-byte.bin",
        include_bytes!("../../../packages/login-definition/vectors/bundles/trailing-byte.bin"),
    ),
    (
        "truncated-data.bin",
        include_bytes!("../../../packages/login-definition/vectors/bundles/truncated-data.bin"),
    ),
    (
        "truncated-header.bin",
        include_bytes!("../../../packages/login-definition/vectors/bundles/truncated-header.bin"),
    ),
    (
        "undeclared-env.bin",
        include_bytes!("../../../packages/login-definition/vectors/bundles/undeclared-env.bin"),
    ),
    (
        "undeclared-path.bin",
        include_bytes!("../../../packages/login-definition/vectors/bundles/undeclared-path.bin"),
    ),
    (
        "under-file.bin",
        include_bytes!("../../../packages/login-definition/vectors/bundles/under-file.bin"),
    ),
    (
        "unsorted.bin",
        include_bytes!("../../../packages/login-definition/vectors/bundles/unsorted.bin"),
    ),
    (
        "version-2.bin",
        include_bytes!("../../../packages/login-definition/vectors/bundles/version-2.bin"),
    ),
];

const DIGESTS: &str = include_str!("../../../packages/login-definition/vectors/digests.json");
const CANONICAL: &str = include_str!("../../../packages/login-definition/vectors/canonical.json");
const HEADERS: &str = include_str!("../../../packages/login-definition/vectors/headers/cases.json");
const BUNDLE_CASES: &str =
    include_str!("../../../packages/login-definition/vectors/bundles/cases.json");
const MAX_DEFINITIONS: &str =
    include_str!("../../../packages/login-definition/vectors/max-inputs/definitions.json");
const MAX_BUNDLE: &str =
    include_str!("../../../packages/login-definition/vectors/max-inputs/bundle.json");

fn json(text: &str) -> Value {
    serde_json::from_str(text).expect("vector file is JSON")
}

fn definition_of(name: &str) -> (LoginDefinition, [u8; 32]) {
    let (_, text) = VALID
        .iter()
        .find(|(n, _)| *n == name)
        .expect("valid vector");
    let (document, parsed) = parse_definition_str(text).expect("valid vector parses");
    (
        parsed.definition,
        definition_digest(&document).expect("digest"),
    )
}

#[test]
fn listings_match_disk() {
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../packages/login-definition/vectors"
    );
    let on_disk = |sub: &str, ext: &str| {
        let mut names: Vec<String> = std::fs::read_dir(format!("{dir}/{sub}"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n.ends_with(ext))
            .collect();
        names.sort();
        names
    };
    let listed = |items: &[&str]| items.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    assert_eq!(
        on_disk("valid", ".json"),
        listed(&VALID.iter().map(|v| v.0).collect::<Vec<_>>())
    );
    assert_eq!(
        on_disk("invalid", ".json"),
        listed(&INVALID.iter().map(|v| v.0).collect::<Vec<_>>())
    );
    assert_eq!(
        on_disk("bundles", ".bin"),
        listed(&BUNDLES.iter().map(|v| v.0).collect::<Vec<_>>())
    );
}

#[test]
fn valid_definitions_and_digests() {
    let digests = json(DIGESTS);
    assert_eq!(digests.as_object().unwrap().len(), VALID.len());
    for (name, text) in VALID {
        let expected = &digests[*name];
        let (document, parsed) =
            parse_definition_str(text).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let warnings: Vec<&str> = parsed.warnings.iter().map(|w| w.as_str()).collect();
        let expected_warnings: Vec<&str> = expected["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w.as_str().unwrap())
            .collect();
        assert_eq!(warnings, expected_warnings, "{name}");
        assert_eq!(
            canonical_json(&document).unwrap(),
            expected["canonical"],
            "{name}"
        );
        assert_eq!(
            to_hex(&definition_digest(&document).unwrap()),
            expected["digest"],
            "{name}"
        );
        assert_eq!(to_hex(&parsed.digest), expected["digest"], "{name}");
    }
}

#[test]
fn invalid_definitions() {
    assert!(INVALID.len() > 100);
    for (name, text) in INVALID {
        let vector = json(text);
        let expect = vector["expect"].as_str().unwrap();
        let result = match vector.get("documentText") {
            Some(Value::String(raw)) => parse_definition_str(raw).map(|(_, p)| p),
            _ => parse_definition(&vector["document"]),
        };
        let error = result
            .err()
            .unwrap_or_else(|| panic!("{name} was accepted"));
        assert_eq!(error.code.as_str(), expect, "{name}");
    }
}

#[test]
fn canonical_json_cases() {
    for case in json(CANONICAL)["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let parsed: Result<Value, _> = serde_json::from_str(case["text"].as_str().unwrap());
        let actual = parsed.ok().and_then(|v| canonical_json(&v).ok());
        match case["canonical"].as_str() {
            Some(expected) => assert_eq!(actual.as_deref(), Some(expected), "{name}"),
            None => assert_eq!(actual, None, "{name}"),
        }
    }
}

#[test]
fn header_value_cases() {
    for case in json(HEADERS)["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let value: Vec<u8> = if let Some(text) = case["value"].as_str() {
            text.as_bytes().to_vec()
        } else if let Some(hex) = case["valueHex"].as_str() {
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect()
        } else {
            let repeat = &case["valueRepeat"];
            vec![
                u8::try_from(repeat["byte"].as_u64().unwrap()).unwrap();
                usize::try_from(repeat["count"].as_u64().unwrap()).unwrap()
            ]
        };
        let result = ValidatedHeaderValue::new(case["format"].as_str().unwrap(), &value);
        assert_eq!(result.is_ok(), case["ok"].as_bool().unwrap(), "{name}");
        if let Ok(header) = result {
            assert!(
                !format!("{header:?}").contains("sk-test"),
                "{name}: Debug is redacted"
            );
        }
    }
}

#[test]
fn max_input_definitions() {
    let cases = json(MAX_DEFINITIONS);
    let cases = cases["cases"].as_array().unwrap();
    assert!(cases.len() > 40);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let result = match case.get("textPadding").and_then(Value::as_u64) {
            None => parse_definition(&case["document"]),
            Some(padding) => {
                let mut text = canonical_json(&case["document"]).unwrap();
                text.push_str(&" ".repeat(usize::try_from(padding).unwrap()));
                parse_definition_str(&text).map(|(_, parsed)| parsed)
            }
        };
        assert_eq!(
            result.is_ok(),
            case["ok"].as_bool().unwrap(),
            "{name}: {result:?}"
        );
        if let Err(error) = result {
            assert_eq!(error.code, DefinitionErrorCode::Invalid, "{name}");
            if let Some(first) = case.get("firstIssue") {
                let issue = &error.issues[0];
                assert_eq!(issue.path, first["path"], "{name}");
                assert_eq!(issue.message, first["message"], "{name}");
            }
        }
    }
}

#[test]
fn bundle_cases() {
    for case in json(BUNDLE_CASES)["cases"].as_array().unwrap() {
        let file = case["file"].as_str().unwrap();
        let (definition, digest) = definition_of(case["definition"].as_str().unwrap());
        let (_, bytes) = BUNDLES
            .iter()
            .find(|(n, _)| *n == file)
            .expect("listed bundle");
        let expect = case["expect"].as_str().unwrap();
        let result = decode_bundle(bytes, &definition, &digest);
        if expect != "ok" {
            let error = result.err().unwrap_or_else(|| panic!("{file} decoded"));
            assert_eq!(error.reason.as_str(), expect, "{file}");
            continue;
        }
        let bundle = result.unwrap_or_else(|e| panic!("{file}: {e}"));
        let mut files = Vec::new();
        for f in &bundle.files {
            let mut entry = serde_json::Map::new();
            let kind = if f.kind == BundleFileKind::File {
                "file"
            } else {
                "dir"
            };
            entry.insert("kind".into(), kind.into());
            entry.insert("path".into(), f.path.into());
            entry.insert("mode".into(), f.mode.into());
            if f.kind == BundleFileKind::File {
                entry.insert("dataHex".into(), to_hex(f.data).into());
            }
            files.push(Value::Object(entry));
        }
        let env: Vec<Value> = bundle
            .env
            .iter()
            .map(|e| serde_json::json!({ "name": e.name, "valueHex": to_hex(e.value) }))
            .collect();
        assert_eq!(
            serde_json::json!({ "files": files, "env": env }),
            case["decoded"],
            "{file}"
        );
        assert_eq!(
            encode_bundle(&bundle, &definition).unwrap().as_bytes(),
            *bytes,
            "{file} re-encodes"
        );
    }
}

fn padded(head: String, fill: char, bytes: usize) -> String {
    let mut s = head;
    while s.len() < bytes {
        s.push(fill);
    }
    s
}

/// Owned storage for the exact-maximum bundle; [`MaxBundle::view`] borrows it.
struct MaxBundle {
    digest: [u8; 32],
    files: Vec<(String, Vec<u8>)>,
    env: Vec<(String, Vec<u8>)>,
}

impl MaxBundle {
    fn view(&self) -> Bundle<'_> {
        Bundle {
            definition_digest: self.digest,
            files: self
                .files
                .iter()
                .map(|(path, data)| BundleFile {
                    kind: BundleFileKind::File,
                    path,
                    mode: 0o600,
                    data,
                })
                .collect(),
            env: self
                .env
                .iter()
                .map(|(name, value)| BundleEnv { name, value })
                .collect(),
        }
    }
}

/// Mirrors `buildMaxBundle` in `packages/login-definition/scripts/generated.ts`.
fn build_max_bundle(recipe: &Value, digest: [u8; 32], variant: Option<&str>) -> MaxBundle {
    let n = |key: &str| usize::try_from(recipe[key].as_u64().unwrap()).unwrap();
    let (file_count, path_bytes, env_count) = (n("fileCount"), n("pathBytes"), n("envCount"));
    let (name_bytes, value_bytes, max_bytes) =
        (n("envNameBytes"), n("envValueBytes"), n("maxBytes"));
    let is = |v: &str| variant == Some(v);
    let path = |i: usize, bytes: usize| padded(format!("d/{i:06}"), 'x', bytes);
    let env_name = |i: usize, bytes: usize| padded(format!("E{i:02}"), '_', bytes);
    let files = (0..file_count + usize::from(is("file-count-plus-one")))
        .map(|i| {
            let mut p = path(i, path_bytes);
            if is("path-length-plus-one") && i == 0 {
                p = path(0, BUNDLE_PATH_MAX_BYTES + 1);
            }
            if is("path-total-plus-one") && i == file_count - 1 {
                p = path(i, path_bytes + 1);
            }
            let size = if i == 0 {
                max_bytes + usize::from(is("data-total-plus-one"))
            } else {
                0
            };
            (p, vec![b'a'; size])
        })
        .collect();
    let env = (0..env_count + usize::from(is("env-count-plus-one")))
        .map(|i| {
            let name = if is("env-name-length-plus-one") && i == env_count - 1 {
                env_name(i, ENV_NAME_MAX_BYTES + 1)
            } else {
                env_name(i, name_bytes)
            };
            let size = value_bytes + usize::from(is("env-value-length-plus-one") && i == 0);
            (name, vec![b'v'; size])
        })
        .collect();
    MaxBundle { digest, files, env }
}

#[test]
fn exact_maximum_bundle() {
    let recipe = json(MAX_BUNDLE);
    let parsed = parse_definition(&recipe["definition"]).unwrap();
    let digest = digest_from_hex(recipe["definitionDigest"].as_str().unwrap()).unwrap();
    assert_eq!(definition_digest(&recipe["definition"]).unwrap(), digest);
    assert_eq!(recipe["expectedBytes"], 4_823_129);

    let bundle = build_max_bundle(&recipe, digest, None);
    let bytes = encode_bundle(&bundle.view(), &parsed.definition).unwrap();
    assert_eq!(bytes.len(), 4_823_129);
    let decoded = decode_bundle(bytes.as_bytes(), &parsed.definition, &digest).unwrap();
    assert_eq!(decoded.files.len(), 4096);
    assert_eq!(decoded.env.len(), 16);

    let mut seen = BTreeMap::new();
    for variant in recipe["variants"].as_array().unwrap() {
        let name = variant["name"].as_str().unwrap();
        let bytes =
            serialize_bundle_unchecked(&build_max_bundle(&recipe, digest, Some(name)).view());
        let error = decode_bundle(bytes.as_bytes(), &parsed.definition, &digest).unwrap_err();
        let encoded = encode_bundle(
            &build_max_bundle(&recipe, digest, Some(name)).view(),
            &parsed.definition,
        );
        assert_eq!(
            encoded.unwrap_err().reason,
            error.reason,
            "{name}: the encoder refuses what the decoder refuses"
        );
        assert_eq!(
            error.reason.as_str(),
            variant["expect"].as_str().unwrap(),
            "{name}"
        );
        seen.insert(name.to_owned(), ());
    }
    assert_eq!(seen.len(), 7);
}
