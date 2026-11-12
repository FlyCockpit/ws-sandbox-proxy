//! Incus image fingerprints and operator alias resolution.
//!
//! Templates pin an immutable host-local fingerprint. VM launch uses the
//! fingerprint only; operator aliases are resolved once at registration.

use sandbox_protocol::SandboxErrorCode;

use crate::error::RuntimeError;

/// Shared with `packages/api/src/sandbox/incus-image.ts` malicious fixtures.
pub const MALICIOUS_INCUS_IMAGE_REFS: &[&str] = &[
    "--project=default",
    "-csecurity.privileged=true",
    "--storage=attacker",
    "-ubuntu",
    "--vm",
    "images:ubuntu/24.04/cloud%00",
    " images:ubuntu/24.04/cloud",
];

const INCUS_IMAGE_MAX_LENGTH: usize = 128;
const INCUS_FINGERPRINT_HEX_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedHostImage {
    pub fingerprint: String,
    pub architecture: String,
    /// Compressed image size in bytes when the daemon reports it.
    pub size_bytes: Option<u64>,
}

pub fn is_incus_image_ref(value: &str) -> bool {
    if value.trim() != value {
        return false;
    }
    if value.is_empty()
        || value.len() > INCUS_IMAGE_MAX_LENGTH
        || value.eq_ignore_ascii_case("unknown")
    {
        return false;
    }
    if value.starts_with('-') || value.contains('%') || value.contains('\\') {
        return false;
    }
    if looks_like_content_digest(value) {
        return false;
    }
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '/' | '-' | '_' | '.'))
}

/// Canonical application/wire identity. Raw Incus hex is adapted only at IO.
pub fn is_incus_fingerprint(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == INCUS_FINGERPRINT_HEX_LEN
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

pub fn normalize_incus_fingerprint(value: &str) -> Result<String, RuntimeError> {
    if !is_incus_fingerprint(value) {
        return Err(RuntimeError::new(
            SandboxErrorCode::ProtocolError,
            "invalid Incus image fingerprint",
        ));
    }
    Ok(value.to_owned())
}

/// Only host-authoritative Incus config/inventory uses bare hexadecimal hashes.
#[cfg(target_os = "linux")]
pub(crate) fn fingerprint_from_incus(value: &str) -> Result<String, RuntimeError> {
    normalize_incus_fingerprint(&format!("sha256:{value}"))
}

pub fn require_launch_fingerprint(
    incus_fingerprint: Option<&str>,
    template_digest: &str,
) -> Result<String, RuntimeError> {
    if let Some(fp) = incus_fingerprint.filter(|value| !value.is_empty()) {
        let fingerprint = normalize_incus_fingerprint(fp)?;
        if !template_digest.is_empty()
            && normalize_incus_fingerprint(template_digest)? != fingerprint
        {
            return Err(RuntimeError::new(
                SandboxErrorCode::IdempotencyConflict,
                "template and launch fingerprints differ",
            ));
        }
        return Ok(fingerprint);
    }
    normalize_incus_fingerprint(template_digest)
}

/// A restore launches `restore` (the stored
/// disk image) while the template tag stays `template_digest`. Both must be
/// well-formed fingerprints; the template launch check does not apply.
/// Returns the normalized launch (restore) fingerprint.
pub fn require_restore_launch_fingerprint(
    restore: &str,
    template_digest: &str,
) -> Result<String, RuntimeError> {
    normalize_incus_fingerprint(template_digest)?;
    normalize_incus_fingerprint(restore)
}

fn looks_like_content_digest(value: &str) -> bool {
    let Some((algo, rest)) = value.split_once(':') else {
        return false;
    };
    matches!(algo, "sha256" | "sha512" | "sha1")
        && !rest.is_empty()
        && rest.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::{
        MALICIOUS_INCUS_IMAGE_REFS, is_incus_fingerprint, is_incus_image_ref,
        normalize_incus_fingerprint, require_launch_fingerprint,
    };
    use sandbox_protocol::SandboxErrorCode;

    const FP: &str = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    #[test]
    fn accepts_aliases_and_fingerprints() {
        assert!(is_incus_image_ref("images:ubuntu/24.04/cloud"));
        assert!(is_incus_fingerprint(FP));
        assert_eq!(normalize_incus_fingerprint(FP).expect("fp"), FP);
        assert_eq!(
            require_launch_fingerprint(Some(FP), FP).expect("launch"),
            FP
        );
    }

    #[test]
    fn rejects_digest_shaped_aliases_and_unknown() {
        assert!(!is_incus_image_ref("sha256:abc"));
        assert!(!is_incus_image_ref("unknown"));
        let err = require_launch_fingerprint(None, "images:ubuntu/24.04/cloud")
            .expect_err("alias not a fingerprint");
        assert_eq!(err.code, SandboxErrorCode::ProtocolError);
    }

    #[test]
    fn rejects_malicious_flag_shaped_image_refs() {
        for image in MALICIOUS_INCUS_IMAGE_REFS {
            assert!(!is_incus_image_ref(image), "expected reject for `{image}`");
        }
    }

    #[test]
    fn explicit_fingerprint_must_match_template_digest() {
        let other = "sha256:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
        let error = require_launch_fingerprint(Some(FP), other).expect_err("mismatched template");
        assert_eq!(error.code, SandboxErrorCode::IdempotencyConflict);
    }
}
