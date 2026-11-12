//! Host slug validation (`host-slug:<slug>` device login scope).

use anyhow::Result;

const MIN: usize = 1;
const MAX: usize = 63;

pub fn validate_host_slug(value: &str) -> Result<()> {
    if value.len() < MIN || value.len() > MAX {
        anyhow::bail!("host slug must be between {MIN} and {MAX} characters");
    }
    let bytes = value.as_bytes();
    if bytes.first().is_some_and(|byte| *byte == b'-')
        || bytes.last().is_some_and(|byte| *byte == b'-')
    {
        anyhow::bail!("host slug `{value}` cannot start or end with `-`");
    }
    let mut previous_hyphen = false;
    for ch in value.chars() {
        let valid = ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-';
        if !valid {
            anyhow::bail!(
                "host slug `{value}` may only contain lowercase letters, numbers, and `-`"
            );
        }
        if ch == '-' && previous_hyphen {
            anyhow::bail!("host slug `{value}` cannot contain repeated hyphens");
        }
        previous_hyphen = ch == '-';
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_host_slug_policy() {
        validate_host_slug("desk-01").expect("valid");
        assert!(validate_host_slug("").is_err());
        assert!(validate_host_slug("Desk").is_err());
        assert!(validate_host_slug("-abc").is_err());
        assert!(validate_host_slug("a--b").is_err());
    }
}
