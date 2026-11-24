//! Identifier grammar shared by every payload: the bounded relay ids
//! (operation, sandbox, owner, request, host) and the 32-hex journal
//! identities. Leaf module: it depends on nothing else in the crate.

/// A relay id: 1..=128 ASCII alphanumerics, `-` or `_`, starting with an
/// alphanumeric.
pub fn valid_terminal_id(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && id.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A journal identity: exactly 32 lowercase hex digits.
pub(crate) fn valid_journal_identity(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
