# Security policy

## Reporting a vulnerability

Please report security issues privately via GitHub's
[private vulnerability reporting](https://github.com/FlyCockpit/ws-sandbox-proxy/security/advisories/new)
rather than opening a public issue. We'll acknowledge and work with you on a
fix and disclosure timeline.

## What ships by default

- `unsafe_code = "forbid"` at the workspace level — no `unsafe` without an
  explicit, reviewed change.
- `cargo-deny` in CI: a license allowlist, banned/duplicate-crate checks,
  source allowlist (crates.io only), and RUSTSEC advisory scanning.
- Policy checks that grep for committed private keys, AWS keys, hook-bypass
  flags, and unsafe-lint overrides.
- SHA-pinned GitHub Actions, with Dependabot updating the pins.
- Warnings-as-errors (`-D warnings`) and clippy lints that forbid
  `unwrap()`/`panic!`/`dbg!`/`todo!` in production code.

## Supported versions

Only the latest release is supported.
