# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities privately, not via public issues:

- Preferred: open a private advisory on the repository's
  [Security tab](https://github.com/FlyCockpit/ws-sandbox-proxy/security/advisories/new).

We aim to acknowledge reports within 72 hours.

## Supported versions

Only the latest release on the default branch is supported.

## Controls shipped by default

- pnpm 12 supply-chain hardening — release-age gate, exotic-subdep blocking,
  build-script allowlist, sha512-pinned package manager.
- SHA-pinned GitHub Actions kept current by Dependabot.
- Trufflehog verified-secret scanning on every PR.
- Trivy HIGH/CRITICAL image scanning on every container build.
- `pnpm audit` on every PR with `--audit-level=high`.
- Non-root `USER node` in the production server and worker images.
- Content-Security-Policy and `secureHeaders` middleware.
- Tiered rate limiting (signup stricter than generic auth).
- Production-boot guards in `packages/env`: a weak `BETTER_AUTH_SECRET` refuses
  to start in production.

See `AGENTS.md` for the guardrails coding agents must respect (auth, CSRF,
secrets, destructive database commands).

## Features that need a paid GitHub tier

The defaults above work on any repository. These are intentionally not shipped
because they require GitHub Advanced Security on private repos:

- CodeQL
- GitHub Dependency Review Action
