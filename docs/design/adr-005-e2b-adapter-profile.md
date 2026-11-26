# ADR-005: E2B adapter profile

## Status

Proposed

## Context

Coding harnesses may expect E2B-shaped SDK calls. The v1 product API is
native to WS Sandbox Proxy (browser oRPC + isolated bearer `/v1` HTTP). The
[native HTTP boundary](./native-http-contract.md), its resource endpoints and the
native TypeScript SDK ([`@wssp/sdk`](../../packages/sdk/README.md)) are
implemented. An E2B-compatible facade is optional later work and does not exist
today.

## Decision

- Document supported E2B-style surfaces in [e2b-parity.md](./e2b-parity.md).
- A future adapter maps DTOs and errors explicitly; unsupported calls return
  typed failures — never silent success.
- Core daemon/runtime code does not import E2B SDKs.

## Consequences

- Conformance fixtures target the fake runtime before Linux integration
  runners.
- Public sandbox procedures remain the source of truth for lifecycle
  semantics.
- Native TypeScript SDK ships first.

The native SDK supplies E2B-shaped files and tracked commands with deliberate
divergences: bounded pages, qualified identity, typed signal refusal, proof-based
kill outcomes, checked nonzero exits and observer detach by default. It remains
neither an E2B wire facade nor an all-guest process API. See the
[filesystem and command limits](../guide/sandboxes.md#filesystem-and-command-result-limits).
