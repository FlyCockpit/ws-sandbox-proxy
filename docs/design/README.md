# Sandbox design notes

Architecture decision records and design notes for the WS Sandbox Proxy sandbox control
plane.

## ADR index

| ADR                                              | Status   | Summary                                                                                             |
| ------------------------------------------------ | -------- | --------------------------------------------------------------------------------------------------- |
| [ADR-001](./adr-001-lifecycle-and-operations.md) | Accepted | Separate sandbox machine states and durable operation states with generation binding.               |
| [ADR-002](./adr-002-idempotency-and-outbox.md)   | Accepted | Owner-scoped idempotency keys, canonical request-body hashing, and transactional outbox rows.       |
| [ADR-003](./adr-003-host-enrollment.md)          | Accepted | Outbound WSS node daemons, `SandboxHost` / `HostToken` pairing.                                     |
| [ADR-004](./adr-004-runtime-boundary.md)         | Accepted | Control plane talks over the relay; Incus/KVM lives in `crates/sandbox-runtime` on the node daemon. |
| [ADR-005](./adr-005-e2b-adapter-profile.md)      | Proposed | Native API first; an E2B-shaped adapter is an explicit capability matrix plus unsupported errors.   |
| [ADR-006](./adr-006-agent-host-access.md)        | Accepted | Scoped agent host commands/files, node-local opt-in, ownership, queued commands and audit.          |

User-facing explanations of these decisions are in the [guide](../guide/README.md).

## Related material

- [E2B-like parity notes](./e2b-parity.md)
- [Declarative template builds](./declarative-build.md)
- [Host policy reconciliation](./host-policy-reconciliation.md)
- [Terminal relay contract](./terminal-relay-contract.md) (frames, fences, flow control, close intent)
- [Browser terminal authentication](./browser-terminal-auth.md) (tickets, refusals, re-reads and web client)
- [Device flow contract](./device-flow-contract.md) (`wssp login` exchange)
- [Webhooks contract](./webhooks-contract.md) (emission triggers, ledger state machine, signing bytes, versioning)
- [Credential vault crypto](./credential-vault.md) (CLI-login value encryption, sealed captures, envelope v1, feature gate, vectors)
- Prisma models: `packages/db/prisma/schema/sandbox.prisma`
- API domain: `packages/api/src/sandbox/`
- Public procedures: `packages/api/src/routers/sandboxes.ts`
- Runtime: `crates/sandbox-runtime/`

The [native HTTP contract](./native-http-contract.md) defines the `/v1` credential
plane, request limits, middleware order, error envelope, logging contract, public
DTOs, read endpoints and the static OpenAPI document (`packages/sandbox-contracts`).
