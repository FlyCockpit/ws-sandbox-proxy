# ADR-001: Lifecycle and operation states

## Status

Accepted

## Context

Sandbox VMs, in-guest work, and control-plane mutations evolve on different
timelines. A booted VM with no tracked command is not the same as an active
platform operation.

## Decision

- Persist **sandbox machine state** (`SandboxState`) separately from
  **operation state** (`OperationState`).
- Bind mutations to a monotonic **generation** per sandbox; late events for
  older generations are ignored.
- Implement allowed transitions in
  `packages/api/src/sandbox/state-transitions.ts`.

## Consequences

- Routers and workers must transition through the shared transition helpers.
- Host-loss and recovery flows can mark sandboxes `UNREACHABLE` without
  immediately claiming `HOST_LOST`.
- Ordinary exec, file, and process results never author VM lifecycle state.

Host drain is admission state on `SandboxHost`, independent of guest lifecycle.
It prevents new creates, STOPPED restarts and template registration under the host
lock; it never changes guest state or stops a VM. See
[host drain](adr-003-host-enrollment.md#host-drain).

Tracked command detach is observation-only; stop preserves disk rather than
processes/RAM. Natural nonzero command exit remains SUCCEEDED; confirmed cancel
is CANCELLED and uncertainty is never death proof. After UNKNOWN there is no
command retry: recover with sandbox stop/kill. See the [filesystem and command behavior](../guide/sandboxes.md#filesystem-and-command-result-limits).
