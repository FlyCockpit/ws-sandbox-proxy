# ADR-002: Idempotency and outbox

## Status

Accepted

## Context

Network retries and client replays must not create duplicate VMs or operations.
Side effects must be observable by workers relaying host commands.

## Decision

- Every mutation carries an owner-scoped **idempotency key** and **canonical
  body hash** on `SandboxOperation` (host dispatch) or
  `SandboxActionReceipt` (registration, observation and command controls), or
  `SandboxTransfer` (spool session creation).
- Same key + same body returns the original operation/sandbox; same key +
  different body is a conflict.
- The shared `ownerKeyTransaction` locks the owner for admission, then an
  owner/key advisory lock. It reauthorizes and looks up replay before lifecycle
  or capacity checks. Host, sandbox and operation locks follow in that order.
  All three tables share this key namespace. A P2002 is inspected after
  transaction rollback and returns a matching, reauthorized winner.
- Record `OutboxEvent` rows in the same database transaction as
  sandbox/operation writes.

## Consequences

- `packages/api/src/sandbox/idempotency.ts` owns hashing and replay
  reconciliation.
- A mutation receipt means accepted, not ready or completed.
- Dispatch consumes unprocessed outbox rows; a lost in-process wake is
  recovered by a periodic scan.

Non-dispatch actions persist `UNKNOWN_OUTCOME` before host IO, and publish a
confirmed outcome only after the work returns. No database lock spans host IO.
A process death between intent and confirmation retains uncertainty; retrying
the same key returns that receipt and never repeats the effect. Template
registration can be reconciled against the owner's template inventory. Probe
receipts include their recorded generation; a generation change refuses a
stale observation. Stdin receipts record acceptance into the durable outbox;
cancel receipts remain pending until the target command's termination is
confirmed. Polling those receipts follows the target command's terminal state.

Typed file/process pages and controls retain their accepted identity on same-key
replay; expired content never becomes a new observation implicitly. Qualified
stdin commits its receipt, sequence and outbox atomically; acceptance is not
guest consumption. Kill/SIGKILL canonicalizes to operation cancellation. See the
[filesystem and command behavior](../guide/sandboxes.md#filesystem-and-command-result-limits).

## Dispatch outbox retention

Every writer stores the payload's `operationId` in the indexed outbox column;
relay lookups use that column rather than scanning payloads. Processed rows are
pruned only when the sandbox is DELETED, detached from every host and holds no
live or disk resources. All operations must be SUCCEEDED, FAILED or CANCELLED,
and no unprocessed row may remain. UNKNOWN_OUTCOME keeps the rows.

The sandbox and processed outbox row must both be older than 30 days. A remnant
reattachment updates the sandbox and restarts that window. Each maintenance pass
visits at most 50 sandboxes by default and deletes pages of 500 rows, with one
transaction per page and the sandbox locked before its outbox rows. SKIP LOCKED
keeps maintenance from waiting on relay work. Results, receipts and webhook
history have their own retention policies.
