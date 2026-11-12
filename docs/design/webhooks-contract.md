# Webhooks contract

The guide is [docs/guide/webhooks.md](../guide/webhooks.md). This page is the
implementation contract: where events come from, how the ledger moves, and
exactly which bytes are signed.

## Emission (database triggers)

Three row triggers in the committed initial migration
(`packages/db/prisma/migrations/0_init/migration.sql`), applied by the migration runner:

- `wssp_webhook_sandbox_event`: `AFTER INSERT OR UPDATE OF state ON sandbox_instance`.
- `wssp_webhook_operation_event`: `AFTER INSERT OR UPDATE OF state ON sandbox_mutation_operation`.
- `wssp_webhook_credential_event`: `AFTER INSERT ON credential_event` (CLI logins).

Each inserts one `webhook_event` row per event type that at least one of the
owner's enabled endpoints subscribes to, in the writer's transaction. A
rollback emits nothing; every writer is covered, raw SQL included. An update
that leaves `state` unchanged emits nothing (`UPDATE OF state` plus an
`IS NOT DISTINCT FROM` guard). An INSERT counts as a transition from `null`.

Predicates (`from` = `OLD.state::text`, `to` = `NEW.state::text`):

| Type                    | Fires when                                                                                                                        |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `sandbox.ready`         | `to = READY`                                                                                                                      |
| `sandbox.stopped`       | `to = STOPPED`                                                                                                                    |
| `sandbox.create_failed` | `NEW.readyAt IS NULL` and `from` is pre-READY and (`to = ERROR` or (`to = DELETED` and `NEW.lastErrorCode IS NOT NULL`))          |
| `sandbox.destroyed`     | `to = DELETED`                                                                                                                    |
| `operation.completed`   | `to` in SUCCEEDED, FAILED, CANCELLED, UNKNOWN_OUTCOME, and the endpoint's kind filter is empty or names `NEW.kind`                |
| `credential.<type>`     | `NEW.type` in `capture_failed`, `capture_lost`, `recovery_required`, `needs_login` (credential_event rows, not state transitions) |

The pre-READY list lives in exactly one place, the managed function
`wssp_webhook_pre_ready_states()`: `REQUESTED`, `SCHEDULED`, `PROVISIONING`,
`WAITING_FOR_CAPACITY`. It compares text, not enum literals, so it already
covers the capacity queue's `WAITING_FOR_CAPACITY → DELETED` with
`lastErrorCode = capacity_wait_timeout` (and its other failure codes) as
`create_failed`, while a cancelled wait (no error code) is `destroyed` only.

`facts` freezes the transition: `{from, to, generation, errorCode}` (raw error
code), plus `kind` for operations. Only the renderer reads them. A
`credential.*` event's facts are `{credentialEventId}` only: the renderer
re-reads that owner's `credential_event` row through
`webhookCredentialEventRenderSelect` (ids, type and reason; never `hostId`,
sizes or sequences) and drops a reason that is not a fixed token.

**Locks.** `webhook_event` has no foreign keys and the endpoint probe is a
plain `SELECT`, so emission takes no key-share lock on `user` or
`sandbox_instance` and adds no lock-order edge (a `credential_event` insert's
own key-share lock on `user` predates the trigger)
(`packages/api/src/webhooks/webhook-lock-order.pg.test.ts`).

**Removal safety.** All three functions return early when the webhook tables are
absent, so a schema without them never breaks sandbox writes. Removing the
feature needs explicit trigger/function cleanup in a reviewed committed
migration, with application compatibility maintained during the transition.

**Visibility.** Events are emitted only for transitions that commit after an
endpoint exists; fan-out also requires `endpoint.createdAt <= event.occurredAt`.

No `pg_notify`: the dispatcher polls every 2 seconds, which keeps NOTIFY's
commit serialization off sandbox write paths.

## Ledger (Postgres) and timer (BullMQ)

```
webhook_event ──fan-out──▶ webhook_delivery (PENDING) ──claim──▶ IN_FLIGHT
                                   ▲            │                    │
                       retry (seq+1, NULL)      │ expired            ├─ 2xx ─▶ SUCCEEDED
                                   └────────────┼────────────────────┤
                                                ▼                    └─ fail ─▶ PENDING (next) or FAILED
                                              FAILED      endpoint disabled ─▶ CANCELLED
```

- **Fan-out** (`fanOutEvents`): read a page of candidate events without locks
  (`fannedOutAt IS NULL`, by `seq`). For each, in its own transaction with
  `SET LOCAL lock_timeout = '200ms'`: lock the owner's enabled endpoints
  `FOR KEY SHARE` (by id), then the event `FOR UPDATE SKIP LOCKED`, re-check
  `fannedOutAt`, render the body once, insert one delivery per endpoint that
  is subscribed, created before the event and passes the kind filter (owner
  not deleting or banned; `CANCELLED backlog_overflow` past 10,000 pending
  per endpoint), and set `fannedOutAt`.
  - **Lock order** is endpoints before events, the order account
    finalization (it locks all the owner's endpoints `FOR UPDATE` by id before
    its bulk delete, then deletes events) and endpoint deletion use, so
    fan-out may wait on a deleter (at most the lock timeout) but no deleter
    ever waits back: no deadlock. The endpoint locks are held through the
    insert, so an endpoint cannot vanish under it: no FK race. A deleted
    endpoint simply drops out of the locked set.
  - **Fairness.** A lock timeout (`55P03`) rolls back that event only and
    marks its owner busy for the rest of the pass; later candidates exclude
    busy owners, so one owner's backlog costs one 200 ms timeout. A pass
    yields after 2 s of total lock waiting. Each dispatcher keeps an
    in-memory cursor: the next pass resumes after the last attempted event and
    wraps, so contended owners at the front cannot monopolize every pass.
    Nothing is persisted. Enqueue and maintenance run concurrently with
    fan-out, never behind its lock waits.
  - **Clock.** Ledger times (fan-out, claim, record, maintenance, enqueue
    including `enqueuedAt`, retention) come from the database clock in UTC,
    never a worker clock. The maintenance cadence uses a monotonic clock, so
    a wall-clock correction cannot stall or stampede it.
    Only the per-attempt `webhook-timestamp` uses the worker clock, since
    receivers compare it with theirs.
  - Owner edits and rotation lock the endpoint `FOR NO KEY UPDATE`, which
    does not conflict with fan-out's key-share lock.
  - **Backlog cap.** Each fan-out pass counts an endpoint's PENDING rows once
    (bounded at 10,001), then advances that count by its own committed
    inserts instead of recounting per event. An estimate over the cap is
    recounted once per pass before anything is cancelled. Rows other writers
    add during a pass (another dispatcher, retries, test sends, redeliveries)
    are not seen until the next pass, so the backlog can exceed 10,000 by
    that much. Completions after a pass's recount are not seen either, so
    near the cap a pass can cancel a delivery that would just have fitted.
    The cap is a backstop, not a quota.
- **Release protocol** (Postgres holds the backlog, Valkey holds only runnable
  work). BullMQ jobs carry `{deliveryId, attempt, seq}` with job id
  `wh-<deliveryId>-<seq>-<attempt>` and no delay. A PENDING delivery is
  _released_ when `enqueuedAt` is set. An endpoint's slots are its IN_FLIGHT
  rows with a live lease plus its released rows. The releaser keeps them at or
  under the in-flight cap (2), so Valkey never holds more than 2 jobs per
  endpoint, however long the backlog.
  - One release transaction locks a batch of endpoints `FOR NO KEY UPDATE`
    (by id: the claim's lock). In a second statement, on a snapshot taken
    after those locks, it fills each endpoint's free slots with due
    unreleased rows (`nextAttemptAt ≤ now`, by `nextAttemptAt` then id,
    `FOR UPDATE SKIP LOCKED`): manual sends (`kind` `test`, `redeliver`) first,
    from the partial index `webhook_delivery_manual_due_idx`
    (`(endpointId, nextAttemptAt) WHERE state = 'PENDING' AND kind <> 'event'`),
    then `event` rows in the slots left. Two lateral picks, never a sort over
    the backlog; manual sends count against the same cap. Each picked row gets `enqueueSeq + 1` and
    `enqueuedAt = now`. After commit, one bulk add puts the jobs in Valkey. If
    Valkey fails, one batched `UPDATE … FROM unnest(id, seq)` clears
    `enqueuedAt` for exactly those seqs, and the next sweep releases them
    again.
  - The dispatcher's 2 s sweep loose-scans the endpoints that have PENDING
    rows (index `(state, endpointId, nextAttemptAt)`), 100 per transaction
    and at most 1,000 per poll. An in-memory cursor carries the rest to the
    next poll. It skips locked endpoints. Its cost scales with the number of
    endpoints, not the number of backlog rows.
  - A finished attempt (recorded, or ended at claim as expired or cancelled)
    releases its own endpoint's next row at once. That release waits at most
    1 s for the endpoint lock; the sweep is the backstop.
  - A released row whose `enqueuedAt` is more than 2 minutes old no longer
    holds a slot and is released again under a new seq. This covers Valkey
    losing the job and a crash between the release commit and the add, so
    such a crash delays those rows by up to 2 minutes but never loses one.
    A job whose seq no longer matches is a no-op, so a re-release never
    collides with a completed job BullMQ still keeps, and an add that did
    land before the crash never sends twice.
  - Every other path back to PENDING (a retry, a claim deferral, a lease
    reclaim) clears `enqueuedAt` and bumps the seq. The row then waits in
    Postgres until it is due and has a slot.
- **Claim** (`claimDelivery`): lock the endpoint `FOR NO KEY UPDATE`, then the
  delivery `FOR UPDATE`. Require PENDING, `attemptCount = attempt − 1`,
  `enqueueSeq = seq`, due, unexpired, endpoint enabled, fewer than 2 IN_FLIGHT
  for the endpoint. If the endpoint is at the cap (only a release race, such
  as a stale-released job firing late), the row goes back to the backlog
  unreleased (seq + 1, same due time). No job is re-added: the releaser hands
  it out when a slot frees. A worker without `DATA_ENCRYPTION_KEY` does the
  same with the row due again in 60 s. Decide private eligibility here
  (`isAdminAccountAuthorized` under `admins` scope). Set IN_FLIGHT,
  `attemptCount = attempt`, `leaseUntil = now + 60 s`.
- **Record** (`recordAttempt`): same lock order. Insert the attempt row only
  while the delivery exists (an endpoint deleted mid-attempt cascaded it). CAS
  `IN_FLIGHT(attempt)` to SUCCEEDED, PENDING (next time, seq + 1, unreleased)
  or FAILED; a lost CAS keeps the attempt row and changes nothing else. Failures other
  than `not_configured`, on non-test deliveries, count toward the endpoint's
  `consecutiveFailures`/`failingSince`; 72 hours and 20 failures disables it,
  cancels its PENDING deliveries and claims the one notification
  (`disabledNotifiedAt`) in the same transaction.
- **Maintenance** (60 s): expired leases → PENDING `worker_lost` (seq + 1) or
  FAILED; PENDING past `expiresAt` → FAILED `expired`; re-encrypt secrets still
  under a kid other than the `data_key_epoch` row's (the shared write fence,
  [credential vault rotation](./credential-vault.md#rotation)).
- **Account deletion** finalizes endpoints first (deliveries and attempts
  cascade) and then the FK-free events: the claim's own order.
- **Retention**: a daily job deletes events older than 7 days in batches;
  deliveries and attempts cascade. Each batch's transaction first locks the
  endpoints its deliveries point at `FOR KEY SHARE` by id, then deletes the
  events: the same endpoints-before-events order as fan-out and account
  finalization, so the reaper may wait on a finalizer but never deadlock
  with it. A batch that still hits `40P01` is retried once.

A worker without `DATA_ENCRYPTION_KEY` defers deliveries by 60 s and records
nothing, so an unconfigured or misconfigured worker cannot disable endpoints.

## Signing bytes

```
key       = base64decode(secret without "whsec_")      # 32 random bytes
signed    = utf8(webhook-id) || "." || ascii(webhook-timestamp) || "." || raw body bytes
signature = "v1," || base64(HMAC-SHA256(key, signed))
header    = signature for the current secret [ " " signature for the previous secret ]
```

The timestamp is set per attempt (Unix seconds); the body is rendered once at
fan-out and never changes across retries and redeliveries. Shared vectors,
including the Standard Webhooks specification vector, live in
`packages/sandbox-contracts/src/webhook-signing-vectors.json` and are checked
by the server signer and the SDK verifier.

Secrets at rest: AES-256-GCM under the sub-key
`HKDF-SHA256(ikm = DATA_ENCRYPTION_KEY, salt = "wssp-data-key-v1", info = "webhook-endpoint-secret:v1", 32 bytes)`,
96-bit random nonce, AAD =
`encodeHmacContext(["wssp-data-key-v1", "webhook-endpoint-secret:v1", endpointId, userId, version])`.
The stored key id (`secretKeyId`, `previousSecretKeyId`) is the **root** key
id, the first 16 hex of SHA-256(root), so a root rotation finds every row to
re-encrypt by root id regardless of purpose; the purpose is fixed per column
and bound by the AAD. A value sealed under any other key or purpose (including
the retired raw-key scheme) fails authentication and is treated as
`not_configured`, never as a crash.
Rotation moves the current secret (with its own version) to the `previous*`
columns for the overlap.

## Versioning

`schemaVersion` is 1. Adding fields does not change it; receivers must ignore
unknown fields (the SDK returns unknown event types untyped instead of
failing). A breaking change ships as version 2, selected per endpoint through
`payloadVersion`.
