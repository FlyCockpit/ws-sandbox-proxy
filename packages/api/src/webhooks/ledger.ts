import { isUserBanned } from "@wssp/auth/ban";
import prisma, { type Prisma } from "@wssp/db";
import type { WebhookErrorClass } from "@wssp/sandbox-contracts";
import { DataKeyStaleWriter, fenceWriteKey } from "../crypto/data-key-epoch";
import { isAdminAccountAuthorized } from "../lib/sensitive-session-two-factor-gate";
import { openSecret, sealSecret, type WebhookSecretKey } from "./crypto";
import { type RenderableEvent, renderWebhookEvent } from "./render";
import {
  DELIVERY_LEASE_MS,
  ENDPOINT_BACKLOG_CAP,
  ENDPOINT_IN_FLIGHT_CAP,
  nextAttemptAt,
  shouldDisableEndpoint,
  WEBHOOK_DELIVERY_WINDOW_MS,
  WEBHOOK_LOG_RETENTION_DAYS,
  WEBHOOK_MAX_ATTEMPTS,
} from "./schedule";

/**
 * The Postgres delivery ledger. Every delivery and
 * attempt lives here; BullMQ jobs carry only `{deliveryId, attempt, seq}`.
 *
 * Lock order, everywhere: endpoint row (FOR NO KEY UPDATE) before delivery row.
 * Account finalization deletes endpoints (cascading deliveries) before events,
 * the same order. Fan-out takes event rows FOR UPDATE SKIP LOCKED, so several
 * dispatchers never fan the same event twice.
 *
 * Release protocol (Postgres holds the backlog, Redis only runnable work):
 * a PENDING delivery is "released" when `enqueuedAt` is set. Only the
 * releaser (`enqueuePending`'s sweep and `releaseEndpoints`, both under the
 * endpoint lock) sets it, bumping
 * `enqueueSeq` in the same committed transaction, and only for a due row of
 * an endpoint with a free slot: IN_FLIGHT (live lease) plus released rows stay
 * at most ENDPOINT_IN_FLIGHT_CAP. After commit it adds the jobs
 * `wh-<id>-<seq>-<attempt>` in one bulk call; a Redis failure clears
 * `enqueuedAt` again for exactly those seqs. A crash between commit and add
 * leaves a released row without a job, which the sweep treats as lost after
 * LOST_JOB_GRACE_MS and re-releases under a new seq. A job whose `seq` no
 * longer matches is a no-op, so a re-release never reuses a job id BullMQ is
 * still holding (completed jobs are kept for an hour). Everyone else who
 * returns a row to PENDING (retry, deferral, lease reclaim) clears
 * `enqueuedAt` and bumps the seq; the row waits in Postgres until it is due
 * and a slot is free.
 */

type Tx = Prisma.TransactionClient;
type Client = Pick<typeof prisma, "$transaction" | "$queryRaw" | "$executeRaw">;

export const FAN_OUT_BATCH = 100;
/**
 * Statement lock wait for fan-out's endpoint locks (PostgreSQL `lock_timeout`).
 * Deletion holds are brief; a longer wait only delays other owners.
 */
export const FAN_OUT_LOCK_TIMEOUT_MS = 200;
/** Total time one pass may spend in timed-out lock waits before it yields. */
export const FAN_OUT_CONTENTION_BUDGET_MS = 2_000;
/** Endpoints one release transaction (and one bulk Redis add) covers. */
export const ENQUEUE_ENDPOINT_BATCH = 100;
/** Release batches per sweep; the cursor carries the rest to the next poll. */
export const ENQUEUE_MAX_BATCHES = 10;
/** Lock wait of a targeted release (a finished attempt freeing its slot). */
export const RELEASE_LOCK_TIMEOUT_MS = 1_000;
export const MAINTENANCE_BATCH = 500;
/** A released delivery whose job was handed to Redis this long ago is released again. */
export const LOST_JOB_GRACE_MS = 120_000;

/** One runnable job: released only when due, so it never carries a delay. */
export type EnqueueRequest = {
  deliveryId: string;
  attempt: number;
  seq: number;
};
/** Adds the BullMQ jobs in one call; must be idempotent per (id, seq, attempt). */
export type EnqueueJobs = (requests: readonly EnqueueRequest[]) => Promise<void>;

// --- Fan-out ---------------------------------------------------------------------

type EventRow = RenderableEvent & { seq: bigint };

/** The database clock as a UTC timestamp: ledger time never trusts a worker clock. */
export async function dbNow(client: Pick<typeof prisma, "$queryRaw">): Promise<Date> {
  const [row] = await client.$queryRaw<
    { now: Date }[]
  >`SELECT clock_timestamp() AT TIME ZONE 'UTC' AS now`;
  if (!row) throw new Error("database clock unavailable");
  return row.now;
}

/**
 * Fan out up to FAN_OUT_BATCH unfanned events, one transaction each: render
 * the body once, insert one delivery per matching endpoint, mark the event.
 *
 * Lock order: ENDPOINTS BEFORE THE EVENT, the order
 * account finalization (endpoints, then events) and endpoint deletion use.
 * Candidates are read without locks (by seq); for each one, the owner's
 * enabled endpoints are locked FOR KEY SHARE (by id) under a short
 * `lock_timeout`, then the event FOR UPDATE SKIP LOCKED, fannedOutAt is
 * re-checked and the deliveries are inserted while those locks are held, so
 * no endpoint can vanish under the insert (no FK race) and fan-out can wait on
 * a deleter without the deleter ever waiting back (no deadlock).
 *
 * Fairness: a lock timeout (200 ms) rolls back that event only and marks its
 * owner busy for the rest of the pass; later candidates exclude busy owners,
 * so one owner's backlog costs one timeout. A pass yields after 2 s of total
 * lock waiting, and the dispatcher's in-memory cursor resumes the next pass
 * after the last attempted event (wrapping), so contended owners at the front
 * cannot monopolize every pass. Nothing is persisted; timed-out events are
 * retried when the cursor comes round again.
 * All times are the database clock (UTC).
 */
/**
 * In-memory scan position kept by one dispatcher across polls (never
 * persisted). Each pass resumes after the last attempted event and wraps, so
 * contended owners at the front of the queue cannot monopolize every pass.
 */
export type FanOutCursor = { afterSeq: bigint; contendedMs: number };

export function newFanOutCursor(): FanOutCursor {
  return { afterSeq: -1n, contendedMs: 0 };
}

export async function fanOutEvents(
  client: Client = prisma,
  now?: Date,
  cursor: FanOutCursor = newFanOutCursor(),
): Promise<number> {
  let done = 0;
  const start = cursor.afterSeq;
  let afterSeq = start;
  // Scan [start+1 .. end], then wrap to [first .. start].
  let wrapped = start < 0n;
  let exhausted = false;
  let contendedMs = 0;
  const busyOwners: string[] = [];
  const backlog: BacklogCache = new Map();
  scan: while (done < FAN_OUT_BATCH) {
    const candidates = await client.$queryRaw<{ id: string; seq: bigint; userId: string }[]>`
      SELECT id, seq, "userId" FROM webhook_event
      WHERE "fannedOutAt" IS NULL AND seq > ${afterSeq}
        AND (${!wrapped || start < 0n} OR seq <= ${start})
        AND NOT ("userId" = ANY(${busyOwners}::text[]))
      ORDER BY seq LIMIT ${FAN_OUT_BATCH}`;
    if (candidates.length === 0) {
      if (!wrapped) {
        wrapped = true;
        afterSeq = -1n;
        continue;
      }
      exhausted = true;
      break;
    }
    for (const candidate of candidates) {
      afterSeq = candidate.seq;
      if (busyOwners.includes(candidate.userId)) continue;
      const began = performance.now();
      try {
        if (await fanOutCandidate(client, candidate, now, backlog)) done++;
      } catch (error) {
        if (!isLockNotAvailable(error)) throw error;
        contendedMs += performance.now() - began;
        busyOwners.push(candidate.userId);
        if (contendedMs >= FAN_OUT_CONTENTION_BUDGET_MS) break scan;
      }
      if (done >= FAN_OUT_BATCH) break scan;
    }
  }
  // A completed cycle restarts at the front next time; an interrupted one resumes.
  cursor.afterSeq = exhausted ? -1n : afterSeq;
  cursor.contendedMs = contendedMs;
  return done;
}

/**
 * Per-pass PENDING backlog per endpoint (JS-4), so fan-out does not recount a
 * backlog of up to ENDPOINT_BACKLOG_CAP rows for every event. An endpoint is
 * counted exactly (bounded at the cap + 1) the first time a pass needs it and
 * then advanced by the pass's own committed PENDING inserts. An estimate at or
 * under the cap is trusted (writers outside this pass can add rows beyond it
 * meanwhile: the cap is a backstop, not a quota); an estimate over the cap is
 * re-counted once before the pass cancels anything, so completions earlier in
 * the pass are seen. Never persisted; the next pass counts afresh.
 */
type BacklogCache = Map<string, { count: number; recounted: boolean }>;
type BacklogView = { cache: BacklogCache; staged: BacklogCache };

async function fanOutCandidate(
  client: Client,
  candidate: { id: string; userId: string },
  testNow: Date | undefined,
  cache: BacklogCache,
): Promise<boolean> {
  // Staged in the transaction, applied only once it commits.
  const backlog: BacklogView = { cache, staged: new Map() };
  const fannedOut = await client.$transaction(async (tx) => {
    await tx.$executeRawUnsafe(`SET LOCAL lock_timeout = '${FAN_OUT_LOCK_TIMEOUT_MS}ms'`);
    const now = testNow ?? (await dbNow(tx));
    // 1. Endpoints first (deletion's order), waiting at most lock_timeout.
    const endpoints = await tx.$queryRaw<
      { id: string; operationKinds: string[]; events: string[]; createdAt: Date }[]
    >`SELECT id, "operationKinds", events, "createdAt" FROM webhook_endpoint
      WHERE "userId" = ${candidate.userId} AND "disabledAt" IS NULL
      ORDER BY id FOR KEY SHARE`;
    // 2. Then the event; another dispatcher may hold or have finished it.
    const [event] = await tx.$queryRaw<EventRow[]>`
      SELECT id, seq, "userId", type, "sandboxId", "operationId", "occurredAt", facts
      FROM webhook_event WHERE id = ${candidate.id} AND "fannedOutAt" IS NULL
      FOR UPDATE SKIP LOCKED`;
    if (!event) return false;
    await fanOutOne(tx, event, endpoints, now, backlog);
    return true;
  });
  for (const [endpointId, entry] of backlog.staged) cache.set(endpointId, entry);
  return fannedOut;
}

/** PostgreSQL 55P03 (`lock_not_available`, from NOWAIT), however Prisma wraps it. */
export function isLockNotAvailable(error: unknown): boolean {
  const seen = new Set<unknown>();
  const visit = (value: unknown): boolean => {
    if (!value || typeof value !== "object" || seen.has(value)) return false;
    seen.add(value);
    const record = value as Record<string, unknown>;
    for (const key of ["code", "originalCode", "sqlState"])
      if (record[key] === "55P03") return true;
    if (typeof record.message === "string" && /55P03|could not obtain lock/.test(record.message))
      return true;
    return visit(record.meta) || visit(record.cause);
  };
  return visit(error);
}

/** Whether the endpoint's PENDING backlog is past the cap (see BacklogCache). */
async function backlogOverflows(tx: Tx, endpointId: string, view: BacklogView): Promise<boolean> {
  let entry = view.staged.get(endpointId) ?? view.cache.get(endpointId);
  if (!entry || (entry.count > ENDPOINT_BACKLOG_CAP && !entry.recounted)) {
    const count = await tx.webhookDelivery.count({
      where: { endpointId, state: "PENDING" },
      take: ENDPOINT_BACKLOG_CAP + 1,
    });
    entry = { count, recounted: entry !== undefined };
  }
  const overflow = entry.count > ENDPOINT_BACKLOG_CAP;
  // A PENDING insert grows the backlog; a CANCELLED one does not.
  view.staged.set(endpointId, {
    count: overflow ? entry.count : entry.count + 1,
    recounted: entry.recounted,
  });
  return overflow;
}

async function fanOutOne(
  tx: Tx,
  event: EventRow,
  locked: readonly { id: string; operationKinds: string[]; events: string[]; createdAt: Date }[],
  now: Date,
  backlog: BacklogView,
): Promise<void> {
  const body = await renderWebhookEvent(tx, event);
  const owner = await tx.user.findUnique({
    where: { id: event.userId },
    select: { deletionRequestedAt: true, banned: true, banExpires: true },
  });
  const ownerActive =
    owner !== null && owner.deletionRequestedAt === null && !isUserBanned(owner, now);
  if (body && ownerActive) {
    const facts = (event.facts ?? {}) as { kind?: unknown };
    const rows: Prisma.WebhookDeliveryCreateManyInput[] = [];
    for (const endpoint of locked) {
      // Events are emitted for transitions that commit after the endpoint exists.
      if (!endpoint.events.includes(event.type) || endpoint.createdAt > event.occurredAt) continue;
      if (
        event.type === "operation.completed" &&
        endpoint.operationKinds.length > 0 &&
        !(typeof facts.kind === "string" && endpoint.operationKinds.includes(facts.kind))
      )
        continue;
      const overflow = await backlogOverflows(tx, endpoint.id, backlog);
      rows.push({
        eventId: event.id,
        endpointId: endpoint.id,
        userId: event.userId,
        kind: "event",
        state: overflow ? "CANCELLED" : "PENDING",
        maxAttempts: WEBHOOK_MAX_ATTEMPTS,
        nextAttemptAt: overflow ? null : now,
        expiresAt: new Date(now.getTime() + WEBHOOK_DELIVERY_WINDOW_MS),
        lastErrorClass: overflow ? "backlog_overflow" : null,
        completedAt: overflow ? now : null,
      });
    }
    if (rows.length > 0) await tx.webhookDelivery.createMany({ data: rows });
  }
  await tx.webhookEvent.update({
    where: { id: event.id },
    data: { body, fannedOutAt: now },
  });
}

// --- Release -----------------------------------------------------------------------

/**
 * In-memory scan position of one dispatcher's release sweep (never
 * persisted): each sweep resumes after the last endpoint it visited, so more
 * backlogged endpoints than one sweep covers are all reached in turn.
 */
export type EnqueueCursor = { afterEndpointId: string };

export function newEnqueueCursor(): EnqueueCursor {
  return { afterEndpointId: "" };
}

/**
 * The dispatcher's release sweep. Visits every endpoint that has PENDING
 * deliveries (a loose index scan over `(state, endpointId)`, so the cost is
 * per endpoint, not per backlog row) in batches of ENQUEUE_ENDPOINT_BATCH and
 * releases due rows into free slots. Endpoints another transaction holds are
 * skipped (their holder frees and releases, or the next poll does).
 */
export async function enqueuePending(
  enqueue: EnqueueJobs,
  client: Client = prisma,
  testNow?: Date,
  cursor: EnqueueCursor = newEnqueueCursor(),
): Promise<number> {
  const now = testNow ?? (await dbNow(client));
  let added = 0;
  for (let batch = 0; batch < ENQUEUE_MAX_BATCHES; batch++) {
    const endpoints = await client.$queryRaw<{ id: string }[]>`
      WITH RECURSIVE ep(id) AS (
        (SELECT "endpointId" FROM webhook_delivery
          WHERE state = 'PENDING' AND "endpointId" > ${cursor.afterEndpointId}
          ORDER BY "endpointId" LIMIT 1)
        UNION ALL
        SELECT (SELECT d."endpointId" FROM webhook_delivery d
          WHERE d.state = 'PENDING' AND d."endpointId" > ep.id
          ORDER BY d."endpointId" LIMIT 1)
        FROM ep WHERE ep.id IS NOT NULL
      )
      SELECT id FROM ep WHERE id IS NOT NULL LIMIT ${ENQUEUE_ENDPOINT_BATCH}`;
    const ids = endpoints.map((row) => row.id);
    if (ids.length > 0) added += await releaseBatch(enqueue, client, ids, now, false);
    // A short batch reached the end: the next sweep starts at the front.
    cursor.afterEndpointId = ids.length < ENQUEUE_ENDPOINT_BATCH ? "" : (ids.at(-1) ?? "");
    if (ids.length < ENQUEUE_ENDPOINT_BATCH) break;
  }
  return added;
}

/**
 * Release due deliveries of these endpoints into their free slots now. A
 * finished attempt calls it for its endpoint, so the next row follows without
 * waiting for the dispatcher's poll. Waits briefly for the endpoint lock (a
 * claim holds it for milliseconds); on a timeout the poll catches up.
 */
export async function releaseEndpoints(
  enqueue: EnqueueJobs,
  endpointIds: readonly string[],
  options: { client?: Client; now?: Date } = {},
): Promise<number> {
  const client = options.client ?? prisma;
  const ids = [...new Set(endpointIds)].sort();
  if (ids.length === 0) return 0;
  const now = options.now ?? (await dbNow(client));
  try {
    return await releaseBatch(enqueue, client, ids, now, true);
  } catch (error) {
    if (isLockNotAvailable(error)) return 0;
    throw error;
  }
}

type Released = { id: string; attemptCount: number; enqueueSeq: number };

/**
 * One release transaction, then one bulk add. Statement 1 locks the endpoints
 * (id order, FOR NO KEY UPDATE: the claim's lock, so no claim, record or other
 * release changes their occupancy meanwhile); statement 2 runs on a snapshot
 * taken after those locks, counts each endpoint's occupied slots (IN_FLIGHT
 * with a live lease, plus rows released within LOST_JOB_GRACE_MS) and marks
 * due unreleased rows into the free slots, bumping their seq: manual sends
 * (`test`, `redeliver`, from their small partial index) first, then automatic
 * `event` rows in the slots left; each oldest due first (`nextAttemptAt`, id).
 * Lock order: endpoints, then deliveries.
 */
async function releaseBatch(
  enqueue: EnqueueJobs,
  client: Client,
  endpointIds: readonly string[],
  now: Date,
  wait: boolean,
): Promise<number> {
  const lostBefore = new Date(now.getTime() - LOST_JOB_GRACE_MS);
  const released = await client.$transaction(async (tx) => {
    let locked: { id: string }[];
    if (wait) {
      await tx.$executeRawUnsafe(`SET LOCAL lock_timeout = '${RELEASE_LOCK_TIMEOUT_MS}ms'`);
      locked = await tx.$queryRaw<{ id: string }[]>`
        SELECT id FROM webhook_endpoint WHERE id = ANY(${endpointIds}::text[])
        ORDER BY id FOR NO KEY UPDATE`;
    } else
      locked = await tx.$queryRaw<{ id: string }[]>`
        SELECT id FROM webhook_endpoint WHERE id = ANY(${endpointIds}::text[])
        ORDER BY id FOR NO KEY UPDATE SKIP LOCKED`;
    if (locked.length === 0) return [];
    return tx.$queryRaw<Released[]>`
      WITH slots AS (
        SELECT e.id, ${ENDPOINT_IN_FLIGHT_CAP}::int - (
          SELECT count(*)::int FROM webhook_delivery o
          WHERE o."endpointId" = e.id AND (
            (o.state = 'IN_FLIGHT' AND o."leaseUntil" > ${now}) OR
            (o.state = 'PENDING' AND o."enqueuedAt" >= ${lostBefore}))
        ) AS free
        FROM unnest(${locked.map((row) => row.id)}::text[]) AS e(id)
      ), manual AS (
        SELECT s.id AS "endpointId", p.id FROM slots s CROSS JOIN LATERAL (
          SELECT d.id FROM webhook_delivery d
          WHERE d."endpointId" = s.id AND d.state = 'PENDING' AND d.kind <> 'event'
            AND d."nextAttemptAt" <= ${now}
            AND (d."enqueuedAt" IS NULL OR d."enqueuedAt" < ${lostBefore})
          ORDER BY d."nextAttemptAt", d.id
          LIMIT GREATEST(s.free, 0)
          FOR UPDATE SKIP LOCKED
        ) p
      ), rest AS (
        SELECT s.id, s.free - count(m.id)::int AS free
        FROM slots s LEFT JOIN manual m ON m."endpointId" = s.id
        GROUP BY s.id, s.free
      ), automatic AS (
        SELECT p.id FROM rest s CROSS JOIN LATERAL (
          SELECT d.id FROM webhook_delivery d
          WHERE d."endpointId" = s.id AND d.state = 'PENDING' AND d.kind = 'event'
            AND d."nextAttemptAt" <= ${now}
            AND (d."enqueuedAt" IS NULL OR d."enqueuedAt" < ${lostBefore})
          ORDER BY d."nextAttemptAt", d.id
          LIMIT GREATEST(s.free, 0)
          FOR UPDATE SKIP LOCKED
        ) p
      ), picked AS (
        SELECT id FROM manual UNION ALL SELECT id FROM automatic
      )
      UPDATE webhook_delivery d SET "enqueueSeq" = d."enqueueSeq" + 1, "enqueuedAt" = ${now}
      FROM picked WHERE d.id = picked.id
      RETURNING d.id, d."attemptCount", d."enqueueSeq"`;
  });
  return addJobs(enqueue, client, released);
}

/**
 * Add released rows' jobs in one bulk call. On a Redis failure, un-release
 * exactly those seqs (one statement) so the next sweep retries at once.
 */
async function addJobs(
  enqueue: EnqueueJobs,
  client: Pick<typeof prisma, "$executeRaw">,
  released: readonly Released[],
): Promise<number> {
  if (released.length === 0) return 0;
  try {
    await enqueue(
      released.map((row) => ({
        deliveryId: row.id,
        attempt: row.attemptCount + 1,
        seq: row.enqueueSeq,
      })),
    );
  } catch {
    await client.$executeRaw`
      UPDATE webhook_delivery d SET "enqueuedAt" = NULL
      FROM unnest(${released.map((row) => row.id)}::text[], ${released.map((row) => row.enqueueSeq)}::int[]) AS r(id, seq)
      WHERE d.id = r.id AND d."enqueueSeq" = r.seq AND d.state = 'PENDING'`;
    return 0;
  }
  return released.length;
}

// --- Claim -------------------------------------------------------------------------

export type ClaimedDelivery = {
  deliveryId: string;
  attempt: number;
  kind: string;
  endpointId: string;
  userId: string;
  url: string;
  eventId: string;
  eventType: string;
  body: string;
  secretVersion: number;
  secret: { ciphertext: Uint8Array; nonce: Uint8Array; keyId: string; version: number };
  previous: { ciphertext: Uint8Array; nonce: Uint8Array; keyId: string; version: number } | null;
  ownerMayUsePrivate: boolean;
};

export type ClaimOutcome =
  | { kind: "claimed"; delivery: ClaimedDelivery }
  /**
   * Returned to the Postgres backlog unreleased (no job is re-added): not due,
   * endpoint at its in-flight cap (a release race), or worker not configured
   * (then due again in 60 s). The releaser hands it out again.
   */
  | { kind: "deferred"; reason: "not_due" | "at_cap" | "not_configured" }
  /** `endpointId` is set when this job's row ended here (its slot is free). */
  | { kind: "skipped"; reason: "stale" | "missing" | "terminal"; endpointId?: string };

type ClaimRow = {
  id: string;
  endpointId: string;
  userId: string;
  kind: string;
  state: string;
  attemptCount: number;
  maxAttempts: number;
  enqueueSeq: number;
  nextAttemptAt: Date | null;
  expiresAt: Date;
  eventId: string;
};

/**
 * Un-release inside the claim transaction: the row stays PENDING in Postgres
 * (due at `at`), its seq moves on so this job can never claim it again, and no
 * job is re-added. The releaser hands it out when it is due and has a slot.
 */
async function defer(
  tx: Tx,
  row: ClaimRow,
  at: Date | null,
  reason: "not_due" | "at_cap" | "not_configured",
): Promise<ClaimOutcome> {
  await tx.$executeRaw`
    UPDATE webhook_delivery SET "nextAttemptAt" = COALESCE(${at}::timestamp, "nextAttemptAt"),
      "enqueueSeq" = "enqueueSeq" + 1, "enqueuedAt" = NULL
    WHERE id = ${row.id}`;
  return { kind: "deferred", reason };
}

/**
 * The claim CAS: endpoint FOR NO KEY UPDATE, then the delivery FOR UPDATE.
 * Requires PENDING, the job's attempt and seq, due, unexpired, endpoint enabled
 * and the per-endpoint in-flight cap (Postgres-wide, every worker together).
 * The private-destination eligibility (M5) is decided here, per attempt.
 */
export async function claimDelivery(
  job: { deliveryId: string; attempt: number; seq: number },
  options: {
    configured: boolean;
    privateScope: "admins" | "all";
    client?: Client;
    now?: Date;
  },
): Promise<ClaimOutcome> {
  const client = options.client ?? prisma;
  const now = options.now ?? (await dbNow(client));
  return client.$transaction(async (tx) => {
    const [ref] = await tx.$queryRaw<{ endpointId: string }[]>`
      SELECT "endpointId" FROM webhook_delivery WHERE id = ${job.deliveryId}`;
    if (!ref) return { kind: "skipped", reason: "missing" } as const;
    const [endpoint] = await tx.$queryRaw<
      {
        id: string;
        userId: string;
        url: string;
        disabledAt: Date | null;
        secretCiphertext: Uint8Array;
        secretNonce: Uint8Array;
        secretKeyId: string;
        secretVersion: number;
        previousSecretCiphertext: Uint8Array | null;
        previousSecretNonce: Uint8Array | null;
        previousSecretKeyId: string | null;
        previousSecretVersion: number | null;
        previousSecretExpiresAt: Date | null;
      }[]
    >`SELECT id, "userId", url, "disabledAt", "secretCiphertext", "secretNonce", "secretKeyId", "secretVersion",
        "previousSecretCiphertext", "previousSecretNonce", "previousSecretKeyId", "previousSecretVersion", "previousSecretExpiresAt"
      FROM webhook_endpoint WHERE id = ${ref.endpointId} FOR NO KEY UPDATE`;
    const [row] = await tx.$queryRaw<ClaimRow[]>`
      SELECT id, "endpointId", "userId", kind, state::text AS state, "attemptCount", "maxAttempts", "enqueueSeq",
        "nextAttemptAt", "expiresAt", "eventId"
      FROM webhook_delivery WHERE id = ${job.deliveryId} FOR UPDATE`;
    if (!endpoint || !row) return { kind: "skipped", reason: "missing" } as const;
    if (row.state !== "PENDING") return { kind: "skipped", reason: "terminal" } as const;
    if (row.attemptCount !== job.attempt - 1 || row.enqueueSeq !== job.seq)
      return { kind: "skipped", reason: "stale" } as const;
    if (endpoint.disabledAt) {
      await tx.webhookDelivery.update({
        where: { id: row.id },
        data: { state: "CANCELLED", lastErrorClass: "endpoint_disabled", completedAt: now },
      });
      return { kind: "skipped", reason: "terminal", endpointId: endpoint.id } as const;
    }
    if (row.expiresAt.getTime() <= now.getTime()) {
      await tx.webhookDelivery.update({
        where: { id: row.id },
        data: { state: "FAILED", lastErrorClass: "expired", completedAt: now },
      });
      return { kind: "skipped", reason: "terminal", endpointId: endpoint.id } as const;
    }
    // A worker without DATA_ENCRYPTION_KEY reports, never attempts or counts.
    if (!options.configured)
      return defer(tx, row, new Date(now.getTime() + 60_000), "not_configured");
    if (row.nextAttemptAt && row.nextAttemptAt.getTime() > now.getTime() + 1000)
      return defer(tx, row, null, "not_due");
    const [inFlight] = await tx.$queryRaw<{ count: number }[]>`
      SELECT count(*)::int AS count FROM webhook_delivery
      WHERE "endpointId" = ${endpoint.id} AND state = 'IN_FLIGHT' AND "leaseUntil" > ${now}`;
    // Release keeps IN_FLIGHT plus released rows within the cap, so this is a
    // race (e.g. a stale-released job firing late): back to the backlog, no re-add.
    if ((inFlight?.count ?? 0) >= ENDPOINT_IN_FLIGHT_CAP) return defer(tx, row, null, "at_cap");
    const [event] = await tx.$queryRaw<{ type: string; body: string | null }[]>`
      SELECT type, body FROM webhook_event WHERE id = ${row.eventId}`;
    if (!event?.body) {
      await tx.webhookDelivery.update({
        where: { id: row.id },
        data: { state: "CANCELLED", lastErrorClass: "protocol_error", completedAt: now },
      });
      return { kind: "skipped", reason: "terminal", endpointId: endpoint.id } as const;
    }
    const ownerMayUsePrivate =
      options.privateScope === "all" ||
      (await isAdminAccountAuthorized(endpoint.userId, { db: tx, now }));
    await tx.$executeRaw`UPDATE webhook_delivery SET state = 'IN_FLIGHT', "attemptCount" = ${job.attempt},
      "leaseUntil" = ${new Date(now.getTime() + DELIVERY_LEASE_MS)}, "nextAttemptAt" = NULL
      WHERE id = ${row.id}`;
    const previousLive =
      endpoint.previousSecretCiphertext &&
      endpoint.previousSecretNonce &&
      endpoint.previousSecretKeyId &&
      endpoint.previousSecretVersion !== null &&
      endpoint.previousSecretExpiresAt &&
      endpoint.previousSecretExpiresAt.getTime() > now.getTime();
    return {
      kind: "claimed",
      delivery: {
        deliveryId: row.id,
        attempt: job.attempt,
        kind: row.kind,
        endpointId: endpoint.id,
        userId: endpoint.userId,
        url: endpoint.url,
        eventId: row.eventId,
        eventType: event.type,
        body: event.body,
        secretVersion: endpoint.secretVersion,
        secret: {
          ciphertext: endpoint.secretCiphertext,
          nonce: endpoint.secretNonce,
          keyId: endpoint.secretKeyId,
          version: endpoint.secretVersion,
        },
        previous: previousLive
          ? {
              ciphertext: endpoint.previousSecretCiphertext as Uint8Array,
              nonce: endpoint.previousSecretNonce as Uint8Array,
              keyId: endpoint.previousSecretKeyId as string,
              version: endpoint.previousSecretVersion as number,
            }
          : null,
        ownerMayUsePrivate,
      },
    } as const;
  });
}

/** Signing keys for a claim: current first, then the overlapping previous one. */
export function signingKeys(
  delivery: ClaimedDelivery,
  keys: readonly WebhookSecretKey[],
): Buffer[] {
  const binding = (version: number) => ({
    endpointId: delivery.endpointId,
    userId: delivery.userId,
    version,
  });
  const out = [openSecret(delivery.secret, binding(delivery.secret.version), keys)];
  if (delivery.previous)
    out.push(openSecret(delivery.previous, binding(delivery.previous.version), keys));
  return out;
}

// --- Record ------------------------------------------------------------------------

export type AttemptRecord = {
  startedAt: Date;
  durationMs: number;
  statusCode: number | null;
  errorClass: WebhookErrorClass | null;
  resolvedAddress: string | null;
  responseExcerpt: string | null;
  retryAfterSeconds: number | null;
};

export type RecordOutcome = {
  state: "SUCCEEDED" | "PENDING" | "FAILED" | "lost";
  /** Set when this attempt disabled the endpoint and the owner must be told (once). */
  disabled: { endpointId: string; userId: string; url: string; consecutiveFailures: number } | null;
};

/**
 * Record one attempt. Inserts the attempt row only while the delivery exists
 * (an endpoint deleted mid-attempt cascades it away: no P2003), then CASes
 * IN_FLIGHT(attempt) to its outcome. A lost CAS (lease reclaimed) keeps the
 * attempt row and changes nothing else.
 */
export async function recordAttempt(
  delivery: Pick<ClaimedDelivery, "deliveryId" | "attempt" | "endpointId" | "kind">,
  attempt: AttemptRecord,
  options: { client?: Client; now?: Date; random?: number } = {},
): Promise<RecordOutcome> {
  const client = options.client ?? prisma;
  const now = options.now ?? (await dbNow(client));
  return client.$transaction(async (tx) => {
    const [endpoint] = await tx.$queryRaw<
      {
        id: string;
        userId: string;
        url: string;
        consecutiveFailures: number;
        failingSince: Date | null;
        disabledAt: Date | null;
      }[]
    >`SELECT id, "userId", url, "consecutiveFailures", "failingSince", "disabledAt"
      FROM webhook_endpoint WHERE id = ${delivery.endpointId} FOR NO KEY UPDATE`;
    const [row] = await tx.$queryRaw<
      {
        state: string;
        attemptCount: number;
        maxAttempts: number;
        expiresAt: Date;
        enqueueSeq: number;
      }[]
    >`SELECT state::text AS state, "attemptCount", "maxAttempts", "expiresAt", "enqueueSeq"
      FROM webhook_delivery WHERE id = ${delivery.deliveryId} FOR UPDATE`;
    if (!endpoint || !row) return { state: "lost", disabled: null };
    await tx.webhookDeliveryAttempt.createMany({
      data: [
        {
          deliveryId: delivery.deliveryId,
          attempt: delivery.attempt,
          startedAt: attempt.startedAt,
          durationMs: attempt.durationMs,
          statusCode: attempt.statusCode,
          errorClass: attempt.errorClass,
          resolvedAddress: attempt.resolvedAddress,
          responseExcerpt: attempt.responseExcerpt,
        },
      ],
      skipDuplicates: true,
    });
    if (row.state !== "IN_FLIGHT" || row.attemptCount !== delivery.attempt)
      return { state: "lost", disabled: null };
    const counts = delivery.kind !== "test" && attempt.errorClass !== "not_configured";
    if (attempt.errorClass === null) {
      await tx.webhookDelivery.update({
        where: { id: delivery.deliveryId },
        data: {
          state: "SUCCEEDED",
          completedAt: now,
          leaseUntil: null,
          lastStatusCode: attempt.statusCode,
          lastErrorClass: null,
        },
      });
      if (delivery.kind !== "test")
        await tx.webhookEndpoint.update({
          where: { id: endpoint.id },
          data: { consecutiveFailures: 0, failingSince: null, lastSuccessAt: now },
        });
      return { state: "SUCCEEDED", disabled: null };
    }
    const at = nextAttemptAt({
      completed: delivery.attempt,
      maxAttempts: row.maxAttempts,
      now,
      expiresAt: row.expiresAt,
      retryAfterSeconds: attempt.retryAfterSeconds,
      random: options.random,
    });
    // A retry waits unreleased in Postgres until `at`; the releaser hands it out.
    await tx.webhookDelivery.update({
      where: { id: delivery.deliveryId },
      data: at
        ? {
            state: "PENDING",
            nextAttemptAt: at,
            leaseUntil: null,
            enqueueSeq: row.enqueueSeq + 1,
            enqueuedAt: null,
            lastStatusCode: attempt.statusCode,
            lastErrorClass: attempt.errorClass,
          }
        : {
            state: "FAILED",
            completedAt: now,
            leaseUntil: null,
            lastStatusCode: attempt.statusCode,
            lastErrorClass: attempt.errorClass,
          },
    });
    let disabled: RecordOutcome["disabled"] = null;
    if (counts) {
      const failures = endpoint.consecutiveFailures + 1;
      const failingSince = endpoint.failingSince ?? now;
      const disable =
        endpoint.disabledAt === null &&
        shouldDisableEndpoint({ failingSince, consecutiveFailures: failures, now });
      await tx.webhookEndpoint.update({
        where: { id: endpoint.id },
        data: {
          consecutiveFailures: failures,
          failingSince,
          lastFailureAt: now,
          lastFailureClass: attempt.errorClass,
          ...(disable
            ? { disabledAt: now, disabledReason: "sustained_failures", disabledNotifiedAt: now }
            : {}),
        },
      });
      if (disable) {
        await tx.webhookDelivery.updateMany({
          where: { endpointId: endpoint.id, state: "PENDING" },
          data: { state: "CANCELLED", lastErrorClass: "endpoint_disabled", completedAt: now },
        });
        disabled = {
          endpointId: endpoint.id,
          userId: endpoint.userId,
          url: endpoint.url,
          consecutiveFailures: failures,
        };
      }
    }
    // Disabling cancelled every PENDING delivery of the endpoint, this one included.
    if (disabled) return { state: "FAILED", disabled };
    return { state: at ? "PENDING" : "FAILED", disabled: null };
  });
}

// --- Maintenance ----------------------------------------------------------------

/**
 * The 60 s maintenance tick: reclaim expired leases (the duplicate source:
 * receivers dedupe by webhook-id), fail expired deliveries, clear expired
 * rotation overlaps, and re-encrypt secrets still under a previous root
 * key. Each step is bounded.
 */
export async function runMaintenance(
  options: {
    client?: Client;
    now?: Date;
    keys?: readonly WebhookSecretKey[];
    /** Rekey scan position carried across ticks by the dispatcher. */
    rekeyCursor?: RekeyCursor;
  } = {},
): Promise<{
  reclaimed: number;
  expired: number;
  clearedOverlaps: number;
  rekeyed: number;
  /** Rows no configured key could open this tick (a count only). */
  rekeyFailed: number;
}> {
  const client = options.client ?? prisma;
  const now = options.now ?? (await dbNow(client));
  const reclaimed = await client.$executeRaw`
    UPDATE webhook_delivery SET
      state = CASE WHEN "attemptCount" >= "maxAttempts" OR "expiresAt" <= ${now}
        THEN 'FAILED'::"WebhookDeliveryState" ELSE 'PENDING'::"WebhookDeliveryState" END,
      "completedAt" = CASE WHEN "attemptCount" >= "maxAttempts" OR "expiresAt" <= ${now} THEN ${now}::timestamp ELSE NULL END,
      "lastErrorClass" = 'worker_lost', "leaseUntil" = NULL, "nextAttemptAt" = ${now},
      "enqueueSeq" = "enqueueSeq" + 1, "enqueuedAt" = NULL
    WHERE id IN (SELECT id FROM webhook_delivery WHERE state = 'IN_FLIGHT' AND "leaseUntil" < ${now}
      ORDER BY "leaseUntil" LIMIT ${MAINTENANCE_BATCH} FOR UPDATE SKIP LOCKED)`;
  const expired = await client.$executeRaw`
    UPDATE webhook_delivery SET state = 'FAILED', "completedAt" = ${now}, "lastErrorClass" = 'expired'
    WHERE id IN (SELECT id FROM webhook_delivery WHERE state = 'PENDING' AND "expiresAt" <= ${now}
      ORDER BY "expiresAt" LIMIT ${MAINTENANCE_BATCH} FOR UPDATE SKIP LOCKED)`;
  // An expired previous secret never signs again (claimDelivery checks the
  // expiry), so drop its ciphertext instead of keeping it until the next
  // rotation. Endpoint rows only; a row a rotation holds is skipped and
  // cleared on a later tick. Runs before rekeying so dead secrets are not
  // re-encrypted.
  const clearedOverlaps = await client.$executeRaw`
    UPDATE webhook_endpoint SET "previousSecretCiphertext" = NULL, "previousSecretNonce" = NULL,
      "previousSecretKeyId" = NULL, "previousSecretVersion" = NULL, "previousSecretExpiresAt" = NULL
    WHERE "previousSecretExpiresAt" <= ${now} AND id IN (SELECT id FROM webhook_endpoint
      WHERE "previousSecretExpiresAt" <= ${now}
      ORDER BY "previousSecretExpiresAt", id LIMIT ${MAINTENANCE_BATCH} FOR NO KEY UPDATE SKIP LOCKED)`;
  const { rekeyed, failed: rekeyFailed } = options.keys
    ? await rekeySecrets(client, options.keys, options.rekeyCursor ?? newRekeyCursor())
    : { rekeyed: 0, failed: 0 };
  return { reclaimed, expired, clearedOverlaps, rekeyed, rekeyFailed };
}

export const REKEY_BATCH = 50;

/**
 * In-memory keyset position for re-encryption, kept by one dispatcher across
 * maintenance ticks (never persisted). Each tick scans at most `REKEY_BATCH`
 * stale rows after `afterId`, then advances past every row it looked at,
 * including rows no configured key can open (corrupt, or sealed under an
 * unknown root). A short batch wraps to the front, so unrecoverable rows can
 * never starve recoverable ones behind them: with N stale rows, every row is
 * visited within ceil(N / REKEY_BATCH) + 1 ticks.
 */
export type RekeyCursor = { afterId: string | null };

export function newRekeyCursor(): RekeyCursor {
  return { afterId: null };
}

/**
 * Re-encrypt secrets sealed under a non-current root (root-key rotation). Rows
 * store the ROOT kid, so `secretKeyId <> current kid` finds them. "Current" is
 * the kid the data-key epoch row names (the write fence), not this process's env current: a process that does not hold that
 * root rekeys nothing (`stale_writer`, retried next tick).
 */
async function rekeySecrets(
  client: Client,
  keys: readonly WebhookSecretKey[],
  cursor: RekeyCursor,
): Promise<{ rekeyed: number; failed: number }> {
  if (keys.length < 2) return { rekeyed: 0, failed: 0 };
  return client.$transaction(async (tx) => {
    let current: WebhookSecretKey;
    try {
      current = await fenceWriteKey(tx, keys);
    } catch (error) {
      if (error instanceof DataKeyStaleWriter) return { rekeyed: 0, failed: 0 };
      throw error;
    }
    const rows = await tx.$queryRaw<
      {
        id: string;
        userId: string;
        secretCiphertext: Uint8Array;
        secretNonce: Uint8Array;
        secretKeyId: string;
        secretVersion: number;
        previousSecretCiphertext: Uint8Array | null;
        previousSecretNonce: Uint8Array | null;
        previousSecretKeyId: string | null;
        previousSecretVersion: number | null;
      }[]
    >`SELECT id, "userId", "secretCiphertext", "secretNonce", "secretKeyId", "secretVersion",
        "previousSecretCiphertext", "previousSecretNonce", "previousSecretKeyId", "previousSecretVersion"
      FROM webhook_endpoint
      WHERE ("secretKeyId" <> ${current.rootKeyId} OR ("previousSecretKeyId" IS NOT NULL AND "previousSecretKeyId" <> ${current.rootKeyId}))
        AND id > ${cursor.afterId ?? ""}
      ORDER BY id LIMIT ${REKEY_BATCH} FOR NO KEY UPDATE SKIP LOCKED`;
    // Advance past every row looked at (opened or not); a short batch wraps.
    cursor.afterId = rows.length < REKEY_BATCH ? null : (rows.at(-1)?.id ?? null);
    let count = 0;
    let failed = 0;
    for (const row of rows) {
      const binding = (version: number) => ({ endpointId: row.id, userId: row.userId, version });
      try {
        const sealed =
          row.secretKeyId === current.rootKeyId
            ? null
            : sealSecret(
                openSecret(
                  {
                    ciphertext: row.secretCiphertext,
                    nonce: row.secretNonce,
                    keyId: row.secretKeyId,
                  },
                  binding(row.secretVersion),
                  keys,
                ),
                binding(row.secretVersion),
                current,
              );
        const previous =
          row.previousSecretCiphertext &&
          row.previousSecretNonce &&
          row.previousSecretKeyId &&
          row.previousSecretVersion !== null &&
          row.previousSecretKeyId !== current.rootKeyId
            ? sealSecret(
                openSecret(
                  {
                    ciphertext: row.previousSecretCiphertext,
                    nonce: row.previousSecretNonce,
                    keyId: row.previousSecretKeyId,
                  },
                  binding(row.previousSecretVersion),
                  keys,
                ),
                binding(row.previousSecretVersion),
                current,
              )
            : null;
        // Each update checks the kids it read (the rows are locked; belt and braces).
        await tx.webhookEndpoint.updateMany({
          where: {
            id: row.id,
            secretKeyId: row.secretKeyId,
            previousSecretKeyId: row.previousSecretKeyId,
          },
          data: {
            ...(sealed
              ? {
                  secretCiphertext: new Uint8Array(sealed.ciphertext),
                  secretNonce: new Uint8Array(sealed.nonce),
                  secretKeyId: sealed.keyId,
                }
              : {}),
            ...(previous
              ? {
                  previousSecretCiphertext: new Uint8Array(previous.ciphertext),
                  previousSecretNonce: new Uint8Array(previous.nonce),
                  previousSecretKeyId: previous.keyId,
                }
              : {}),
          },
        });
        count++;
      } catch {
        // Unrecoverable under every configured key: owners must rotate. Counted,
        // never logged with ids or values; the cursor has already moved past it.
        failed++;
      }
    }
    return { rekeyed: count, failed };
  });
}

// --- Reaper ------------------------------------------------------------------------

/**
 * Delete events past retention in bounded batches (deliveries and attempts
 * cascade). Lock order is everyone else's: in each batch's
 * transaction the endpoints those events' deliveries point at are locked FOR
 * KEY SHARE by id BEFORE any event is touched, so the reaper can wait on an
 * account finalization (endpoints, then deliveries, then events) but never
 * hold an event the finalizer needs while waiting on its deliveries. A batch
 * that still hits a deadlock (40P01) is retried once.
 */
export async function reapWebhookLog(
  options: {
    client?: Pick<typeof prisma, "$transaction" | "$queryRaw">;
    now?: Date;
    batch?: number;
  } = {},
): Promise<number> {
  const client = options.client ?? prisma;
  const now = options.now ?? (await dbNow(client));
  const cutoff = new Date(now.getTime() - WEBHOOK_LOG_RETENTION_DAYS * 86_400_000);
  const batch = options.batch ?? 1000;
  let deleted = 0;
  for (;;) {
    let result: { selected: number; deleted: number };
    try {
      result = await reapBatch(client, cutoff, batch);
    } catch (error) {
      if (!isDeadlock(error)) throw error;
      result = await reapBatch(client, cutoff, batch);
    }
    deleted += result.deleted;
    if (result.selected === 0 || result.deleted === 0 || result.selected < batch) break;
  }
  return deleted;
}

async function reapBatch(
  client: Pick<typeof prisma, "$transaction">,
  cutoff: Date,
  batch: number,
): Promise<{ selected: number; deleted: number }> {
  return client.$transaction(async (tx) => {
    const rows = await tx.$queryRaw<{ id: string }[]>`
      SELECT id FROM webhook_event WHERE "occurredAt" < ${cutoff}
      ORDER BY "occurredAt", id LIMIT ${batch}`;
    if (rows.length === 0) return { selected: 0, deleted: 0 };
    const ids = rows.map((row) => row.id);
    // 1. Endpoints first, by id (the order of fan-out and finalization).
    await tx.$queryRaw`
      SELECT id FROM webhook_endpoint
      WHERE id IN (SELECT DISTINCT "endpointId" FROM webhook_delivery WHERE "eventId" = ANY(${ids}::text[]))
      ORDER BY id FOR KEY SHARE`;
    // 2. Then the events (cascading their deliveries and attempts).
    const removed = await tx.webhookEvent.deleteMany({
      where: { id: { in: ids }, occurredAt: { lt: cutoff } },
    });
    return { selected: rows.length, deleted: removed.count };
  });
}

/** PostgreSQL 40P01 (deadlock_detected), however Prisma wraps it (P2034). */
export function isDeadlock(error: unknown): boolean {
  const seen = new Set<unknown>();
  const visit = (value: unknown): boolean => {
    if (!value || typeof value !== "object" || seen.has(value)) return false;
    seen.add(value);
    const record = value as Record<string, unknown>;
    for (const key of ["code", "originalCode", "sqlState"])
      if (record[key] === "40P01" || record[key] === "P2034") return true;
    if (typeof record.message === "string" && /40P01|deadlock detected/.test(record.message))
      return true;
    return visit(record.meta) || visit(record.cause);
  };
  return visit(error);
}
