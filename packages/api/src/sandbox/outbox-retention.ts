import prisma from "@wssp/db";
import { Prisma as PrismaValue } from "@wssp/db/client";

/**
 * Outbox maintenance (D5), run by the relay retention task
 * (`apps/server/src/sandbox-relay/command-output.ts`).
 *
 * Every statement here is bounded, and every lock is taken with SKIP LOCKED:
 * these passes never wait on a relay transaction, so they cannot join a lock
 * cycle, and a row a relay transaction holds is simply left for a later tick.
 */

/** Processed rows of a torn-down DELETED sandbox are kept this long. */
export const OUTBOX_RETENTION_DAYS = 30;
const DAY_MS = 86_400_000;

type Client = Pick<typeof prisma, "$transaction" | "$queryRaw">;

/** Sandbox `s` is DELETED, detached, holds nothing, has no unsettled operation
 * or unprocessed outbox row, and was last written before `cutoff`. */
function prunableSandbox(cutoff: Date) {
  return PrismaValue.sql`s.state = 'DELETED' AND s."sandboxHostId" IS NULL
    AND NOT s."liveResourcesHeld" AND NOT s."diskReservationHeld"
    AND s."updatedAt" < ${cutoff}
    AND NOT EXISTS (
      SELECT 1 FROM sandbox_mutation_operation o
      WHERE o."sandboxId" = s.id AND o.state NOT IN ('SUCCEEDED', 'FAILED', 'CANCELLED'))
    AND NOT EXISTS (
      SELECT 1 FROM sandbox_dispatch_outbox e
      WHERE e."userId" = s."userId" AND e."aggregateType" = 'sandbox'
        AND e."aggregateId" = s.id AND e."processedAt" IS NULL)`;
}

async function databaseNow(client: Pick<typeof prisma, "$queryRaw">): Promise<Date> {
  const [row] = await client.$queryRaw<
    { now: Date }[]
  >`SELECT clock_timestamp() AT TIME ZONE 'UTC' AS now`;
  if (!row) throw new Error("database clock unavailable");
  return row.now;
}

/**
 * Delete processed outbox rows of sandboxes that were DELETED and torn down
 * at least `OUTBOX_RETENTION_DAYS` ago. Nothing reads such rows: every outbox
 * read is either an unprocessed-row scan or a lookup by an operation the
 * relay is still driving, and a sandbox qualifies only when it holds no live
 * or disk resources, is detached from every host, has no unprocessed outbox
 * row and no operation outside SUCCEEDED/FAILED/CANCELLED, and has not been
 * written for the retention window. A remnant re-attach writes the sandbox
 * (generation, host) and so restarts its window.
 *
 * Bounded per call: at most `sandboxLimit` sandboxes after `cursor`, each in
 * pages of `batch` rows, one transaction per page, and at most `maxPages`
 * pages in total (a sandbox cut off by the budget is resumed, not skipped). The sandbox row (S) is
 * locked before its outbox rows, as everywhere else. Returns the cursor to
 * resume from ("" once the scan wraps).
 */
export async function pruneDeletedSandboxOutbox(
  options: {
    client?: Client;
    now?: Date;
    cursor?: string;
    sandboxLimit?: number;
    batch?: number;
    maxPages?: number;
    signal?: AbortSignal;
  } = {},
): Promise<{ deleted: number; cursor: string }> {
  const client = options.client ?? prisma;
  const now = options.now ?? (await databaseNow(client));
  const cutoff = new Date(now.getTime() - OUTBOX_RETENTION_DAYS * DAY_MS);
  const sandboxLimit = Math.max(1, Math.min(200, options.sandboxLimit ?? 50));
  const batch = Math.max(1, Math.min(1000, options.batch ?? 500));
  const maxPages = Math.max(1, options.maxPages ?? 20);
  let pages = 0;
  const after = options.cursor ?? "";
  // Detached DELETED sandboxes are read from the (sandboxHostId, state) index;
  // only those with an expired processed row and every other condition met.
  const candidates = await client.$queryRaw<{ id: string; userId: string }[]>`
    SELECT s.id, s."userId" FROM sandbox_instance s
    WHERE ${prunableSandbox(cutoff)} AND s.id > ${after}
      AND EXISTS (
        SELECT 1 FROM sandbox_dispatch_outbox e
        WHERE e."userId" = s."userId" AND e."aggregateType" = 'sandbox'
          AND e."aggregateId" = s.id AND e."processedAt" < ${cutoff})
    ORDER BY s.id LIMIT ${sandboxLimit}`;
  let deleted = 0;
  let cursor = after;
  for (const sandbox of candidates) {
    if (options.signal?.aborted) return { deleted, cursor };
    for (;;) {
      const page = await client.$transaction(async (tx) => {
        // Re-checked under S: a re-attach or a new operation in between wins.
        const locked = await tx.$queryRaw<{ id: string }[]>`
          SELECT s.id FROM sandbox_instance s
          WHERE s.id = ${sandbox.id} AND s."userId" = ${sandbox.userId}
            AND ${prunableSandbox(cutoff)}
          FOR UPDATE OF s SKIP LOCKED`;
        if (locked.length === 0) return { selected: 0, removed: 0 };
        const rows = await tx.$queryRaw<{ id: string }[]>`
          SELECT id FROM sandbox_dispatch_outbox
          WHERE "userId" = ${sandbox.userId} AND "aggregateType" = 'sandbox'
            AND "aggregateId" = ${sandbox.id} AND "processedAt" < ${cutoff}
          ORDER BY id LIMIT ${batch}
          FOR UPDATE SKIP LOCKED`;
        if (rows.length === 0) return { selected: 0, removed: 0 };
        const removed = await tx.outboxEvent.deleteMany({
          where: {
            id: { in: rows.map((row) => row.id) },
            userId: sandbox.userId,
            aggregateType: "sandbox",
            aggregateId: sandbox.id,
            processedAt: { lt: cutoff },
          },
        });
        return { selected: rows.length, removed: removed.count };
      });
      deleted += page.removed;
      pages += 1;
      // An abort mid-sandbox resumes at this sandbox, not after it.
      if (options.signal?.aborted) return { deleted, cursor };
      if (page.selected < batch || page.removed === 0) break;
      // Out of budget mid-sandbox: resume at this sandbox next tick.
      if (pages >= maxPages) return { deleted, cursor };
    }
    cursor = sandbox.id;
  }
  return { deleted, cursor: candidates.length < sandboxLimit ? "" : cursor };
}
