import prisma, { type Prisma } from "@wssp/db";
import { Prisma as PrismaValue } from "@wssp/db/client";
import { type ImageStore, imageStore } from "../image-store/s3";
import { shredDestroyedOffloads } from "./destroy";
import { shredOffloadKeys } from "./keys";
import {
  type EndedOffload,
  endLiveOffload,
  enqueueDiskVerify,
  finishEndedOffload,
  lockSandboxRow,
  PRE_STORED_STATES,
  UPLOADABLE_STATES,
} from "./store";

/**
 * Disk offload maintenance (worker job `disk_maintenance`, hourly with the
 * image store sweep). Every pass is a
 * bounded page:
 *
 * 1. supersede: a live, not-yet-STORED offload whose sandbox left STOPPED at
 *    its source generation on its source host (the admission supersede's
 *    backstop, X2);
 * 2. stale: PENDING/EXPORTING with no begin for a while, UPLOADING with no
 *    OPEN session or whose session's transfer ended or expired → FAILED;
 *    (the upload stall rule runs on the server's 15 s image tick instead,
 *    `stallOffloadUploads`, which also tells the host);
 * 3. verify backstop: retry after an hour, fail unavailable after a day;
 * 4. consumed grace: a CONSUMED row past `deleteAfter` is shredded in the GC
 *    transaction that precedes the object delete (§3, §6a);
 * 5. retention (S3 step 5): rows in CONSUMED | SUPERSEDED | FAILED | DELETED
 *    shredded more than 30 days ago are hard-deleted (sessions, parts and
 *    transfers cascade), never while their object still exists;
 * 6. deferred destroy shred (§3, §8.9): a DELETING row past `shredAfter`
 *    whose sandbox is still DELETED by that destroy is shredded, its object
 *    deleted, and the row ends DELETED; a refused gate alerts and keeps it.
 */

const PAGE = 200;
const HOUR_MS = 3_600_000;
/** A requested export that never began is given up after this long. */
const OFFLOAD_PENDING_TIMEOUT_MS = 2 * HOUR_MS;
const VERIFY_TIMEOUT_MS = 24 * HOUR_MS;
const OFFLOAD_RETENTION_MS = 30 * 24 * HOUR_MS;

export type DiskMaintenanceResult = {
  superseded: number;
  failed: number;
  reverified: number;
  consumedShredded: number;
  retained: number;
  destroyShredded: number;
  destroyRefused: number;
};

async function endInSandboxLock(
  sandboxId: string,
  end: (tx: Prisma.TransactionClient) => Promise<EndedOffload | null>,
): Promise<EndedOffload | null> {
  return prisma.$transaction(async (tx) => {
    await lockSandboxRow(tx, sandboxId);
    return end(tx);
  });
}

export async function maintainDiskOffloads(
  store: ImageStore | null = imageStore(),
  now = new Date(),
  enqueueVerify: (offloadId: string) => Promise<void> = enqueueDiskVerify,
): Promise<DiskMaintenanceResult> {
  const result: DiskMaintenanceResult = {
    superseded: 0,
    failed: 0,
    reverified: 0,
    consumedShredded: 0,
    retained: 0,
    destroyShredded: 0,
    destroyRefused: 0,
  };
  // 1. The sandbox moved on: the attempt can never be stored.
  const moved = await prisma.$queryRaw<{ id: string; sandboxId: string }[]>`
    SELECT o.id, o."sandboxId" FROM sandbox_disk_offload o
    JOIN sandbox_instance s ON s.id = o."sandboxId"
    WHERE o.state::text = ANY(${[...PRE_STORED_STATES]}::text[])
      AND (s.state::text <> 'STOPPED' OR s.generation <> o."sourceGeneration"
        OR s."sandboxHostId" IS DISTINCT FROM o."sourceHostId")
    ORDER BY o.id LIMIT ${PAGE}`;
  for (const row of moved) {
    const ended = await endInSandboxLock(row.sandboxId, async (tx) => {
      // Re-check under the sandbox lock.
      const [still] = await tx.$queryRaw<{ ok: boolean }[]>`SELECT (s.state::text <> 'STOPPED'
          OR s.generation <> o."sourceGeneration"
          OR s."sandboxHostId" IS DISTINCT FROM o."sourceHostId") AS ok
        FROM sandbox_disk_offload o JOIN sandbox_instance s ON s.id = o."sandboxId"
        WHERE o.id = ${row.id}`;
      return still?.ok ? endLiveOffload(tx, row.id, "SUPERSEDED", "superseded") : null;
    });
    if (ended) result.superseded++;
    await finishEndedOffload(store, ended);
  }
  // 2. Stale attempts.
  const stalePredicate = PrismaValue.sql`((o.state::text IN ('PENDING', 'EXPORTING')
        AND o."updatedAt" < ${new Date(now.getTime() - OFFLOAD_PENDING_TIMEOUT_MS)})
      OR (o.state::text = 'UPLOADING' AND (
        (NOT EXISTS (SELECT 1 FROM sandbox_image_upload_session s WHERE s."liveDiskOffloadId" = o.id)
          AND o."updatedAt" < ${new Date(now.getTime() - 10 * 60_000)})
        OR EXISTS (SELECT 1 FROM sandbox_image_upload_session s
          JOIN sandbox_image_transfer t ON t.id = s."transferId"
          WHERE s."liveDiskOffloadId" = o.id AND (t.state::text <> 'OPEN' OR t."expiresAt" < ${now})))))`;
  const stale = await prisma.$queryRaw<{ id: string; sandboxId: string }[]>`
    SELECT o.id, o."sandboxId" FROM sandbox_disk_offload o WHERE ${stalePredicate}
    ORDER BY o.id LIMIT ${PAGE}`;
  for (const row of stale) {
    const ended = await endInSandboxLock(row.sandboxId, async (tx) => {
      // Begin may have committed a fresh session since the candidate scan.
      const [still] = await tx.$queryRaw<{ id: string }[]>`
        SELECT o.id FROM sandbox_disk_offload o WHERE o.id = ${row.id} AND ${stalePredicate}`;
      return still ? endLiveOffload(tx, row.id, "FAILED", "stale", UPLOADABLE_STATES) : null;
    });
    if (ended) result.failed++;
    await finishEndedOffload(store, ended);
  }
  // 3. Verify backstop: one page per run; a still-live job is left alone.
  // No dedicated VERIFYING timestamp exists; Complete sets updatedAt on entry.
  // Re-enqueueing/retrying verification never updates it.
  {
    const stuck = await prisma.sandboxDiskOffload.findMany({
      where: { state: "VERIFYING", updatedAt: { lt: new Date(now.getTime() - HOUR_MS) } },
      select: { id: true, sandboxId: true, updatedAt: true },
      orderBy: { id: "asc" },
      take: PAGE,
    });
    for (const row of stuck) {
      if (row.updatedAt.getTime() <= now.getTime() - VERIFY_TIMEOUT_MS) {
        const ended = await endInSandboxLock(row.sandboxId, async (tx) => {
          const still = await tx.sandboxDiskOffload.findFirst({
            where: { id: row.id, state: "VERIFYING", updatedAt: row.updatedAt },
            select: { id: true },
          });
          // Use the same shred-before-delete terminal path as stale uploads.
          // Unverified data is abandoned, never labelled corrupt or restored.
          return still
            ? endLiveOffload(tx, row.id, "FAILED", "verify_unavailable", ["VERIFYING"])
            : null;
        });
        if (ended) result.failed++;
        await finishEndedOffload(store, ended);
        continue;
      }
      if (!store) continue;
      try {
        await enqueueVerify(row.id);
        result.reverified++;
      } catch {
        // The next run retries; one unreachable job must not end the pass.
      }
    }
  }
  // 4. Consumed grace passed: shred, then delete the object (§3 order).
  const consumed = await prisma.sandboxDiskOffload.findMany({
    where: { state: "CONSUMED", shreddedAt: { equals: null }, deleteAfter: { lte: now } },
    select: { id: true, objectKey: true },
    orderBy: { id: "asc" },
    take: PAGE,
  });
  for (const row of consumed) {
    const shredded = await prisma.$transaction(async (tx) => {
      const [locked] = await tx.$queryRaw<{ state: string }[]>`SELECT state::text AS state
        FROM sandbox_disk_offload WHERE id = ${row.id} FOR UPDATE`;
      if (locked?.state !== "CONSUMED") return false;
      return (await shredOffloadKeys(tx, row.id)) !== null;
    });
    if (!shredded) continue;
    result.consumedShredded++;
    if (store && row.objectKey) await store.deleteObject(row.objectKey).catch(() => {});
  }
  // 5. Retention.
  const old = await prisma.sandboxDiskOffload.findMany({
    where: {
      state: { in: ["CONSUMED", "SUPERSEDED", "FAILED", "DELETED"] },
      shreddedAt: { lt: new Date(now.getTime() - OFFLOAD_RETENTION_MS) },
    },
    select: { id: true, objectKey: true },
    orderBy: { id: "asc" },
    take: PAGE,
  });
  for (const row of old) {
    if (row.objectKey) {
      // Never forget a row whose object the store still holds: delete it and
      // let a later pass retire the row.
      if (!store) continue;
      let exists = true;
      try {
        exists = await store.objectExists(row.objectKey);
      } catch {
        continue;
      }
      if (exists) {
        await store.deleteObject(row.objectKey).catch(() => {});
        continue;
      }
    }
    const deleted = await prisma.sandboxDiskOffload.deleteMany({
      where: {
        id: row.id,
        state: { in: ["CONSUMED", "SUPERSEDED", "FAILED", "DELETED"] },
        CurrentFor: { is: null },
      },
    });
    result.retained += deleted.count;
  }
  // 6. Deferred destroy shred.
  const destroyed = await shredDestroyedOffloads(store, now);
  result.destroyShredded = destroyed.shredded;
  result.destroyRefused = destroyed.refused;
  return result;
}
