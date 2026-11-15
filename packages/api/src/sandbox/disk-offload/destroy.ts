import prisma, { type Prisma, type SandboxState } from "@wssp/db";
import { readSandboxOffloadEnv } from "@wssp/env/image-store-config";
import type { ImageStore } from "../image-store/s3";
import { requireRelayFence } from "../relay-fence-rejected";
import { shredOffloadKeys } from "./keys";

/**
 * DELETED safety for an offloaded disk.
 *
 * `endOffloadForDestroy` is the ONLY clearer of `Sandbox.diskOffloadId` for a
 * destroy, and it runs only for an `OWNER_DESTROY` teardown (the owner kill,
 * or the server-completed destroy of an OFFLOADED sandbox). Every other
 * DELETED writer leaves `diskOffloadId` set and the
 * `sandbox_instance_deleted_offload` CHECK aborts its transaction, so a
 * mis-mapped system teardown can never end the only copy (enumerated by
 * `deleted-writers.test.ts`).
 *
 * The stored object is not deleted here: the offload moves to DELETING with
 * the destroy's operation id and `shredAfter = now +
 * SANDBOX_OFFLOAD_SHRED_GRACE_HOURS`. `shredDestroyedOffloads` shreds it only
 * after that grace and only while the sandbox is still DELETED with that
 * operation as its terminal one; a refused gate keeps the key and the object
 * and raises an operational alert.
 */

type Tx = Prisma.TransactionClient;

/** The hostless state whose destroy is server-completed (written by detach only). */
const OFFLOADED = "OFFLOADED" satisfies SandboxState;

/**
 * End the sandbox's stored offload for its owner destroy. Caller holds S and
 * writes DELETED right after, in this transaction. Returns false (nothing
 * written) when the sandbox has no current offload or the teardown is not an
 * owner destroy.
 */
export async function endOffloadForDestroy(
  tx: Tx,
  input: {
    sandboxId: string;
    userId: string;
    destroyOperationId: string;
    now: Date;
    /** The server-completed destroy of an OFFLOADED sandbox at `generation`:
     * this write is also its DELETED write (generation + 1), since an
     * OFFLOADED row holds its disk pointer until it leaves OFFLOADED. */
    offloaded?: { generation: number };
  },
): Promise<boolean> {
  const destroy = await tx.sandboxOperation.findFirst({
    where: {
      id: input.destroyOperationId,
      sandboxId: input.sandboxId,
      userId: input.userId,
      kind: "KILL_SANDBOX",
      teardownIntent: "OWNER_DESTROY",
    },
    select: { id: true },
  });
  if (!destroy) return false;
  const sandbox = await tx.sandbox.findFirst({
    where: { id: input.sandboxId, userId: input.userId },
    select: { diskOffloadId: true },
  });
  const offloadId = sandbox?.diskOffloadId;
  if (!offloadId) return false;
  const [offload] = await tx.$queryRaw<{ state: string }[]>`SELECT state::text AS state
    FROM sandbox_disk_offload WHERE id = ${offloadId} AND "sandboxId" = ${input.sandboxId}
    FOR UPDATE`;
  requireRelayFence(offload?.state === "STORED" || offload?.state === "EVICTING");
  const cleared = input.offloaded
    ? await tx.sandbox.updateMany({
        where: {
          id: input.sandboxId,
          userId: input.userId,
          diskOffloadId: offloadId,
          state: OFFLOADED,
          generation: input.offloaded.generation,
        },
        data: {
          // credential-settlement: exempt — the caller settled (settleCredentialsOnDeleted).
          state: "DELETED",
          generation: input.offloaded.generation + 1,
          diskOffloadId: null,
          cachedOffloadSeq: null,
        },
      })
    : await tx.sandbox.updateMany({
        where: { id: input.sandboxId, userId: input.userId, diskOffloadId: offloadId },
        data: { diskOffloadId: null, cachedOffloadSeq: null },
      });
  requireRelayFence(cleared.count === 1);
  const hours = readSandboxOffloadEnv().SANDBOX_OFFLOAD_SHRED_GRACE_HOURS;
  const ended = await tx.sandboxDiskOffload.updateMany({
    where: { id: offloadId, state: { in: ["STORED", "EVICTING"] } },
    data: {
      state: "DELETING",
      liveSandboxId: null,
      destroyOperationId: input.destroyOperationId,
      shredAfter: new Date(input.now.getTime() + hours * 3_600_000),
      evictGrantId: null,
      evictHostId: null,
      evictGrantEpoch: null,
      evictGrantedAt: null,
      evictGrantExpiresAt: null,
    },
  });
  requireRelayFence(ended.count === 1);
  // Its stale local copies go too (discard at the next pass).
  await tx.sandboxDiskCopy.updateMany({
    where: { sandboxId: input.sandboxId, state: "STALE" },
    data: { discardSentAt: null },
  });
  return true;
}

const SHRED_PAGE = 100;

export type ShredGate = "shredded" | "refused" | "skipped";

/**
 * The deferred shred gate of one DELETING offload, in its own transaction:
 * shreds only when the sandbox is still DELETED and the recorded destroy is
 * its terminal (latest) lifecycle operation, SUCCEEDED.
 */
export async function shredDestroyedOffload(
  tx: Tx,
  offloadId: string,
  now: Date,
): Promise<ShredGate> {
  const [row] = await tx.$queryRaw<
    {
      state: string;
      sandboxId: string;
      destroyOperationId: string | null;
      shredAfter: Date | null;
      shreddedAt: Date | null;
    }[]
  >`SELECT state::text AS state, "sandboxId", "destroyOperationId", "shredAfter", "shreddedAt"
    FROM sandbox_disk_offload WHERE id = ${offloadId} FOR UPDATE`;
  if (
    row?.state !== "DELETING" ||
    row.shreddedAt !== null ||
    row.shredAfter === null ||
    row.shredAfter > now
  )
    return "skipped";
  const sandbox = await tx.sandbox.findUnique({
    where: { id: row.sandboxId },
    select: { state: true },
  });
  const terminal = await tx.sandboxOperation.findFirst({
    where: {
      sandboxId: row.sandboxId,
      kind: { in: ["CREATE_SANDBOX", "RECONNECT_SANDBOX", "STOP_SANDBOX", "KILL_SANDBOX"] },
    },
    orderBy: [{ generation: "desc" }, { createdAt: "desc" }],
    select: { id: true, state: true },
  });
  if (
    sandbox?.state !== "DELETED" ||
    row.destroyOperationId === null ||
    terminal?.id !== row.destroyOperationId ||
    terminal.state !== "SUCCEEDED"
  )
    return "refused";
  return (await shredOffloadKeys(tx, offloadId)) !== null ? "shredded" : "skipped";
}

/**
 * Maintenance pass (worker `disk_maintenance`): every DELETING offload past
 * its `shredAfter`. A shredded one has its object deleted and ends DELETED;
 * a refused gate raises an operational alert (ids only) and keeps both.
 */
export async function shredDestroyedOffloads(
  store: ImageStore | null,
  now: Date,
): Promise<{ shredded: number; refused: number }> {
  const due = await prisma.sandboxDiskOffload.findMany({
    where: { state: "DELETING", shreddedAt: { equals: null }, shredAfter: { lte: now } },
    select: { id: true, objectKey: true },
    orderBy: { id: "asc" },
    take: SHRED_PAGE,
  });
  let shredded = 0;
  let refused = 0;
  for (const row of due) {
    const gate = await prisma.$transaction((tx) => shredDestroyedOffload(tx, row.id, now));
    if (gate === "refused") {
      refused++;
      console.error(
        `[disk-offload] deferred shred refused: offload=${row.id} is not ended by its sandbox's terminal destroy; key and object kept`,
      );
      continue;
    }
    if (gate !== "shredded") continue;
    shredded++;
    if (store && row.objectKey) await store.deleteObject(row.objectKey).catch(() => {});
    await prisma.sandboxDiskOffload.updateMany({
      where: { id: row.id, state: "DELETING", shreddedAt: { not: null } },
      // credential-settlement: exempt — the offload row, not a sandbox.
      data: { state: "DELETED" },
    });
  }
  return { shredded, refused };
}
