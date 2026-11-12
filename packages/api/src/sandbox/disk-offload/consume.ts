import type { Prisma } from "@wssp/db";
import { requireRelayFence } from "../relay-fence";
import { closeRestoreFetch } from "./restore-exit";
import { consumedGraceSeconds } from "./settings";

/**
 * READY consumes the stored object. The READY transaction of a restore (`isRestoreAttempt`) or of a
 * cached cold reconnect while `diskOffloadId` is set:
 *
 * - moves the offload `STORED → CONSUMED` with `deleteAfter = now + grace`
 *   (the admin setting, read once here; a later change never moves the row)
 *   and ends it as the live offload (`liveSandboxId` cleared);
 * - returns the sandbox fields its READY write carries in the same `data`:
 *   `diskOffloadId` and `cachedOffloadSeq` cleared (CHECK
 *   `sandbox_instance_offload_parked`) and, for a restore only,
 *   `diskBaseFingerprint = offload.fingerprint` (a cold reconnect keeps the
 *   lineage's base); `cloudInitInstanceId` stays as the offload recorded it;
 * - asks every stale copy of the sandbox to discard at the next pass;
 * - completes the restore's RESTORE_FETCH transfer.
 *
 * A CONSUMED copy is never a restore source (only the row `diskOffloadId`
 * points at, in STORED, is), never counted toward quota, and is shredded
 * and deleted once `deleteAfter` passes (maintenance step 4). Caller holds
 * H → S and the operation row; the sandbox row it read names `offloadId`.
 */
export async function consumeOffloadAtReady(
  tx: Prisma.TransactionClient,
  input: {
    sandboxId: string;
    offloadId: string;
    /** The READY of a restore attempt (else a cached cold reconnect). */
    restoreOperationId: string | null;
    now: Date;
  },
): Promise<Prisma.SandboxUncheckedUpdateManyInput> {
  const [offload] = await tx.$queryRaw<
    { state: string; fingerprint: string | null }[]
  >`SELECT state::text AS state, fingerprint FROM sandbox_disk_offload
    WHERE id = ${input.offloadId} AND "sandboxId" = ${input.sandboxId} FOR UPDATE`;
  // The current disk is STORED until a READY consumes it (I20).
  requireRelayFence(offload?.state === "STORED");
  const grace = await consumedGraceSeconds(tx);
  const consumed = await tx.sandboxDiskOffload.updateMany({
    where: { id: input.offloadId, sandboxId: input.sandboxId, state: "STORED" },
    data: {
      state: "CONSUMED",
      liveSandboxId: null,
      consumedAt: input.now,
      deleteAfter: new Date(input.now.getTime() + grace * 1000),
    },
  });
  requireRelayFence(consumed.count === 1);
  await tx.sandboxDiskCopy.updateMany({
    where: { sandboxId: input.sandboxId, state: "STALE" },
    data: { discardSentAt: null },
  });
  if (input.restoreOperationId) await closeRestoreFetch(tx, input.restoreOperationId, "restored");
  return {
    diskOffloadId: null,
    cachedOffloadSeq: null,
    ...(input.restoreOperationId && offload.fingerprint
      ? { diskBaseFingerprint: offload.fingerprint }
      : {}),
  };
}
