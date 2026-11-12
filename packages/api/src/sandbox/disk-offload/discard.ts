import prisma, { type Prisma } from "@wssp/db";
import type { RootObservationV11, ServerDiskMessage } from "@wssp/sandbox-contracts";
import { releaseRootResources } from "../host-admission";
import { hostDatabaseNow, lockHostByEpoch, requireRelayFence } from "../relay-fence";
import { rootProofMatches } from "./detach";

export { noteCopyReported } from "./detach";

/**
 * Discard of a stale local copy.
 *
 * A `SandboxDiskCopy` holds its host's root reservation for a copy the
 * sandbox left behind. `discardFrames` sends each copy whose host is
 * connected a `disk.discard` (re-sent after `DISCARD_RETRY_MS`); the daemon
 * deletes the bound instance, or the orphan root named by the row's pool and
 * marker, and answers `disk.discarded`. `settleDiscarded` releases the copy
 * row's reservation once, only on a root proof matching the row, and then
 * deletes the row; a refusal leaves it for a later retry.
 */

type Tx = Prisma.TransactionClient;

/** A copy is asked to discard again after this long without an answer. */
export const DISCARD_RETRY_MS = 5 * 60_000;
const DISCARD_PAGE = 50;

/**
 * Tick: `disk.discard` for copies on connected offload-capable hosts not
 * asked recently (oldest first, bounded). Marks each DISCARDING with
 * `discardSentAt`; an undelivered frame is retried by the next pass.
 */
export async function discardFrames(
  now: Date,
): Promise<{ hostId: string; epoch: number; frame: ServerDiskMessage }[]> {
  const rows = await prisma.$queryRaw<
    {
      id: string;
      sandboxId: string;
      hostId: string;
      epoch: number;
      createKey: string;
      baseFingerprint: string;
      templateFingerprint: string;
      storagePoolName: string;
      storageMarker: string;
    }[]
  >`
    SELECT c.id, c."sandboxId", c."hostId", h."connectionEpoch" AS epoch, c."createKey",
      c."baseFingerprint", r."incusFingerprint" AS "templateFingerprint",
      c."storagePoolName", c."storageMarker"
    FROM sandbox_disk_copy c
    JOIN sandbox_host h ON h.id = c."hostId" AND h."userId" = c."hostOwnerId"
    JOIN sandbox_instance s ON s.id = c."sandboxId" AND s."userId" = c."userId"
    JOIN sandbox_template_revision r ON r.id = s."templateRevisionId" AND r."userId" = s."userId"
    WHERE h.status::text = 'CONNECTED' AND h."daemonDiskOffload"
      AND (c."discardSentAt" IS NULL OR c."discardSentAt" < ${new Date(now.getTime() - DISCARD_RETRY_MS)})
    ORDER BY c."discardSentAt" ASC NULLS FIRST, c.id
    LIMIT ${DISCARD_PAGE}`;
  const frames = [];
  for (const row of rows) {
    const marked = await prisma.sandboxDiskCopy.updateMany({
      where: {
        id: row.id,
        OR: [
          { discardSentAt: null },
          { discardSentAt: { lt: new Date(now.getTime() - DISCARD_RETRY_MS) } },
        ],
      },
      data: { state: "DISCARDING", discardSentAt: now },
    });
    if (marked.count !== 1) continue;
    frames.push({
      hostId: row.hostId,
      epoch: row.epoch,
      frame: {
        type: "disk.discard" as const,
        sandboxId: row.sandboxId,
        copyId: row.id,
        createKey: row.createKey,
        baseFingerprint: row.baseFingerprint,
        templateFingerprint: row.templateFingerprint,
        storagePoolName: row.storagePoolName,
        storageMarker: row.storageMarker,
      },
    });
  }
  return frames;
}

export type DiscardedOutcome = "released" | "refused" | "unknown";

/**
 * `disk.discarded` from the copy's host (current epoch): with a root proof
 * matching the row (pool name + marker, absent, network cleaned), release
 * the reservation once and delete the row; with a refusal code, leave the
 * row STALE for a retry after `DISCARD_RETRY_MS`.
 */
export async function settleDiscarded(
  tx: Tx,
  sender: { userId: string; hostId: string; connectionEpoch: number; isCurrent?: () => boolean },
  m: { sandboxId: string; copyId: string; rootAbsenceProof?: RootObservationV11; code?: string },
): Promise<DiscardedOutcome> {
  await lockHostByEpoch(tx, sender.hostId, sender.connectionEpoch, sender.userId);
  requireRelayFence(sender.isCurrent?.() !== false);
  const [copy] = await tx.$queryRaw<
    { id: string; storageMarker: string; storagePoolName: string }[]
  >`SELECT id, "storageMarker", "storagePoolName" FROM sandbox_disk_copy
    WHERE id = ${m.copyId} AND "sandboxId" = ${m.sandboxId} AND "hostId" = ${sender.hostId}
      AND "hostOwnerId" = ${sender.userId} FOR UPDATE`;
  if (!copy) return "unknown";
  if (!m.rootAbsenceProof || !rootProofMatches(m.rootAbsenceProof, copy)) {
    // The daemon refused (e.g. another binding lives there) or the proof
    // names another root: re-evaluated on a later pass.
    await tx.sandboxDiskCopy.updateMany({
      where: { id: copy.id },
      data: { state: "STALE", discardSentAt: await hostDatabaseNow(tx) },
    });
    return "refused";
  }
  await releaseRootResources(tx, { hostId: sender.hostId, copyId: copy.id });
  const deleted = await tx.sandboxDiskCopy.deleteMany({
    where: { id: copy.id, hostId: sender.hostId, diskReservationHeld: false },
  });
  requireRelayFence(deleted.count === 1);
  return "released";
}
