import prisma from "@wssp/db";
import { Prisma as PrismaValue } from "@wssp/db/client";
import { type ImageStore, imageStore } from "../image-store/s3";
import { endLiveOffload, finishEndedOffload, lockSandboxRow, UPLOADABLE_STATES } from "./store";

/** One bounded page per call (like the maintenance steps). */
const PAGE = 200;

/**
 * An offload upload whose OPEN `OFFLOAD_UPLOAD` transfer moved no bytes for
 * this long (parts reports and the daemon's 30 s byte heartbeats move
 * `lastProgressAt`) ends FAILED `upload_stalled`: the backstop for a lost
 * failure report, so an attempt never holds its host's export slot until
 * the 24 h transfer expiry.
 */
export const OFFLOAD_UPLOAD_STALL_MS = 30 * 60_000;

/** A stalled upload the stall rule ended: its source host is told to drop it. */
type StalledOffloadUpload = {
  sandboxId: string;
  offloadId: string;
  seq: number;
  sourceHostId: string;
};

/**
 * The stall rule (bounded page): every UPLOADING offload whose live
 * session's OPEN `OFFLOAD_UPLOAD` transfer has `lastProgressAt` older than
 * `OFFLOAD_UPLOAD_STALL_MS` ends FAILED `upload_stalled`, re-checked under the
 * sandbox lock (a heartbeat or parts report since the scan keeps it), with
 * the usual cleanup. The ended row no longer holds its host's export slot.
 * Returns the ended attempts (the caller tells each source host).
 */
export async function endStalledOffloadUploads(
  store: ImageStore | null = imageStore(),
  now = new Date(),
): Promise<StalledOffloadUpload[]> {
  const cutoff = new Date(now.getTime() - OFFLOAD_UPLOAD_STALL_MS);
  const stalled = PrismaValue.sql`(o.state::text = 'UPLOADING' AND EXISTS (
      SELECT 1 FROM sandbox_image_upload_session s
      JOIN sandbox_image_transfer t ON t.id = s."transferId"
      WHERE s."liveDiskOffloadId" = o.id AND t.state::text = 'OPEN'
        AND t.purpose::text = 'OFFLOAD_UPLOAD' AND t."lastProgressAt" < ${cutoff}))`;
  const rows = await prisma.$queryRaw<{ id: string; sandboxId: string }[]>`
    SELECT o.id, o."sandboxId" FROM sandbox_disk_offload o WHERE ${stalled}
    ORDER BY o.id LIMIT ${PAGE}`;
  const ended: StalledOffloadUpload[] = [];
  for (const row of rows) {
    // One row at a time: a row that fails (a lock timeout, a deadlock
    // victim) never loses the rows already ended, nor their cancels.
    const done = await prisma
      .$transaction(async (tx) => {
        await lockSandboxRow(tx, row.sandboxId);
        // Lock order sandbox → offload → session → transfer: the session
        // before its transfer, as resume, completion and every upload
        // session frame take them; a heartbeat takes host → transfer.
        await tx.$queryRaw`SELECT id FROM sandbox_disk_offload WHERE id = ${row.id} FOR UPDATE`;
        await tx.$queryRaw`SELECT id FROM sandbox_image_upload_session
          WHERE "liveDiskOffloadId" = ${row.id} FOR UPDATE`;
        // Re-checked with the transfer row locked: a heartbeat that
        // committed first is seen, one that waits finds it no longer OPEN.
        const [still] = await tx.$queryRaw<{ id: string }[]>`
          SELECT o.id FROM sandbox_disk_offload o
          JOIN sandbox_image_upload_session s ON s."liveDiskOffloadId" = o.id
          JOIN sandbox_image_transfer t ON t.id = s."transferId"
          WHERE o.id = ${row.id} AND o.state::text = 'UPLOADING' AND t.state::text = 'OPEN'
            AND t.purpose::text = 'OFFLOAD_UPLOAD' AND t."lastProgressAt" < ${cutoff}
          FOR UPDATE OF t`;
        return still
          ? endLiveOffload(tx, row.id, "FAILED", "upload_stalled", UPLOADABLE_STATES)
          : null;
      })
      .catch(() => null);
    // Best-effort cleanup (the sweeper retries it): a failure never loses
    // this or another committed row's cancel (round 3).
    await finishEndedOffload(store, done).catch(() => {});
    if (done)
      ended.push({
        sandboxId: done.sandboxId,
        offloadId: done.offloadId,
        seq: done.seq,
        sourceHostId: done.sourceHostId,
      });
  }
  return ended;
}
