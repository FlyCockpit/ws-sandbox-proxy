/**
 * wssp-ssh §10: retention of the `SandboxConnectSession` audit. Imported by
 * the worker's daily sweep, so it reaches nothing but Postgres (no server
 * environment).
 */
import prisma, { type Prisma } from "@wssp/db";

/** Rows older than this (by `openedAt`) are purged. */
export const CONNECT_SESSION_RETENTION_DAYS = 90;
const DAY_MS = 86_400_000;

/**
 * Delete rows whose `openedAt` is past retention, in id-page batches that
 * recheck the cutoff at delete time. At most `maxBatches` per run: the next
 * daily firing continues a backlog.
 */
export async function purgeConnectSessions(
  options: { now?: Date; batch?: number; maxBatches?: number } = {},
): Promise<number> {
  const now = options.now ?? new Date();
  const batch = Math.min(1000, Math.max(1, options.batch ?? 1000));
  const maxBatches = Math.max(1, options.maxBatches ?? 100);
  const where = {
    openedAt: { lt: new Date(now.getTime() - CONNECT_SESSION_RETENTION_DAYS * DAY_MS) },
  } satisfies Prisma.SandboxConnectSessionWhereInput;
  let deleted = 0;
  for (let round = 0; round < maxBatches; round += 1) {
    const rows = await prisma.sandboxConnectSession.findMany({
      where,
      orderBy: [{ openedAt: "asc" }, { id: "asc" }],
      take: batch,
      select: { id: true } satisfies Prisma.SandboxConnectSessionSelect,
    });
    if (rows.length === 0) break;
    const removed = await prisma.sandboxConnectSession.deleteMany({
      where: { ...where, id: { in: rows.map((row) => row.id) } },
    });
    deleted += removed.count;
    if (rows.length < batch || removed.count === 0) break;
  }
  return deleted;
}
