import { resolve } from "node:path";
import prisma from "@wssp/db";
import { env } from "@wssp/env/server";
import { ImageRelaySpool } from "./spool.js";

let spool: ImageRelaySpool | null = null;
/** The process-wide transient spool (single web service; see docs/infra.md). */
export function imageRelaySpool(): ImageRelaySpool {
  spool ??= new ImageRelaySpool(resolve(env.IMAGE_RELAY_SPOOL_DIR), env.IMAGE_RELAY_SPOOL_BYTES);
  return spool;
}

/**
 * Startup: relayed parts never survive a restart. Every OPEN relay transfer
 * fails with `server_restart` and its links are dropped; daemons re-request.
 */
export async function resetImageRelay(): Promise<void> {
  await imageRelaySpool().reset();
  // Not fatal: the image store sweeper expires anything this misses.
  await failOpenRelayTransfers().catch(() =>
    console.error("[image-relay] could not fail open relay transfers at startup"),
  );
}

async function failOpenRelayTransfers(): Promise<void> {
  const open = await prisma.sandboxImageTransfer.findMany({
    where: { mode: "RELAY", state: "OPEN" },
    select: { id: true },
    take: 1000,
  });
  if (open.length === 0) return;
  const ids = open.map((t) => t.id);
  await prisma.sandboxImageTransfer.updateMany({
    where: { id: { in: ids }, state: "OPEN" },
    data: { state: "FAILED", endReason: "server_restart" },
  });
  await prisma.sandboxImageLink.deleteMany({ where: { transferId: { in: ids } } });
}

/**
 * Release relayed parts of transfers that are no longer OPEN or have expired
 * (P2-13): the worker's sweep only changes rows; the bytes and the
 * reservation live in this process's spool. Bounded by the spool itself.
 */
export async function reconcileImageRelaySpool(
  spool: ImageRelaySpool = imageRelaySpool(),
  now = new Date(),
): Promise<number> {
  const held = spool.transferIds();
  if (held.length === 0) return 0;
  // pagination:audited — `id in held`: transfers with parts in this spool (bounded by its bytes).
  const live = await prisma.sandboxImageTransfer.findMany({
    where: { id: { in: held }, state: "OPEN", expiresAt: { gt: now } },
    select: { id: true },
  });
  const keep = new Set(live.map((row) => row.id));
  let dropped = 0;
  for (const id of held)
    if (!keep.has(id)) {
      await spool.dropTransfer(id);
      dropped++;
    }
  return dropped;
}
