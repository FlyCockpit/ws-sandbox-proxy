import type { Prisma } from "@wssp/db";
import { serviceResourceFilter } from "../lib/sdk-key-access";
import type { Principal } from "./contracts";
import { poolNotFound } from "./errors";
import { viewerOf } from "./principal-kinds";

export const poolSelect = {
  id: true,
  slug: true,
  label: true,
  ownHostsOnly: true,
  disconnectGraceSeconds: true,
  maxLeaseMs: true,
  unlimitedLeaseForShares: true,
  memberImageCacheMaxGiB: true,
  preferOwnHosts: true,
  capacityWaitMaxMs: true,
  capacityQueuePerKeyMax: true,
  capacityQueuePerOwnerMax: true,
  createdAt: true,
  updatedAt: true,
  deletedAt: true,
} satisfies Prisma.SandboxPoolSelect;

/** Grant intersection is in SQL; a missing, foreign, ungranted or deleted ID
 * has the same response. Retained execution authority never calls this lookup. */
export async function visiblePool(tx: Prisma.TransactionClient, owner: Principal, id: string) {
  const { allowedPoolIds } = viewerOf(owner);
  if (allowedPoolIds !== "allUsable" && !allowedPoolIds.has(id)) throw poolNotFound();
  const pool = await tx.sandboxPool.findFirst({
    where: { AND: [serviceResourceFilter(owner, "pool"), { id, deletedAt: null }] },
    select: poolSelect,
  });
  if (!pool) throw poolNotFound();
  return pool;
}
