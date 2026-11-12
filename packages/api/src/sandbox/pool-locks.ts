import { ORPCError } from "@orpc/server";
import type { Prisma } from "@wssp/db";

// Public active memberships plus one historical attribution retained by a guest.
export const MAX_ACTIVE_POOL_MEMBERSHIPS = 250;
export const MAX_POOL_GRAPH_PATHS = MAX_ACTIVE_POOL_MEMBERSHIPS + 1;

/** Exclusive G, sorted before H. Missing/deleted rows confer no authority. */
export async function lockPoolGraph(tx: Prisma.TransactionClient, ids: readonly string[]) {
  const sorted = [...new Set(ids)].sort();
  if (sorted.length > MAX_POOL_GRAPH_PATHS) throw poolGraphOverflow();
  if (sorted.length)
    await tx.$queryRaw`SELECT id FROM sandbox_pool WHERE id = ANY(${sorted}::text[]) ORDER BY id FOR UPDATE`;
}

/**
 * Shared G for read-only lease-policy lookups (setTimeout, warm reconnect,
 * the pull-in sweep, the lowering preview). Pool writers keep the exclusive
 * form, so a policy read waits for a concurrent pool or membership write and
 * readers do not serialize each other. Same order: sorted, before H. A
 * transaction must never take the exclusive form of a row it already holds
 * shared (that upgrade can deadlock against another sharer).
 */
export async function lockPoolGraphShared(tx: Prisma.TransactionClient, ids: readonly string[]) {
  const sorted = [...new Set(ids)].sort();
  if (sorted.length > MAX_POOL_GRAPH_PATHS) throw poolGraphOverflow();
  if (sorted.length)
    await tx.$queryRaw`SELECT id FROM sandbox_pool WHERE id = ANY(${sorted}::text[]) ORDER BY id FOR SHARE`;
}

export function poolGraphOverflow() {
  return new ORPCError("CONFLICT", {
    message: "Too many pool paths. Remove pool memberships before retrying this operation.",
  });
}
