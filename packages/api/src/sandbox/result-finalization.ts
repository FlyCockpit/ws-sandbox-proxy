import type { Prisma } from "@wssp/db";
import { Prisma as PrismaValue } from "@wssp/db/client";
import { lockResultQuota, resultOutboxLockQuery } from "./result-locks";

type Pending = { ownerId: string; operationIds: Set<string>; sandboxIds: Set<string> };
// Derived from the update-many args: the bare generated where-input name trips
// TruffleHog's Box token detector (a 32-char word next to "box").
type ResultWhere = NonNullable<Prisma.SandboxOperationResultUpdateManyArgs["where"]>;
const pending = new WeakMap<object, Pending>();
/** Defer the suffix until every prefix/outbox writer and host finalizer has
 * finished. All recorded O rows are already locked by the terminal writer. */
export function noteTerminalResultRelease(
  tx: Prisma.TransactionClient,
  ownerId: string,
  target: { operationId: string } | { sandboxId: string },
) {
  let entry = pending.get(tx);
  if (!entry) {
    entry = { ownerId, operationIds: new Set(), sandboxIds: new Set() };
    pending.set(tx, entry);
  }
  if (entry.ownerId !== ownerId) throw new Error("Result finalization must use one owner.");
  if ("operationId" in target) entry.operationIds.add(target.operationId);
  else entry.sandboxIds.add(target.sandboxId);
}
export async function zeroReservedResultHolds(
  tx: Prisma.TransactionClient,
  ownerId: string,
  where: ResultWhere,
) {
  return (
    await tx.sandboxOperationResult.updateMany({
      where: { AND: [where, { userId: ownerId, reservationState: "RESERVED" }] },
      data: {
        reservationState: "RELEASED",
        reservationBytes: 0,
        payload: PrismaValue.DbNull,
        continuation: PrismaValue.DbNull,
      },
    })
  ).count;
}
/** Structurally the final database work before commit, after host finalization. */
export async function finalizeTerminalResultHolds(tx: Prisma.TransactionClient) {
  const entry = pending.get(tx);
  if (!entry) return;
  const ids = [...entry.operationIds].sort();
  const sandboxes = [...entry.sandboxIds].sort();
  const where: ResultWhere = {
    userId: entry.ownerId,
    reservationState: "RESERVED",
    Operation: {
      state: { in: ["SUCCEEDED", "FAILED", "CANCELLED"] },
      OR: [{ id: { in: ids } }, { sandboxId: { in: sandboxes } }],
    },
  };
  const candidate = await tx.sandboxOperationResult.findFirst({
    where,
    select: { operationId: true },
  });
  if (!candidate) return;
  // Noted O rows are already held; their sandbox ids key the outbox index.
  const owning = await tx.sandboxOperation.findMany({
    where: { userId: entry.ownerId, id: { in: [...ids, candidate.operationId] } },
    select: { sandboxId: true },
    distinct: ["sandboxId"],
    take: 100,
  });
  // All affected O/outbox writes precede this sorted outbox suffix. No earlier
  // row is acquired after either quota lock, including by host finalization.
  await tx.$queryRaw(
    resultOutboxLockQuery(entry.ownerId, {
      sandboxIds: owning.map((row) => row.sandboxId),
      operationIds: ids,
      wholeSandboxIds: sandboxes,
    }),
  );
  await lockResultQuota(tx, entry.ownerId, [...ids, candidate.operationId]);
  await zeroReservedResultHolds(tx, entry.ownerId, where);
}
