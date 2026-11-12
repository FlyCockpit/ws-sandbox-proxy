import type { Prisma } from "@wssp/db";
import { Prisma as PrismaValue } from "@wssp/db/client";
import { outboxOperationInSql } from "./outbox-operation";

/** B1-C-3: the result suffix's outbox pass. `aggregateId` is the indexed
 * `(userId, aggregateType, aggregateId, operationId)` key, so the operation
 * filter only runs over the named sandboxes' rows, never the owner's whole
 * outbox history. */
export function resultOutboxLockQuery(
  ownerId: string,
  scope: {
    sandboxIds: readonly string[];
    operationIds: readonly string[];
    wholeSandboxIds?: readonly string[];
  },
) {
  const sandboxes = [...new Set([...scope.sandboxIds, ...(scope.wholeSandboxIds ?? [])])].sort();
  const operations = [...scope.operationIds].sort();
  const whole = [...(scope.wholeSandboxIds ?? [])].sort();
  return PrismaValue.sql`SELECT id FROM sandbox_dispatch_outbox WHERE "userId" = ${ownerId} AND "aggregateType" = 'sandbox' AND "aggregateId" = ANY(${sandboxes}::text[]) AND ("aggregateId" = ANY(${whole}::text[]) OR ${outboxOperationInSql(operations)}) ORDER BY id FOR UPDATE`;
}

// Transaction clients are unique per interactive transaction. Remember the
// suffix so reentrant finalizers cannot seek new prefix rows after quota.
const suffixes = new WeakMap<object, { ownerId: string; operationIds: ReadonlySet<string> }>();
export function assertBeforeResultQuota(tx: Prisma.TransactionClient) {
  if (suffixes.has(tx)) throw new Error("Prefix lock requested after result quota.");
}
/** Caller already holds K/H/S and all existing O rows in stable ID order. */
export async function lockResultQuota(
  tx: Prisma.TransactionClient,
  ownerId: string,
  operationIds: readonly string[],
) {
  const prior = suffixes.get(tx);
  if (prior) {
    // B1-C-5 (deferred to slice 6A): the suffix is single-shot per
    // transaction. A batched receipt or inventory reconcile must use one
    // result transaction per operation, or pre-declare its whole sorted
    // operation set in the first call; widening here fails closed.
    if (prior.ownerId !== ownerId || operationIds.some((id) => !prior.operationIds.has(id)))
      throw new Error("Result suffix cannot acquire another owner or operation.");
    return;
  }
  // B1-C-4: the global transfer-admission rank is taken only by transfer
  // work (lockTransferAdmission), always before this owner rank; a writer
  // that holds result quota can no longer take it, so the order is total.
  await tx.$queryRaw`SELECT 1 AS locked FROM pg_advisory_xact_lock(hashtextextended(${ownerId}, 270028))`;
  suffixes.set(tx, { ownerId, operationIds: new Set(operationIds) });
}

/** Global transfer admission (270027). It ranks before every owner result
 * quota, so it refuses a transaction that already holds the result suffix. */
export async function lockTransferAdmission(tx: Prisma.TransactionClient) {
  assertBeforeResultQuota(tx);
  await tx.$queryRaw`SELECT 1 FROM pg_advisory_xact_lock(270027)`;
}
