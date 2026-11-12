import type { Prisma } from "@wssp/db";
import { Prisma as PrismaValue } from "@wssp/db/client";

/**
 * Per-operation outbox lookups. Every outbox writer copies
 * `payload.operationId` into the indexed `operationId` column, so a lookup is
 * an index probe on `(userId, aggregateType, aggregateId, operationId)`
 * instead of a JSON read of every payload of the sandbox.
 */
export function outboxOperationWhere(operationId: string) {
  return { operationId } satisfies Prisma.OutboxEventWhereInput;
}

/** The same predicate for raw SQL over the unaliased outbox table, for a set
 * of operation ids. */
export function outboxOperationInSql(operationIds: readonly string[]) {
  const ids = [...operationIds];
  return PrismaValue.sql`"operationId" = ANY(${ids}::text[])`;
}

/** Single-operation form of `outboxOperationInSql`. */
export function outboxOperationSql(operationId: string) {
  return PrismaValue.sql`"operationId" = ${operationId}`;
}

/** The column value a writer stores for a payload: its string `operationId`. */
export function outboxOperationIdOf(payload: Prisma.InputJsonObject): string {
  if (typeof payload.operationId !== "string")
    throw new Error("Missing outbox operation identity.");
  return payload.operationId;
}
