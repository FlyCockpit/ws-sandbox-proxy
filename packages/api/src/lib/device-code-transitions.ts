import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import { precheckOwnerHostCapacity } from "../sandbox/owner-host-cap";

export function userCodeCandidates(userCode: string): string[] {
  const normalized = userCode.replace(/[^a-zA-Z0-9]/g, "").toUpperCase();
  return normalized && normalized !== userCode ? [userCode, normalized] : [userCode];
}

/** Call after acquiring the write locks: PostgreSQL now() freezes at BEGIN. */
export async function deviceDatabaseNow(tx: Prisma.TransactionClient): Promise<Date> {
  const [row] = await tx.$queryRaw<
    { now: Date }[]
  >`SELECT clock_timestamp() AT TIME ZONE 'UTC' AS now`;
  if (!row) throw new Error("Database clock unavailable");
  return row.now;
}

export type EnrollmentIntent = { kind: "create" } | { kind: "replace"; hostId: string };

const DEVICE_REQUEST_UNAVAILABLE = "Device request is no longer available.";

/** The conditional write owns the transition; a terminal status is not a lock. */
export async function transitionDeviceCode(input: {
  userCode: string;
  userId: string;
  action: "claim" | "approve" | "deny";
  intent?: EnrollmentIntent;
}) {
  const row = await prisma.deviceCode.findFirst({
    where: { userCode: { in: userCodeCandidates(input.userCode) } },
    select: { id: true, status: true, userId: true },
  });
  if (!row || row.status !== "pending" || (row.userId !== null && row.userId !== input.userId)) {
    throw new ORPCError("CONFLICT", { message: DEVICE_REQUEST_UNAVAILABLE });
  }
  if (input.action !== "claim" && (!row.userId || (input.action === "approve" && !input.intent))) {
    throw new ORPCError("BAD_REQUEST", { message: "Claim and review the device request first." });
  }
  // C52-R2-3: refuse an approval that could only fail at enrollment; the mint
  // re-checks the cap under its lock, so this read is advisory.
  if (input.action === "approve" && input.intent?.kind === "create") {
    await precheckOwnerHostCapacity(prisma, input.userId);
  }
  return prisma
    .$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM device_code WHERE id = ${row.id} FOR UPDATE`;
      const current = await tx.deviceCode.findUnique({
        where: { id: row.id },
        select: { status: true, userId: true, expiresAt: true },
      });
      const now = await deviceDatabaseNow(tx);
      if (
        input.action === "claim" &&
        current?.status === "pending" &&
        current.userId === input.userId &&
        current.expiresAt > now
      )
        return { success: true, deviceRequestId: row.id };
      const changed = await tx.deviceCode.updateMany({
        where: { id: row.id, status: "pending", userId: row.userId, expiresAt: { gt: now } },
        data:
          input.action === "claim"
            ? { userId: input.userId }
            : {
                status: input.action === "approve" ? "approved" : "denied",
                ...(input.action === "approve"
                  ? {
                      enrollmentIntent: input.intent?.kind,
                      replaceHostId: input.intent?.kind === "replace" ? input.intent.hostId : null,
                    }
                  : {}),
              },
      });
      if (changed.count !== 1) {
        throw new ORPCError("CONFLICT", { message: DEVICE_REQUEST_UNAVAILABLE });
      }
      return { success: true, deviceRequestId: row.id };
    })
    .catch(rethrowDeviceTransactionError);
}

/** Match structured Prisma/adapter SQLSTATEs, never human-readable messages. */
export function rethrowDeviceTransactionError(error: unknown): never {
  const visited = new Set<unknown>();
  function retryable(value: unknown): boolean {
    if (!value || typeof value !== "object" || visited.has(value)) return false;
    visited.add(value);
    const record = value as Record<string, unknown>;
    if (
      [record.code, record.sqlState, record.originalCode].some(
        (code) => code === "P2034" || code === "40P01" || code === "40001",
      )
    )
      return true;
    return [record.meta, record.cause, record.driverAdapterError].some(retryable);
  }
  if (retryable(error))
    throw new ORPCError("SERVICE_UNAVAILABLE", {
      message: "Device request is busy; poll again.",
      data: { deviceFlowError: "authorization_pending" },
      cause: error,
    });
  throw error;
}
