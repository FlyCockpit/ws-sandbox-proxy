import { ORPCError } from "@orpc/server";
import { hostSlugFromDeviceLoginScope } from "@wssp/config/host-device-login";
import {
  isUserDeviceLoginScope,
  type UserLoginGrant,
  userLoginGrantSchema,
} from "@wssp/config/user-device-login";
import prisma, { type Prisma } from "@wssp/db";
import { sessionPrincipal } from "../sandbox/contracts";
import { precheckOwnerHostCapacity } from "../sandbox/owner-host-cap";
import { requirePoolUse } from "../sandbox/sharing-authority";

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

/** What a stored device request is for; decided by its scope, never by the approver. */
export type DeviceRequestKind = "host" | "user";

export function deviceRequestKind(scope: string | null | undefined): DeviceRequestKind | null {
  if (isUserDeviceLoginScope(scope)) return "user";
  return hostSlugFromDeviceLoginScope(scope) !== null ? "host" : null;
}

/**
 * Advisory approve-time check of a user-login grant: the approver can use every
 * selected pool now. The mint re-checks under its locks, so a later loss of
 * access refuses the exchange instead.
 */
async function requireApprovableLoginGrant(userId: string, raw: unknown): Promise<UserLoginGrant> {
  const parsed = userLoginGrantSchema.safeParse(raw);
  if (!parsed.success) throw new ORPCError("BAD_REQUEST", { message: "Invalid login grant." });
  for (const poolId of parsed.data.poolIds)
    await requirePoolUse(prisma, sessionPrincipal(userId), poolId);
  return parsed.data;
}

/** The conditional write owns the transition; a terminal status is not a lock. */
export async function transitionDeviceCode(input: {
  userCode: string;
  userId: string;
  action: "claim" | "approve" | "deny";
  intent?: EnrollmentIntent;
  grant?: unknown;
}) {
  const row = await prisma.deviceCode.findFirst({
    where: { userCode: { in: userCodeCandidates(input.userCode) } },
    select: { id: true, status: true, userId: true, scope: true },
  });
  if (!row || row.status !== "pending" || (row.userId !== null && row.userId !== input.userId)) {
    throw new ORPCError("CONFLICT", { message: DEVICE_REQUEST_UNAVAILABLE });
  }
  const kind = deviceRequestKind(row.scope);
  if (input.action !== "claim" && !row.userId) {
    throw new ORPCError("BAD_REQUEST", { message: "Claim and review the device request first." });
  }
  // The stored scope decides the decision's shape: a host enrollment carries
  // only an intent, a user login only a grant. Either one on the wrong row (or
  // a row of neither kind) is refused before anything is written.
  if (input.action === "approve") {
    const valid =
      kind === "host"
        ? input.intent !== undefined && input.grant === undefined
        : kind === "user"
          ? input.grant !== undefined && input.intent === undefined
          : false;
    if (!valid)
      throw new ORPCError("BAD_REQUEST", { message: "Claim and review the device request first." });
  }
  // C52-R2-3: refuse an approval that could only fail at enrollment; the mint
  // re-checks the cap under its lock, so this read is advisory.
  if (input.action === "approve" && input.intent?.kind === "create") {
    await precheckOwnerHostCapacity(prisma, input.userId);
  }
  const loginGrant =
    input.action === "approve" && kind === "user"
      ? await requireApprovableLoginGrant(input.userId, input.grant)
      : null;
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
                ...(input.action === "approve" && kind === "host"
                  ? {
                      enrollmentIntent: input.intent?.kind,
                      replaceHostId: input.intent?.kind === "replace" ? input.intent.hostId : null,
                    }
                  : {}),
                ...(loginGrant ? { loginGrant } : {}),
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
