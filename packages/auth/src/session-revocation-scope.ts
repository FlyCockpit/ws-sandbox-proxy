/**
 * Who a Better Auth session delete revokes (C53-CC-2). The adapter deletes
 * sessions with `deleteMany({ where: { token: { equals } } })` (sign-out) or
 * `{ userId: { equals } }` (revoke-sessions, ban), so the deleted rows' owners
 * are resolved from the `where` itself, or by reading the matched rows'
 * `userId` just before the delete. Only those owners' long-lived browser
 * surfaces are then notified; the notification stays broad only when the
 * owners are genuinely unknown (unscoped delete, too many owners, read
 * failure). A notification carries no authority either way: listeners
 * re-read, and a missed or extra one only changes when they do.
 */
import prisma, { type Prisma } from "@wssp/db";
import { notifyAuthSessionsRevoked, type SessionRevocation } from "@wssp/db/session-revocation";

/** Above this many distinct owners one delete notifies everyone instead. */
export const REVOKED_SESSION_OWNERS_MAX = 100;

const sessionOwnerSelect = { userId: true } satisfies Prisma.SessionSelect;

/** A string, or Prisma's `{ equals: string }` filter of exactly that string. */
function exactString(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  if (value && typeof value === "object") {
    const keys = Object.keys(value);
    const equals = (value as { equals?: unknown }).equals;
    if (keys.length === 1 && keys[0] === "equals" && typeof equals === "string") return equals;
  }
  return undefined;
}

/**
 * The owners of the session rows `where` matches, resolved BEFORE the delete
 * runs; `null` when they cannot be bounded (notify everyone).
 */
export async function sessionOwnersFor(
  where: Prisma.SessionWhereInput | undefined,
): Promise<string[] | null> {
  if (!where || Object.keys(where).length === 0) return null;
  if (Object.keys(where).length === 1) {
    const userId = exactString(where.userId);
    if (userId !== undefined) return [userId];
  }
  try {
    const rows = await prisma.session.findMany({
      where,
      select: sessionOwnerSelect,
      distinct: ["userId"],
      take: REVOKED_SESSION_OWNERS_MAX + 1,
    });
    if (rows.length > REVOKED_SESSION_OWNERS_MAX) return null;
    return rows.map((row) => row.userId);
  } catch {
    return null;
  }
}

/** Notify each resolved owner, or everyone when the owners are unknown. */
export function notifySessionOwners(owners: readonly string[] | null): void {
  if (owners === null) {
    notifyAuthSessionsRevoked({});
    return;
  }
  for (const userId of owners) notifyAuthSessionsRevoked({ userId });
}

/** Retain a precise session hint when the delete names a bounded session set. */
export async function sessionRevocationsFor(
  where: Prisma.SessionWhereInput | undefined,
): Promise<SessionRevocation[]> {
  if (!where || Object.keys(where).length === 0) return [{}];
  const userId = Object.keys(where).length === 1 ? exactString(where.userId) : undefined;
  if (userId !== undefined) return [{ userId }];
  try {
    const rows = await prisma.session.findMany({
      where,
      select: { id: true, userId: true },
      take: REVOKED_SESSION_OWNERS_MAX + 1,
    });
    if (rows.length <= REVOKED_SESSION_OWNERS_MAX)
      return rows.map(({ id: sessionId, userId }) => ({ userId, sessionId }));
    const owners = await sessionOwnersFor(where);
    return owners === null ? [{}] : owners.map((userId) => ({ userId }));
  } catch {
    return [{}];
  }
}
export function notifySessionRevocations(scopes: readonly SessionRevocation[]): void {
  for (const scope of scopes) notifyAuthSessionsRevoked(scope);
}
