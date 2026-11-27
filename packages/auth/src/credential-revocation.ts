import { AsyncLocalStorage } from "node:async_hooks";
import { randomBytes } from "node:crypto";
import prisma, { type Prisma } from "@wssp/db";
import {
  type AuthorityChangeHold,
  holdAuthorityChange,
  withAuthorityChange,
} from "@wssp/db/authority";
import { notifyAuthSessionsRevoked } from "@wssp/db/session-revocation";
import { isAPIError } from "better-auth/api";
import { hashPassword } from "better-auth/crypto";
import { withLockSlot } from "./lock-slots.js";
import { REVOKED_SESSION_OWNERS_MAX } from "./session-revocation-scope";

type PrismaTransaction = Parameters<Parameters<typeof prisma.$transaction>[0]>[0];

/** Only the operations used here; plain and query-extended delegates differ. */
export type CredentialTransactionClient = Pick<PrismaTransaction, "$queryRaw" | "$executeRaw"> & {
  [Model in "user" | "sdkKey" | "mcpGrant" | "hostToken" | "hostDeviceCredential"]: {
    updateMany(
      args: Parameters<PrismaTransaction[Model]["updateMany"]>[0],
    ): Promise<Prisma.BatchPayload>;
  };
} & {
  [Model in
    | "session"
    | "verification"
    | "deviceCode"
    | "oauthAccessToken"
    | "oauthRefreshToken"
    | "oauthConsent"]: {
    deleteMany(
      args: Parameters<PrismaTransaction[Model]["deleteMany"]>[0],
    ): Promise<Prisma.BatchPayload>;
  };
} & {
  session: {
    findMany(args: {
      where: Prisma.SessionWhereInput;
      select: { id: true; userId: true };
      take: number;
    }): Promise<{ id: string; userId: string }[]>;
  };
  verification: {
    findMany(args: {
      where: Prisma.VerificationWhereInput;
      select: { identifier: true };
      take: number;
    }): Promise<{ identifier: string }[]>;
  };
};

/** Transaction-local revocations and notifications settle only after the real commit. */
type CredentialTransaction = {
  tx: CredentialTransactionClient;
  notifications: (() => void)[];
  holds: Map<string, AuthorityChangeHold>;
};
const credentialTransaction = new AsyncLocalStorage<CredentialTransaction>();

/** The interactive transaction contract shared by plain and extended clients. */
export type CredentialTransactionDatabase = {
  $transaction<T>(work: (tx: CredentialTransactionClient) => Promise<T>): Promise<T>;
};

export function afterCredentialCommit(notify: () => void): void {
  const scope = credentialTransaction.getStore();
  if (scope) scope.notifications.push(notify);
  else notify();
}

export async function withCredentialTransaction<T>(
  database: CredentialTransactionDatabase,
  work: (tx: CredentialTransactionClient) => Promise<T>,
): Promise<T> {
  const notifications: (() => void)[] = [];
  const holds = new Map<string, AuthorityChangeHold>();
  let committed = false;
  try {
    const result = await database.$transaction((tx) =>
      credentialTransaction.run({ tx, notifications, holds }, () => work(tx)),
    );
    committed = true;
    for (const notify of notifications) notify();
    return result;
  } finally {
    for (const hold of holds.values()) hold.settle(committed);
  }
}

const REVOCATION_ATTEMPTS = 3;
const TWO_FACTOR_CHALLENGE_BATCH = 100;
const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * Shared by password recovery and a password change that ends other sessions.
 * Keep revoked rows for audits; vault logins are guest credentials, not app
 * authentication, and are deliberately untouched.
 *
 * The owner fence invalidates existing authority tickets and wakes live MCP,
 * host and CLI connections. Durable credential checks still run on each request.
 * The owner row lock precedes credential writes, matching admission's owner-first
 * order; NO KEY UPDATE also permits unrelated FK KEY SHARE writers.
 *
 * Reset revokes all sessions in this transaction before Better Auth may write
 * the password or consume the link, then sweeps ALL sessions and credentials again afterward.
 * Lock order: password-write (if present) → this existing owner row lock.
 * Single-connection admissions need no extra slot; never add a competing
 * credential advisory lock or reverse owner → host → code order.
 * Session reads bypass the cookie cache and refuse a revoked row on the next
 * check; credential minting and reset also re-check the live session row.
 * If reset fails before the password write, signing out everywhere with the
 * password unchanged is the safe direction. Retry the idempotent transaction;
 * a failed before-sweep leaves the same recovery link usable.
 */
export async function revokeCredentialsAfterPasswordChange(
  userId: string,
  {
    revokeSessions = false,
    keepSessionToken,
  }: { revokeSessions?: boolean; keepSessionToken?: string } = {},
): Promise<void> {
  const scope = credentialTransaction.getStore();
  if (scope && !scope.holds.has(userId))
    scope.holds.set(userId, holdAuthorityChange({ ownerId: userId }));
  const run = async () => {
    for (let attempt = 0; ; attempt += 1) {
      try {
        const writes = async (tx: CredentialTransactionClient) => {
          await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${userId} FOR NO KEY UPDATE`;
          // Delete sessions in the revocation transaction with the owner lock held:
          // no surviving browser session may authorize a mint between sweeps.
          if (revokeSessions || keepSessionToken)
            await tx.session.deleteMany({
              where: {
                userId,
                ...(keepSessionToken ? { token: { not: keepSessionToken } } : {}),
              },
            });
          // An administrator's impersonation belongs to the target user, but
          // it is still authority obtained by this administrator's password.
          const impersonations = await tx.session.findMany({
            where: { impersonatedBy: userId },
            select: { id: true, userId: true },
            take: REVOKED_SESSION_OWNERS_MAX + 1,
          });
          await tx.session.deleteMany({ where: { impersonatedBy: userId } });
          // Better Auth 1.7.18: 2fa-<random> holds the user ID. Pending
          // OTPs and attempt counters hold hashes/counts, keyed by that ID.
          // Delete each bounded batch with its dependents while holding the
          // owner lock; neither sweep may leave a pending sign-in usable.
          for (;;) {
            const challenges = await tx.verification.findMany({
              where: { value: userId, identifier: { startsWith: "2fa-" } },
              select: { identifier: true },
              take: TWO_FACTOR_CHALLENGE_BATCH,
            });
            if (challenges.length === 0) break;
            await tx.verification.deleteMany({
              where: {
                identifier: {
                  in: challenges.flatMap(({ identifier }) => [
                    identifier,
                    `2fa-attempts-${identifier}`,
                    `2fa-otp-${identifier}`,
                  ]),
                },
              },
            });
          }
          await tx.verification.deleteMany({
            where: {
              OR: [
                { value: userId, identifier: { startsWith: "trust-device-" } },
                // Authenticated-session OTPs use userId!sessionId instead.
                { identifier: { startsWith: `2fa-otp-${userId}!` } },
              ],
            },
          });
          const where = { userId, revokedAt: null };
          const data = { revokedAt: new Date() };
          await tx.sdkKey.updateMany({ where, data });
          await tx.mcpGrant.updateMany({ where, data });
          if (revokeSessions && !keepSessionToken) {
            // Both recovery sweeps and quarantine revoke machine authority
            // under the same owner fence used by enrollment and token minting.
            // Keep host rows and their data; only authentication is revoked.
            await tx.hostToken.updateMany({ where, data });
            await tx.hostDeviceCredential.updateMany({ where, data });
            // Claimed pending and approved host/CLI codes cannot mint later.
            await tx.deviceCode.deleteMany({ where: { userId } });
          } else {
            // A signed-in password change keeps the owner's enrolled hosts.
            await tx.deviceCode.deleteMany({ where: { userId, scope: "user-login" } });
          }
          await tx.oauthAccessToken.deleteMany({ where: { userId } });
          await tx.oauthRefreshToken.deleteMany({ where: { userId } });
          await tx.oauthConsent.deleteMany({ where: { userId } });
          return impersonations;
        };
        const impersonations = scope
          ? await writes(scope.tx)
          : await withLockSlot(() => prisma.$transaction(writes));
        afterCredentialCommit(() => {
          if (revokeSessions || keepSessionToken) notifyAuthSessionsRevoked({ userId });
          if (impersonations.length > REVOKED_SESSION_OWNERS_MAX) notifyAuthSessionsRevoked({});
          else
            for (const session of impersonations)
              notifyAuthSessionsRevoked({ userId: session.userId, sessionId: session.id });
        });
        return;
      } catch (error) {
        if (!scope && attempt + 1 < REVOCATION_ATTEMPTS) {
          await sleep(attempt === 0 ? 100 : 400);
          continue;
        }
        // Never log the error object/message: query parameters can hold secrets.
        console.error("[auth] SECURITY: password credential revocation failed", {
          userId,
          errorClass: error instanceof Error ? error.constructor.name : typeof error,
        });
        throw error;
      }
    }
  };
  if (scope) await run();
  else await withAuthorityChange({ ownerId: userId }, run);
}

export type PasswordChangeRevocationTarget = { userId: string; keepSessionToken: string };

/** Only a successful password change requesting sign-out revokes credentials. */
export function passwordChangeRevocationTarget(ctx: {
  path: string;
  body?: unknown;
  returned?: unknown;
}): PasswordChangeRevocationTarget | null {
  if (ctx.path !== "/change-password" || !isRecord(ctx.body)) return null;
  if (ctx.body.revokeOtherSessions !== true || isAPIError(ctx.returned)) return null;
  if (!isRecord(ctx.returned) || !isRecord(ctx.returned.user)) return null;
  const id = ctx.returned.user.id;
  const token = ctx.returned.token;
  if (typeof id !== "string" || id.length === 0 || typeof token !== "string" || token.length === 0)
    return null;
  return { userId: id, keepSessionToken: token };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object";
}

/**
 * A delayed adapter password write may commit after its outer lock expired.
 * Scramble the credential first, then run the all-session revocation, so a
 * sign-in either sees the changed fingerprint or is caught by that sweep.
 * This deliberately takes no password-write lock: the caller may still hold it.
 * Recovery uses a fresh Forgot password link. Both steps retry and fail loudly.
 */
export async function quarantineUntrustedPasswordWrite(
  userId: string,
  { hash = hashPassword }: { hash?: (password: string) => Promise<string> } = {},
): Promise<void> {
  const unusable = await hash(randomBytes(32).toString("base64url"));
  for (let attempt = 0; ; attempt += 1) {
    try {
      await prisma.account.updateMany({
        where: { userId, providerId: "credential" },
        data: { password: unusable },
      });
      break;
    } catch (error) {
      if (attempt + 1 < REVOCATION_ATTEMPTS) {
        await sleep(attempt === 0 ? 100 : 400);
        continue;
      }
      console.error("[auth] SECURITY: untrusted password scramble failed", {
        userId,
        errorClass: error instanceof Error ? error.constructor.name : typeof error,
      });
      throw error;
    }
  }
  await revokeCredentialsAfterPasswordChange(userId, { revokeSessions: true });
}
