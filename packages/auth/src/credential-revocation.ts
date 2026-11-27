import prisma from "@wssp/db";
import { withAuthorityChange } from "@wssp/db/authority";
import { notifyAuthSessionsRevoked } from "@wssp/db/session-revocation";
import { isAPIError } from "better-auth/api";
import { REVOKED_SESSION_OWNERS_MAX } from "./session-revocation-scope";

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
 * the password or consume the link, then sweeps credentials again afterward.
 * A revoked session can continue reading for at most the 60-second cookie-cache
 * window; credential minting and reset re-check the live session row.
 * If reset fails before the password write, signing out everywhere with the
 * password unchanged is the safe direction. Retry the idempotent transaction;
 * a failed before-sweep leaves the same recovery link usable.
 */
export async function revokeCredentialsAfterPasswordChange(
  userId: string,
  { revokeSessions = false }: { revokeSessions?: boolean } = {},
): Promise<void> {
  await withAuthorityChange({ ownerId: userId }, async () => {
    for (let attempt = 0; ; attempt += 1) {
      try {
        const impersonations = await prisma.$transaction(async (tx) => {
          await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${userId} FOR NO KEY UPDATE`;
          // Delete sessions in the revocation transaction with the owner lock held:
          // no surviving browser session may authorize a mint between sweeps.
          if (revokeSessions) await tx.session.deleteMany({ where: { userId } });
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
          // Machine enrollments/host credentials are deliberately not revoked here pending the owner decision.
          // Claimed pending and approved CLI requests must not mint a credential later.
          await tx.deviceCode.deleteMany({ where: { userId, scope: "user-login" } });
          await tx.oauthAccessToken.deleteMany({ where: { userId } });
          await tx.oauthRefreshToken.deleteMany({ where: { userId } });
          await tx.oauthConsent.deleteMany({ where: { userId } });
          return impersonations;
        });
        if (revokeSessions) notifyAuthSessionsRevoked({ userId });
        if (impersonations.length > REVOKED_SESSION_OWNERS_MAX) notifyAuthSessionsRevoked({});
        else
          for (const session of impersonations)
            notifyAuthSessionsRevoked({ userId: session.userId, sessionId: session.id });
        return;
      } catch (error) {
        if (attempt + 1 < REVOCATION_ATTEMPTS) {
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
  });
}

/** Only a successful password change requesting sign-out revokes credentials. */
export function passwordChangeRevocationTarget(ctx: {
  path: string;
  body?: unknown;
  returned?: unknown;
}): string | null {
  if (ctx.path !== "/change-password" || !isRecord(ctx.body)) return null;
  if (ctx.body.revokeOtherSessions !== true || isAPIError(ctx.returned)) return null;
  if (!isRecord(ctx.returned) || !isRecord(ctx.returned.user)) return null;
  const id = ctx.returned.user.id;
  return typeof id === "string" && id.length > 0 ? id : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object";
}
