/** Shared proof state. Auth and API use the same User lock; no dependency cycle. */
import { createHash } from "node:crypto";
import type { Prisma } from "./index";

export const HOST_PROOF_COOLDOWN_MS = 600_000;
export const HOST_PROOF_LOCK_MS = 900_000;
export const HOST_PROOF_FRESH_MS = 5_000;
export const terminalFactorSelect = {
  id: true,
  userId: true,
  secret: true,
  verified: true,
  lockedUntil: true,
} satisfies Prisma.TwoFactorSelect;
export type TerminalFactor = Prisma.TwoFactorGetPayload<{ select: typeof terminalFactorSelect }>;
export const terminalProofUserSelect = {
  id: true,
  emailVerified: true,
  banned: true,
  banExpires: true,
  deletionRequestedAt: true,
  twoFactorEnabled: true,
  role: true,
  createdAt: true,
  hostTerminalFailedAttempts: true,
  hostTerminalLockedUntil: true,
  hostTerminalLastTotpStep: true,
  hostTerminalFactorFingerprint: true,
  hostTerminalFactorObservedAt: true,
} satisfies Prisma.UserSelect;
export type TerminalProofUser = Prisma.UserGetPayload<{ select: typeof terminalProofUserSelect }>;

export function factorFingerprint(factor: TerminalFactor | null): string {
  if (!factor) return "absent";
  return createHash("sha256")
    .update(
      JSON.stringify([
        factor.id,
        createHash("sha256").update(factor.secret).digest("hex"),
        factor.verified,
      ]),
    )
    .digest("hex");
}
export async function lockTerminalProofUser(tx: Prisma.TransactionClient, userId: string) {
  await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${userId} FOR NO KEY UPDATE`;
  return tx.user.findUnique({ where: { id: userId }, select: terminalProofUserSelect });
}
export async function lockTerminalFactor(tx: Prisma.TransactionClient, userId: string) {
  await tx.$queryRaw`SELECT id FROM two_factor WHERE "userId" = ${userId} FOR SHARE`;
  return tx.twoFactor.findUnique({ where: { userId }, select: terminalFactorSelect });
}
export async function terminalDatabaseTime(tx: Prisma.TransactionClient): Promise<Date> {
  const [row] = await tx.$queryRaw<
    { now: Date }[]
  >`SELECT clock_timestamp() AT TIME ZONE 'UTC' AS now`;
  if (!row) throw new Error("terminal clock unavailable");
  return row.now;
}
/** Always return a result: callers throw only AFTER this observation commits. */
export async function observeTerminalFactor(
  tx: Prisma.TransactionClient,
  user: TerminalProofUser,
  factor: TerminalFactor | null,
  now: Date,
): Promise<boolean> {
  const fingerprint = factorFingerprint(factor);
  if (user.hostTerminalFactorFingerprint !== fingerprint || !user.hostTerminalFactorObservedAt) {
    await tx.user.update({
      where: { id: user.id },
      data: {
        hostTerminalFactorFingerprint: fingerprint,
        hostTerminalFactorObservedAt: now,
      },
    });
    return false;
  }
  return now.getTime() - user.hostTerminalFactorObservedAt.getTime() >= HOST_PROOF_COOLDOWN_MS;
}
export function terminalProofLocked(
  user: TerminalProofUser,
  factor: TerminalFactor | null,
  now: Date,
) {
  return [user.hostTerminalLockedUntil, factor?.lockedUntil].some((at) => at && at > now);
}
export async function failTerminalProof(
  tx: Prisma.TransactionClient,
  user: TerminalProofUser,
  now: Date,
  forceLock = false,
) {
  const failures = user.hostTerminalFailedAttempts + 1;
  await tx.user.update({
    where: { id: user.id },
    data: {
      hostTerminalFailedAttempts: failures,
      ...(forceLock || failures >= 10
        ? {
            hostTerminalLockedUntil: new Date(
              Math.max(
                user.hostTerminalLockedUntil?.getTime() ?? 0,
                now.getTime() + HOST_PROOF_LOCK_MS,
              ),
            ),
          }
        : {}),
    },
  });
}
export async function advanceTerminalWatermark(
  tx: Prisma.TransactionClient,
  user: TerminalProofUser,
  steps: readonly number[],
) {
  const step = steps.length ? BigInt(Math.max(...steps)) : null;
  if (
    step !== null &&
    (user.hostTerminalLastTotpStep === null || step > user.hostTerminalLastTotpStep)
  )
    await tx.user.update({ where: { id: user.id }, data: { hostTerminalLastTotpStep: step } });
}
