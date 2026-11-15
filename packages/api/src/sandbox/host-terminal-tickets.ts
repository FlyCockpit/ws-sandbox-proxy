import { randomBytes } from "node:crypto";
import { ORPCError } from "@orpc/server";
import { matchedTotpSteps } from "@wssp/auth/terminal-proof";
import {
  BROWSER_TERMINAL_MAX_COLS,
  BROWSER_TERMINAL_MAX_ROWS,
  BROWSER_TERMINAL_TICKET_PATTERN,
  BROWSER_TERMINAL_TICKET_TTL_MS,
} from "@wssp/config/browser-terminal";
import prisma, { type Prisma } from "@wssp/db";
import { authorityTicket } from "@wssp/db/authority";
import {
  advanceTerminalWatermark,
  factorFingerprint,
  failTerminalProof,
  HOST_PROOF_COOLDOWN_MS,
  HOST_PROOF_FRESH_MS,
  lockTerminalFactor,
  lockTerminalProofUser,
  observeTerminalFactor,
  type TerminalProofUser,
  terminalDatabaseTime,
  terminalProofLocked,
} from "@wssp/db/terminal-proof";
import { z } from "zod";
import { isOwnerCredentialPolicySatisfied } from "../lib/owner-credential-policy";
import { entityId } from "../lib/schemas";
import { getForcedTwoFactorSettingsRecord } from "../lib/two-factor-policy";
import { consumeSandboxWriteBudget } from "./budgets";
import {
  authorizeTerminalTransport,
  raiseLiveHostTerminalTotp,
  readHostTerminalPolicy,
} from "./host-terminal-policy";
import { consumeHostProofBudget, consumeTerminalMintBudget } from "./terminal-budgets";
import { type TerminalRevocation, terminalTicketDigest } from "./terminal-tickets";

export const createHostTerminalSessionInput = z
  .object({
    hostId: entityId,
    rows: z.number().int().min(1).max(BROWSER_TERMINAL_MAX_ROWS),
    cols: z.number().int().min(1).max(BROWSER_TERMINAL_MAX_COLS),
    code: z
      .string()
      .regex(/^\d{6}$/)
      .optional(),
  })
  .strict();
export type HostTerminalBinding = {
  kind: "host";
  userId: string;
  sessionId: string;
  hostId: string;
  hostOwnerId: string;
  epoch: number;
  rows: number;
  cols: number;
  policyRevision: number;
  proofRequired: boolean;
  verifiedAt: Date | null;
  factorFingerprint: string | null;
  observedAt: Date | null;
};
// Resolve the configured plugin context only for a required proof, once per process.
const loadProofContext = () => import("@wssp/auth").then(({ auth }) => auth.$context);
let proofContext: ReturnType<typeof loadProofContext> | undefined;
function configuredProofContext() {
  proofContext ??= loadProofContext();
  return proofContext;
}
const denied = (detail?: { reason: "enrollment" | "cooldown" | "locked"; retryAt?: Date }) =>
  new ORPCError("FORBIDDEN", { data: { code: "HOST_TERMINAL_PROOF_REQUIRED", ...detail } });
async function liveSession(
  tx: Prisma.TransactionClient,
  user: TerminalProofUser,
  sessionId: string,
  now: Date,
) {
  const session = await tx.session.findFirst({
    where: {
      id: sessionId,
      userId: user.id,
      expiresAt: { gt: now },
      impersonatedBy: null,
    },
    select: { id: true },
  });
  return Boolean(
    user.emailVerified &&
      session &&
      (await isOwnerCredentialPolicySatisfied(
        user,
        now,
        await getForcedTwoFactorSettingsRecord(tx),
      )),
  );
}
async function ownedHost(
  tx: Prisma.TransactionClient,
  userId: string,
  hostId: string,
  epoch: number,
) {
  // H follows User/session/factor; no admission/census/image readiness for host repair.
  await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${hostId} AND "userId" = ${userId} FOR UPDATE`;
  return tx.sandboxHost.findFirst({
    where: {
      id: hostId,
      userId,
      deletionRequestedAt: null,
      connectionEpoch: epoch,
      hostTerminalVetoedAt: null,
      status: "CONNECTED",
      relayProtocolVersion: "1.0",
      relayProtocolEpoch: epoch,
    },
    select: { id: true },
  });
}
export async function mintHostTerminalTicket(
  owner: { userId: string; sessionId: string },
  input: z.infer<typeof createHostTerminalSessionInput>,
) {
  const identity = { user: { id: owner.userId }, session: { id: owner.sessionId } };
  const { isLiveOwnerSessionAuthorized } = await import("../lib/sensitive-session-two-factor-gate");
  if (!(await isLiveOwnerSessionAuthorized(identity))) throw denied();
  await consumeTerminalMintBudget(`uid:${owner.userId}`);
  const policy = readHostTerminalPolicy(input.hostId, owner.userId);
  const host = await prisma.sandboxHost.findFirst({
    where: {
      id: input.hostId,
      userId: owner.userId,
      deletionRequestedAt: null,
    },
    select: { id: true, hostTerminalVetoedAt: true },
  });
  if (!host) throw new ORPCError("NOT_FOUND");
  if (host.hostTerminalVetoedAt || !policy?.hostTerminal)
    throw new ORPCError("CONFLICT", { data: { code: "HOST_TERMINAL_UNAVAILABLE" } });
  if (policy.requireHostTerminalTotp) {
    try {
      await consumeHostProofBudget(owner.userId);
    } catch (error) {
      await prisma.$transaction(async (tx) => {
        const user = await lockTerminalProofUser(tx, owner.userId);
        if (user) await failTerminalProof(tx, user, await terminalDatabaseTime(tx), true);
      });
      throw error;
    }
  }
  let refusal: { reason: "enrollment" | "cooldown" | "locked"; retryAt?: Date } | undefined;
  const snapshot = policy.requireHostTerminalTotp
    ? await prisma.$transaction(async (tx) => {
        const user = await lockTerminalProofUser(tx, owner.userId);
        if (!user) return null;
        const factor = await lockTerminalFactor(tx, owner.userId);
        const now = await terminalDatabaseTime(tx);
        const observed = await observeTerminalFactor(tx, user, factor, now);
        if (terminalProofLocked(user, factor, now)) {
          refusal = {
            reason: "locked",
            retryAt: new Date(
              Math.max(
                user.hostTerminalLockedUntil?.getTime() ?? 0,
                factor?.lockedUntil?.getTime() ?? 0,
              ),
            ),
          };
          return null;
        }
        if (!factor?.verified) {
          refusal = { reason: "enrollment" };
          return null;
        }
        if (!observed) {
          const same = user.hostTerminalFactorFingerprint === factorFingerprint(factor);
          refusal = {
            reason: "cooldown",
            retryAt: new Date(
              (same
                ? (user.hostTerminalFactorObservedAt?.getTime() ?? now.getTime())
                : now.getTime()) + HOST_PROOF_COOLDOWN_MS,
            ),
          };
          return null;
        }
        return {
          factor,
          fingerprint: factorFingerprint(factor),
          observedAt: user.hostTerminalFactorObservedAt!,
          at: now.getTime(),
        };
      })
    : null;
  if (policy.requireHostTerminalTotp && !snapshot) throw denied(refusal);
  const steps = snapshot
    ? await matchedTotpSteps(
        snapshot.factor,
        input.code ?? "",
        (await configuredProofContext()).secretConfig,
        snapshot.at,
      )
    : [];
  // Hygiene only: bounded owner-local expiry work; consume still burns/refuses expired rows.
  const expired = await prisma.hostTerminalTicket.findMany({
    where: { userId: owner.userId, expiresAt: { lte: new Date() } },
    select: { id: true },
    orderBy: { expiresAt: "asc" },
    take: 100, // pagination:audited — bounded internal ticket hygiene, no user list.
  });
  if (expired.length)
    await prisma.hostTerminalTicket.deleteMany({
      where: { id: { in: expired.map((row) => row.id) } },
    });
  const fresh = authorityTicket({ ownerId: owner.userId, hostId: input.hostId });
  const ticket = randomBytes(32).toString("base64url");
  const result = await prisma.$transaction(async (tx) => {
    const user = await lockTerminalProofUser(tx, owner.userId);
    if (!user) return null;
    await tx.$queryRaw`SELECT id FROM session WHERE id = ${owner.sessionId} FOR SHARE`;
    const factor = policy.requireHostTerminalTotp
      ? await lockTerminalFactor(tx, owner.userId)
      : null;
    const now = await terminalDatabaseTime(tx);
    if (!(await liveSession(tx, user, owner.sessionId, now))) return null;
    if (snapshot) {
      const observed = await observeTerminalFactor(tx, user, factor, now);
      if (
        !observed ||
        factorFingerprint(factor) !== snapshot.fingerprint ||
        user.hostTerminalFactorObservedAt?.getTime() !== snapshot.observedAt.getTime() ||
        terminalProofLocked(user, factor, now) ||
        now.getTime() < snapshot.at ||
        now.getTime() - snapshot.at > HOST_PROOF_FRESH_MS
      )
        return null;
      if (
        !steps.length ||
        steps.some(
          (step) =>
            user.hostTerminalLastTotpStep !== null && BigInt(step) <= user.hostTerminalLastTotpStep,
        )
      ) {
        await failTerminalProof(tx, user, now);
        return null;
      }
    }
    if (
      !(await ownedHost(tx, owner.userId, input.hostId, policy.epoch)) ||
      !(await authorizeTerminalTransport(input.hostId, owner.userId, policy.epoch, tx))
    )
      return null;
    const finalNow = await terminalDatabaseTime(tx);
    if (
      !(await liveSession(tx, user, owner.sessionId, finalNow)) ||
      (snapshot &&
        (finalNow.getTime() < snapshot.at ||
          finalNow.getTime() - snapshot.at > HOST_PROOF_FRESH_MS))
    )
      return null;
    const current = readHostTerminalPolicy(input.hostId, owner.userId);
    if (
      !fresh() ||
      !current?.hostTerminal ||
      current.epoch !== policy.epoch ||
      current.policyRevision !== policy.policyRevision ||
      current.requireHostTerminalTotp !== policy.requireHostTerminalTotp
    )
      return null;
    const expiresAt = new Date(finalNow.getTime() + BROWSER_TERMINAL_TICKET_TTL_MS);
    if (snapshot) {
      await advanceTerminalWatermark(tx, user, steps);
      await tx.user.update({ where: { id: user.id }, data: { hostTerminalFailedAttempts: 0 } });
    }
    await tx.hostTerminalTicket.create({
      data: {
        tokenDigest: terminalTicketDigest(ticket),
        createdAt: finalNow,
        expiresAt,
        userId: owner.userId,
        sessionId: owner.sessionId,
        hostOwnerId: owner.userId,
        sandboxHostId: input.hostId,
        epoch: policy.epoch,
        rows: input.rows,
        cols: input.cols,
        policyRevision: BigInt(policy.policyRevision),
        proofRequired: policy.requireHostTerminalTotp,
        verifiedAt: snapshot ? finalNow : null,
        factorFingerprint: snapshot?.fingerprint ?? null,
        observedAt: snapshot?.observedAt ?? null,
      },
      select: { id: true },
    });
    return { ticket, expiresAt };
  });
  if (!result) throw denied();
  return result;
}
export async function consumeHostTerminalTicket(
  ticket: string,
  now = new Date(),
): Promise<HostTerminalBinding | null> {
  if (!BROWSER_TERMINAL_TICKET_PATTERN.test(ticket)) return null;
  const [row] = await prisma.$queryRaw<
    Array<{
      userId: string;
      sessionId: string;
      sandboxHostId: string;
      hostOwnerId: string;
      epoch: number;
      rows: number;
      cols: number;
      policyRevision: bigint;
      proofRequired: boolean;
      verifiedAt: Date | null;
      factorFingerprint: string | null;
      observedAt: Date | null;
      expiresAt: Date;
    }>
  >`DELETE FROM host_terminal_ticket WHERE "tokenDigest" = ${terminalTicketDigest(ticket)}
      RETURNING "userId", "sessionId", "sandboxHostId", "hostOwnerId", epoch, rows, cols,
        "policyRevision", "proofRequired", "verifiedAt", "factorFingerprint", "observedAt", "expiresAt"`;
  if (!row || row.expiresAt <= now) return null;
  const { sandboxHostId, expiresAt: _expiresAt, ...binding } = row;
  return {
    ...binding,
    kind: "host",
    hostId: sandboxHostId,
    policyRevision: Number(row.policyRevision),
  };
}
export async function checkHostTerminalBinding(
  binding: HostTerminalBinding,
): Promise<{ ok: true } | { ok: false; intent: TerminalRevocation }> {
  const ok = await prisma.$transaction(async (tx) => {
    const user = await lockTerminalProofUser(tx, binding.userId);
    if (!user || binding.userId !== binding.hostOwnerId) return false;
    await tx.$queryRaw`SELECT id FROM session WHERE id = ${binding.sessionId} FOR SHARE`;
    const factor = binding.proofRequired ? await lockTerminalFactor(tx, user.id) : null;
    const now = await terminalDatabaseTime(tx);
    if (!(await liveSession(tx, user, binding.sessionId, now))) return false;
    if (binding.proofRequired) {
      const observed = await observeTerminalFactor(tx, user, factor, now);
      if (
        !observed ||
        !factor?.verified ||
        !binding.verifiedAt ||
        binding.verifiedAt > now ||
        binding.factorFingerprint !== factorFingerprint(factor) ||
        binding.observedAt?.getTime() !== user.hostTerminalFactorObservedAt?.getTime()
      )
        return false;
    }
    if (
      !(await ownedHost(tx, user.id, binding.hostId, binding.epoch)) ||
      !(await authorizeTerminalTransport(binding.hostId, user.id, binding.epoch, tx))
    )
      return false;
    if (!(await liveSession(tx, user, binding.sessionId, await terminalDatabaseTime(tx))))
      return false;
    const policy = readHostTerminalPolicy(binding.hostId, user.id);
    if (policy && !policy.hostTerminal) return "host_terminals_disabled" as const;
    return Boolean(
      policy?.hostTerminal &&
        policy.epoch === binding.epoch &&
        policy.policyRevision === binding.policyRevision &&
        policy.requireHostTerminalTotp === binding.proofRequired,
    );
  });
  return ok === true
    ? { ok: true }
    : { ok: false, intent: ok === "host_terminals_disabled" ? ok : "revoked" };
}

/** Human consent path; online only. No lock crosses relay persistence/ACK IO. */
export async function raiseHostTerminalTotp(
  owner: { userId: string; sessionId: string },
  input: { id: string },
) {
  const { isLiveOwnerSessionAuthorized } = await import("../lib/sensitive-session-two-factor-gate");
  if (
    !(await isLiveOwnerSessionAuthorized({
      user: { id: owner.userId },
      session: { id: owner.sessionId },
    }))
  )
    throw new ORPCError("UNAUTHORIZED");
  await consumeSandboxWriteBudget(owner.userId, "pool");
  const host = await prisma.sandboxHost.findFirst({
    where: {
      id: input.id,
      userId: owner.userId,
      deletionRequestedAt: null,
    },
    select: { id: true },
  });
  if (!host) throw new ORPCError("NOT_FOUND");
  if (!readHostTerminalPolicy(host.id, owner.userId))
    throw new ORPCError("CONFLICT", { data: { code: "HOST_OFFLINE" } });
  return { confirmed: await raiseLiveHostTerminalTotp(host.id, owner.userId) };
}
