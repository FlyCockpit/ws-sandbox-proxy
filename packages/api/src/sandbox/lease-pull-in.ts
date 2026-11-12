/**
 * Lease pull-in (§3.4): a system renewal that can only shorten a READY
 * sandbox's lease to its current lease-path limit. It runs inline after a
 * foreign-host path change (sharing-access), after a warm re-arm that ends up
 * over the limit (reconnect, M2), and from the sweep below (M3), which keys on
 * the deadline the host actually enforces.
 */
import prisma, { type Prisma } from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { Prisma as PrismaValue } from "@wssp/db/client";
import { digestContextSnapshot, ENV_FREE_DIGEST_DOMAIN } from "./digest-context";
import { hashLegacyEnvFreeBody } from "./idempotency";
import { leasePolicyIdempotencyKey } from "./idempotency-key-reserved";
import {
  commitSandboxLeaseRenewal,
  isLeaseDeadlinePassed,
  type LeaseClock,
  leaseNow,
  leaseTransactionNow,
} from "./lease";
import {
  deploymentLeaseMaxMs,
  leasePathJoinSql,
  leasePathPools,
  pathLimitSql,
  pathUnlimitedSql,
  pullInDeadlineSql,
  readLockedPathLimit,
  sameLeasePath,
} from "./lease-policy";
import { lockPoolGraphShared } from "./pool-locks";
import { systemAttribution } from "./principal-kinds";
import { lockCurrentHostEpoch, relayTransaction, requireRelayFence } from "./relay-fence";

/** Never issue a pull-in that ends within this margin: reclaim acts on it. */
const PULL_IN_MIN_REMAINING_MS = 1_000;
const SWEEP_PAGE = 32;

const pullInSelect = {
  id: true,
  userId: true,
  sandboxHostId: true,
  generation: true,
  state: true,
  leaseRevision: true,
  leaseExpiresAt: true,
  leaseExpireAction: true,
  leaseExpiresAtEffective: true,
  leasePendingReady: true,
} satisfies Prisma.SandboxSelect;

/** What the host enforces: the later of the requested and acknowledged deadlines. */
export function enforcedLeaseEnd(s: {
  leaseExpiresAt: Date | null;
  leaseExpiresAtEffective: Date | null;
}): number | null {
  if (!s.leaseExpiresAt) return null;
  return Math.max(
    s.leaseExpiresAt.getTime(),
    s.leaseExpiresAtEffective?.getTime() ?? s.leaseExpiresAt.getTime(),
  );
}

/**
 * The caller holds G (the lease path, shared or exclusive), H and S.
 * Returns whether a system renewal was committed.
 */
export async function pullInLeaseLocked(
  tx: Prisma.TransactionClient,
  sandbox: { id: string; userId: string },
  now: Date,
): Promise<boolean> {
  const s = await tx.sandbox.findFirst({
    where: { id: sandbox.id, userId: sandbox.userId },
    select: pullInSelect,
  });
  // Pull-in never touches a non-READY row: expiry, access grace and teardown own it.
  // A READY-based lease not yet ACKed has no deadline to pull in (M7).
  if (!s || s.state !== "READY" || !s.leaseExpiresAt || s.leasePendingReady) return false;
  // Inline callers must never fail their own transaction on these: the host
  // enforces an already-passed effective deadline itself, and an exhausted
  // revision cannot take another renewal.
  if (isLeaseDeadlinePassed(s.leaseExpiresAtEffective, now) || s.leaseRevision >= 2_147_483_647)
    return false;
  const limit = await readLockedPathLimit(tx, s);
  if (limit.unlimited) return false;
  const bound = now.getTime() + limit.finiteMaxMs;
  const requested = s.leaseExpiresAt.getTime();
  const enforced = enforcedLeaseEnd(s) ?? requested;
  if (enforced <= bound) return false;
  // M3: the latest short request is already on its way to the host. Failed,
  // cancelled and unknown attempts do not block a retry.
  if (requested <= bound) {
    const inFlight = await tx.sandboxOperation.findFirst({
      where: {
        sandboxId: s.id,
        userId: s.userId,
        kind: "RENEW_SANDBOX_LEASE",
        leaseRevisionAccepted: s.leaseRevision,
        state: { in: ["QUEUED", "DISPATCHED", "ACCEPTED", "RUNNING"] },
      },
      select: { id: true },
    });
    if (inFlight) return false;
  }
  // The system renewal is never an extension of anything (security review #1):
  // - never later than the lease the host has acknowledged (`effective`): an
  //   unacknowledged user extension must not ride on the system path, which
  //   carries no key; superseding it at the acknowledged deadline cancels it;
  // - never later than the requested deadline (a shorter pending request);
  // - never later than now + the limit.
  // Without an acknowledged lease the host's deadline is unknown: wait for
  // the acknowledgement (the sweep retries).
  if (!s.leaseExpiresAtEffective) return false;
  const effective = s.leaseExpiresAtEffective.getTime();
  const target = Math.min(bound, requested, effective);
  // Bounded only by the requested deadline: the server's own lease reclaim
  // already acts on it.
  if (target === requested && target <= now.getTime() + PULL_IN_MIN_REMAINING_MS) return false;
  if (target <= now.getTime()) return false;
  // Something must actually shrink: the request or what the host enforces.
  if (!(target < enforced)) return false;
  await commitSandboxLeaseRenewal(tx, {
    ownerId: s.userId,
    sandbox: s,
    leaseExpiresAt: new Date(target),
    onExpire: s.leaseExpireAction,
    idempotencyKey: leasePolicyIdempotencyKey(s.id, s.generation, s.leaseRevision),
    bodyHash: hashLegacyEnvFreeBody({
      sandboxId: s.id,
      action: "lease-policy",
      generation: s.generation,
      leaseRevision: s.leaseRevision,
      deadlineUnixMs: target,
    }),
    now,
    timeoutMs: target - now.getTime(),
    attribution: systemAttribution(),
    digestContext: digestContextSnapshot(
      { domain: ENV_FREE_DIGEST_DOMAIN },
      { generation: s.generation },
    ),
  });
  return true;
}

/** One row: User → G (lease path, shared) → H → S, then the locked pull-in. */
export async function pullInSandboxLease(
  sandboxId: string,
  clock: LeaseClock = leaseNow,
): Promise<boolean> {
  return relayTransaction(async (tx) => {
    const discovered = await tx.sandbox.findUnique({
      where: { id: sandboxId },
      select: {
        userId: true,
        hostOwnerId: true,
        sandboxHostId: true,
        originPoolId: true,
        usagePoolId: true,
        usageMemberId: true,
      },
    });
    if (!discovered?.sandboxHostId) return false;
    await lockOwnerForAdmission(tx, discovered.userId);
    await lockPoolGraphShared(tx, leasePathPools(discovered));
    const host = await lockCurrentHostEpoch(tx, discovered.sandboxHostId);
    requireRelayFence(host.userId === discovered.hostOwnerId);
    await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${sandboxId} AND "userId" = ${discovered.userId} FOR UPDATE`;
    const locked = await tx.sandbox.findUnique({
      where: { id: sandboxId },
      select: {
        userId: true,
        hostOwnerId: true,
        sandboxHostId: true,
        originPoolId: true,
        usagePoolId: true,
        usageMemberId: true,
      },
    });
    // The shared G was taken for the discovered path only.
    requireRelayFence(
      locked != null &&
        locked.sandboxHostId === discovered.sandboxHostId &&
        sameLeasePath(discovered, locked),
    );
    const now = await leaseTransactionNow(tx, clock);
    return pullInLeaseLocked(tx, { id: sandboxId, userId: discovered.userId }, now);
  }, false);
}

/**
 * Keyset sweep (M3): READY rows whose enforced deadline lies beyond now plus
 * their path limit, filtered before LIMIT. Pool hints match the lease path
 * pool (own host: origin; foreign: usage). Time is a JS Date parameter, never
 * SQL now(), so the session time zone cannot shift it.
 */
export async function scanLeasePolicy(
  clock: LeaseClock = leaseNow,
  shouldStop: () => boolean = () => false,
  pools?: ReadonlySet<string>,
): Promise<number> {
  let cursor = "";
  let pulled = 0;
  const hinted = [...(pools ?? [])];
  while (!shouldStop()) {
    const now = clock();
    const deployment = deploymentLeaseMaxMs();
    const rows = await prisma.$queryRaw<{ id: string }[]>`
      SELECT s.id FROM sandbox_instance s
      LEFT JOIN sandbox_host h ON h.id = s."sandboxHostId" AND h."userId" = s."hostOwnerId"
      ${leasePathJoinSql}
      WHERE s.id > ${cursor} AND s.state = 'READY' AND s."leaseExpiresAt" IS NOT NULL
        AND (${pools === undefined} OR pool.id = ANY(${hinted}::text[]))
        AND NOT ${pathUnlimitedSql(deployment, PrismaValue.sql`s."userId"`)}
        AND ${pullInDeadlineSql} - (${pathLimitSql(deployment)} * interval '1 millisecond') > ${now}
      ORDER BY s.id LIMIT ${SWEEP_PAGE}`;
    for (const row of rows) {
      if (shouldStop()) return pulled;
      try {
        if (await pullInSandboxLease(row.id, clock)) pulled++;
      } catch {
        // A losing CAS (a concurrent user renewal) or a fenced row retries
        // on the next pass; never log row data.
        console.error("[lease-policy] pull-in deferred; periodic retry pending");
      }
      cursor = row.id;
    }
    if (rows.length < SWEEP_PAGE) return pulled;
  }
  return pulled;
}
