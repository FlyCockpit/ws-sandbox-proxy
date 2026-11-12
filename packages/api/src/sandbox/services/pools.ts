import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import type { z } from "zod";
import { cursorPage, pageTake, withCursor } from "../../lib/pagination";
import { isPrismaUniqueViolation } from "../../lib/prisma-errors";
import { serviceProcedure, serviceResourceFilter } from "../../lib/sdk-key-access";
import { consumeSandboxWriteBudget } from "../budgets";
import { publicCapacityBlocker } from "../capacity-queue";
import type { Principal } from "../contracts";
import { lockOwnerPlacement } from "../direct-placement";
import { hostNotFound, poolNotFound } from "../errors";
import { lockHostForSandboxOperation } from "../host-admission";
import {
  deploymentLeaseMaxMs,
  leasePathJoinSql,
  pathLimitSql,
  pullInDeadlineSql,
} from "../lease-policy";
import type {
  addPoolMemberInput,
  createPoolInput,
  listPoolMembersInput,
  listPoolQueueInput,
  listPoolsInput,
  poolIdInput,
  poolMemberInput,
  previewLeaseLoweringInput,
  updatePoolInput,
  updatePoolMemberInput,
} from "../pool-input";
import { lockPoolGraph, MAX_ACTIVE_POOL_MEMBERSHIPS } from "../pool-locks";
import { poolSelect, visiblePool } from "../pool-visibility";
import { lockCurrentHostEpoch, RelayFenceRejected, requireRelayFence } from "../relay-fence";
import { notifySharingAccessChanged } from "../sharing-access";
import { lockSharingPrincipals, withSharingAuthorityChange } from "../sharing-authority";
import { consumeLeasePreview } from "../sharing-budgets";

export const listPools = serviceProcedure(
  { action: "pools.list" },
  async (owner: Principal, input: z.infer<typeof listPoolsInput>) => {
    const rows = await prisma.sandboxPool.findMany({
      where: withCursor(
        { ...serviceResourceFilter(owner, "pool"), deletedAt: null },
        "createdAt",
        input.cursor,
        "desc",
      ),
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: pageTake(input.limit),
      select: poolSelect,
    });
    return cursorPage(rows, input.limit, "createdAt");
  },
);

export const getPool = serviceProcedure(
  { action: "pools.get", target: (input: z.infer<typeof poolIdInput>) => ({ poolId: input.id }) },
  async (owner: Principal, input) => {
    const pool = await visiblePool(prisma, owner, input.id);
    // Counts use exactly the member-page host/pool visibility, before paging.
    const memberCount = await prisma.sandboxPoolMember.count({
      where: { ...serviceResourceFilter(owner, "member"), poolId: pool.id, removedAt: null },
    });
    return { ...pool, memberCount };
  },
);

const memberSelect = {
  id: true,
  userId: true,
  poolId: true,
  sandboxHostId: true,
  enabled: true,
  removedAt: true,
  hostOwnerId: true,
  memoryCapPercent: true,
  vcpuCapPercent: true,
  maxLeaseMs: true,
  createdAt: true,
  updatedAt: true,
  Host: {
    select: {
      id: true,
      slug: true,
      label: true,
      draining: true,
      status: true,
      User: { select: { name: true } },
    },
  },
} satisfies Prisma.SandboxPoolMemberSelect;

export const listPoolMembers = serviceProcedure(
  {
    action: "pools.members",
    target: (input: z.infer<typeof listPoolMembersInput>) => ({ poolId: input.poolId }),
  },
  async (owner: Principal, input) => {
    await visiblePool(prisma, owner, input.poolId);
    const rows = await prisma.sandboxPoolMember.findMany({
      where: withCursor(
        { ...serviceResourceFilter(owner, "member"), poolId: input.poolId, removedAt: null },
        "createdAt",
        input.cursor,
        "desc",
      ),
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: pageTake(input.limit),
      select: memberSelect,
    });
    return cursorPage(
      rows.map((row) => {
        if (!row.Host) throw poolNotFound();
        return { ...row, Host: row.Host };
      }),
      input.limit,
      "createdAt",
    );
  },
);

async function poolWrite<T>(
  owner: Principal,
  work: (tx: Prisma.TransactionClient) => Promise<T>,
  poolId?: string,
) {
  await consumeSandboxWriteBudget(owner.ownerId, "pool");
  try {
    const result = await withSharingAuthorityChange([owner.ownerId], () =>
      prisma.$transaction(async (tx) => {
        await lockOwnerForAdmission(tx, owner.ownerId);
        await lockOwnerPlacement(tx, owner.ownerId);
        return work(tx);
      }),
    );
    if (poolId) notifySharingAccessChanged(poolId);
    return result;
  } catch (error) {
    if (isPrismaUniqueViolation(error))
      throw new ORPCError("CONFLICT", { message: "Pool slug is already reserved." });
    throw error;
  }
}

export const createPool = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: z.infer<typeof createPoolInput>) =>
    poolWrite(owner, (tx) =>
      tx.sandboxPool.create({ data: { ...input, userId: owner.ownerId }, select: poolSelect }),
    ),
);
export const updatePool = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: z.infer<typeof updatePoolInput>) =>
    poolWrite(
      owner,
      async (tx) => {
        await lockPoolGraph(tx, [input.id]);
        await visiblePool(tx, owner, input.id);
        return tx.sandboxPool.update({
          where: { id: input.id, userId: owner.ownerId },
          data: {
            slug: input.slug,
            label: input.label,
            ownHostsOnly: input.ownHostsOnly,
            preferOwnHosts: input.preferOwnHosts,
            capacityWaitMaxMs: input.capacityWaitMaxMs,
            capacityQueuePerKeyMax: input.capacityQueuePerKeyMax,
            capacityQueuePerOwnerMax: input.capacityQueuePerOwnerMax,
            disconnectGraceSeconds: input.disconnectGraceSeconds,
            // Omitted means unchanged. G (above) serializes this with every
            // lease-policy reader; poolWrite wakes the pull-in sweep after commit.
            maxLeaseMs: input.maxLeaseMs,
            unlimitedLeaseForShares: input.unlimitedLeaseForShares,
            memberImageCacheMaxGiB: input.memberImageCacheMaxGiB,
          },
          select: poolSelect,
        });
      },
      input.id,
    ),
);
export const deletePool = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: z.infer<typeof poolIdInput>) =>
    poolWrite(
      owner,
      async (tx) => {
        await lockPoolGraph(tx, [input.id]);
        await visiblePool(tx, owner, input.id);
        // The DB trigger clears future grants/invites; accepted work retains immutable origin.
        return tx.sandboxPool.update({
          where: { id: input.id, userId: owner.ownerId },
          data: { deletedAt: new Date() },
          select: poolSelect,
        });
      },
      input.id,
    ),
);

async function memberWrite<T>(
  owner: Principal,
  input: z.infer<typeof poolMemberInput>,
  work: (tx: Prisma.TransactionClient) => Promise<T>,
  removingAuthority = false,
) {
  await consumeSandboxWriteBudget(owner.ownerId, "pool");
  // Owner may disable/remove a contributed host, but never alter its caps.
  const discovered = await prisma.sandboxHost.findUnique({
    where: { id: input.sandboxHostId },
    select: { userId: true },
  });
  if (!discovered) throw hostNotFound();
  const result = await withSharingAuthorityChange([owner.ownerId], () =>
    prisma.$transaction(async (tx) => {
      await lockSharingPrincipals(
        tx,
        [owner.ownerId, discovered.userId],
        removingAuthority ? [owner.ownerId] : [owner.ownerId, discovered.userId],
      );
      await lockOwnerPlacement(tx, owner.ownerId);
      await lockPoolGraph(tx, [input.poolId]);
      await visiblePool(tx, owner, input.poolId);
      if (
        discovered.userId !== owner.ownerId &&
        !(await tx.sandboxPoolMember.findFirst({
          where: {
            poolId: input.poolId,
            sandboxHostId: input.sandboxHostId,
            userId: owner.ownerId,
            hostOwnerId: discovered.userId,
            removedAt: null,
          },
          select: { id: true },
        }))
      )
        throw hostNotFound();
      try {
        if (removingAuthority) {
          const host = await lockCurrentHostEpoch(tx, input.sandboxHostId);
          requireRelayFence(host.userId === discovered.userId);
        } else await lockHostForSandboxOperation(tx, input.sandboxHostId, discovered.userId);
      } catch (error) {
        if (error instanceof RelayFenceRejected) {
          if (
            !(await tx.sandboxHost.findFirst({
              where: {
                id: input.sandboxHostId,
                userId: discovered.userId,
                ...(removingAuthority ? {} : { deletionRequestedAt: null }),
              },
              select: { id: true },
            }))
          )
            throw hostNotFound();
        }
        throw error;
      }
      if (removingAuthority) return work(tx);
      const active = await tx.sandboxHost.findFirst({
        where: { id: input.sandboxHostId, userId: discovered.userId, deletionRequestedAt: null },
        select: { id: true },
      });
      if (!active) throw hostNotFound();
      return work(tx);
    }),
  );
  notifySharingAccessChanged(input.poolId);
  return result;
}

export const addPoolMember = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: z.infer<typeof addPoolMemberInput>) => {
    if (
      !(await prisma.sandboxHost.findFirst({
        where: { id: input.sandboxHostId, userId: owner.ownerId, deletionRequestedAt: null },
        select: { id: true },
      }))
    )
      throw hostNotFound();
    return memberWrite(owner, input, async (tx) => {
      if (
        !(await tx.sandboxHost.findFirst({
          where: { id: input.sandboxHostId, userId: owner.ownerId },
          select: { id: true },
        }))
      )
        throw hostNotFound();
      const existing = await tx.sandboxPoolMember.findUnique({
        where: {
          poolId_sandboxHostId: { poolId: input.poolId, sandboxHostId: input.sandboxHostId },
        },
        select: { removedAt: true },
      });
      // N4: a re-activated membership never inherits a stale lease limit.
      const reactivating = existing?.removedAt != null;
      if (!existing || existing.removedAt !== null) {
        const poolCount = await tx.sandboxPoolMember.count({
          where: { poolId: input.poolId, removedAt: null },
        });
        const hostCount = await tx.sandboxPoolMember.count({
          where: { sandboxHostId: input.sandboxHostId, removedAt: null },
        });
        if (poolCount >= MAX_ACTIVE_POOL_MEMBERSHIPS || hostCount >= MAX_ACTIVE_POOL_MEMBERSHIPS)
          throw new ORPCError("CONFLICT", {
            message: "Membership limit reached. Remove pool memberships before retrying.",
          });
      }
      return tx.sandboxPoolMember.upsert({
        where: {
          poolId_sandboxHostId: { poolId: input.poolId, sandboxHostId: input.sandboxHostId },
        },
        create: { ...input, userId: owner.ownerId, hostOwnerId: owner.ownerId },
        update: {
          enabled: input.enabled,
          removedAt: null,
          maxLeaseMs: reactivating ? (input.maxLeaseMs ?? null) : input.maxLeaseMs,
        },
        select: memberSelect,
      });
    });
  },
);
export const updatePoolMember = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: z.infer<typeof updatePoolMemberInput>) =>
    memberWrite(
      owner,
      input,
      async (tx) => {
        const member = await tx.sandboxPoolMember.findFirst({
          where: {
            poolId: input.poolId,
            sandboxHostId: input.sandboxHostId,
            userId: owner.ownerId,
            removedAt: null,
          },
          select: { id: true, hostOwnerId: true },
        });
        if (!member) throw poolNotFound();
        // N2: a membership's lease limit belongs to the host owner. The pool
        // owner may disable or remove a contributed host, never set its limit
        // (the contributor uses contributePoolHost, which gates raises).
        if (input.maxLeaseMs !== undefined && member.hostOwnerId !== owner.ownerId)
          throw new ORPCError("FORBIDDEN", {
            message: "Only the host owner can set this membership's lifetime limit.",
          });
        return tx.sandboxPoolMember.update({
          where: { id: member.id },
          data: { enabled: input.enabled, maxLeaseMs: input.maxLeaseMs },
          select: memberSelect,
        });
      },
      input.enabled === false,
    ),
);
export const removePoolMember = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: z.infer<typeof poolMemberInput>) =>
    memberWrite(
      owner,
      input,
      async (tx) => {
        const result = await tx.sandboxPoolMember.updateMany({
          where: { ...input, userId: owner.ownerId, removedAt: null },
          data: { removedAt: new Date(), enabled: false },
        });
        if (result.count !== 1) throw poolNotFound();
        return { ok: true as const };
      },
      true,
    ),
);

/** At most this many affected sandboxes are counted for a lowering preview. */
const LEASE_PREVIEW_CAP = 250;

/**
 * How many READY sandboxes a lowering would shorten: their lease path (§3.1)
 * is in scope and the deadline the host enforces lies beyond now plus the new
 * limit. Pool scope: the pool owner only. Member scope: the host owner only
 * (own-host member or a contribution). Read-only and bounded.
 */
export const previewLeaseLowering = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: z.infer<typeof previewLeaseLoweringInput>) => {
    // Owner-scoped procedure budget before any query (review #3).
    await consumeLeasePreview(owner.ownerId);
    const pool = await prisma.sandboxPool.findFirst({
      where: { id: input.poolId, deletedAt: null },
      select: { id: true, userId: true },
    });
    if (!pool) throw poolNotFound();
    if (input.scope === "pool" && pool.userId !== owner.ownerId) throw poolNotFound();
    if (input.scope === "member") {
      const member = await prisma.sandboxPoolMember.findFirst({
        where: {
          poolId: pool.id,
          sandboxHostId: input.sandboxHostId,
          hostOwnerId: owner.ownerId,
          removedAt: null,
        },
        select: { id: true },
      });
      if (!member) throw poolNotFound();
    }
    const now = new Date();
    const deployment = deploymentLeaseMaxMs();
    const rows = await prisma.$queryRaw<{ id: string }[]>`
      SELECT s.id FROM sandbox_instance s
      LEFT JOIN sandbox_host h ON h.id = s."sandboxHostId" AND h."userId" = s."hostOwnerId"
      ${leasePathJoinSql}
      WHERE s.state = 'READY' AND s."leaseExpiresAt" IS NOT NULL AND pool.id = ${pool.id}
        AND (${input.sandboxHostId ?? null}::text IS NULL OR m."sandboxHostId" = ${input.sandboxHostId ?? null})
        AND ${pullInDeadlineSql}
          - (LEAST(${pathLimitSql(deployment)}, ${input.maxLeaseMs}::int) * interval '1 millisecond') > ${now}
      ORDER BY s.id LIMIT ${LEASE_PREVIEW_CAP + 1}`;
    return {
      affected: Math.min(rows.length, LEASE_PREVIEW_CAP),
      more: rows.length > LEASE_PREVIEW_CAP,
      earliestEnd: rows.length > 0 ? new Date(now.getTime() + input.maxLeaseMs) : null,
    };
  },
);

const queueSelect = {
  id: true,
  seq: true,
  enqueuedAt: true,
  deadlineAt: true,
  lastBlocker: true,
  cpuCount: true,
  memoryMiB: true,
  diskGiB: true,
  User: { select: { name: true } },
} satisfies Prisma.SandboxCapacityWaitSelect;

/**
 * The pool owner's queue list (session only, owned pools only): requester
 * display name, size, waited since, deadline and blocker. Never the request
 * intent, env or key. Owners see but cannot cancel grantees' entries;
 * revoking the share fails them.
 */
export const listPoolQueue = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: z.infer<typeof listPoolQueueInput>) => {
    const pool = await visiblePool(prisma, owner, input.poolId);
    const rows = await prisma.sandboxCapacityWait.findMany({
      where: withCursor(
        { poolId: pool.id, poolOwnerId: owner.ownerId, state: "WAITING" as const },
        "enqueuedAt",
        input.cursor,
        "asc",
      ),
      orderBy: [{ enqueuedAt: "asc" }, { id: "asc" }],
      take: pageTake(input.limit),
      select: queueSelect,
    });
    const positions = rows.length
      ? await prisma.$queryRaw<{ id: string; position: number }[]>`
          SELECT w.id, (SELECT count(*) FROM sandbox_capacity_wait o
            WHERE o."poolId" = w."poolId" AND o.state = 'WAITING' AND o.seq <= w.seq)::int AS position
          FROM sandbox_capacity_wait w WHERE w.id = ANY(${rows.map((row) => row.id)}::text[])`
      : [];
    const page = cursorPage(rows, input.limit, "enqueuedAt");
    return {
      items: page.items.map((row) => ({
        id: row.id,
        requester: row.User.name,
        cpuCount: row.cpuCount,
        memoryMiB: row.memoryMiB,
        diskGiB: row.diskGiB,
        enqueuedAt: row.enqueuedAt,
        deadlineAt: row.deadlineAt,
        blocker: publicCapacityBlocker(row.lastBlocker),
        position: positions.find((entry) => entry.id === row.id)?.position ?? null,
      })),
      nextCursor: page.nextCursor,
    };
  },
);
