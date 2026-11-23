import { createHash, randomBytes } from "node:crypto";
import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import { authorityTicket } from "@wssp/db/authority";
import { env } from "@wssp/env/server";
import type { z } from "zod";
import { cursorPage, pageTake, withCursor } from "../../lib/pagination";
import { serviceProcedure } from "../../lib/sdk-key-access";
import type { Principal } from "../contracts";
import { poolNotFound } from "../errors";
import { lockHostForSandboxOperation } from "../host-admission";
import { poolLeaseViews } from "../lease-policy";
import type { listPoolMembersInput, listPoolsInput, poolIdInput } from "../pool-input";
import { lockPoolGraph, MAX_ACTIVE_POOL_MEMBERSHIPS } from "../pool-locks";
import { poolSelect } from "../pool-visibility";
import { viewerOf } from "../principal-kinds";
import { lockCurrentHostEpoch, requireRelayFence } from "../relay-fence";
import { notifySharingAccessChanged } from "../sharing-access";
import {
  contributedMemberSelect,
  lockSharingPrincipals,
  requirePoolContribution,
  requireSharingPolicies,
  shareSelect,
  withSharingAuthorityChange,
} from "../sharing-authority";
import {
  consumeInviteAccept,
  consumeInviteIssue,
  consumeInvitePreview,
  consumeSharingWrite,
} from "../sharing-budgets";
import {
  acceptPoolInviteInput,
  contributePoolHostInput,
  grantPoolShareInput,
  inviteTokenInput,
  leavePoolInput,
  poolInviteInput,
  previewPoolInviteInput,
  revokePoolShareInput,
  updatePoolShareInput,
} from "../sharing-input";
import { shareUsageByCreator, shareUsageByPool } from "../sharing-quota";

// Never select tokenDigest or pendingKey, including for the pool owner.
export const inviteSelect = {
  id: true,
  poolId: true,
  email: true,
  canUse: true,
  canContribute: true,
  maxMemoryMiB: true,
  maxVcpu: true,
  maxDiskGiB: true,
  signupAllowed: true,
  createdAt: true,
  expiresAt: true,
  sentAt: true,
  acceptedAt: true,
  revokedAt: true,
  expiredAt: true,
} satisfies Prisma.ShareInviteSelect;

async function requirePoolOwner(ownerId: string, poolId: string) {
  if (
    !(await prisma.sandboxPool.findFirst({
      where: { id: poolId, userId: ownerId, deletedAt: null },
      select: { id: true },
    }))
  )
    throw poolNotFound();
}
export const listPoolShares = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: z.infer<typeof listPoolMembersInput>) => {
    await requirePoolOwner(owner.ownerId, input.poolId);
    const rows = await prisma.share.findMany({
      where: withCursor(
        { poolId: input.poolId, ownerUserId: owner.ownerId },
        "createdAt",
        input.cursor,
        "desc",
      ),
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: pageTake(input.limit),
      select: {
        ...shareSelect,
        Grantee: { select: { name: true, email: true } },
      } satisfies Prisma.ShareSelect,
    });
    const page = cursorPage(rows, input.limit, "createdAt");
    const usageByGrantee = await shareUsageByCreator(
      prisma,
      input.poolId,
      page.items.map((share) => share.granteeUserId),
    );
    return {
      ...page,
      items: page.items.map((share) => {
        const usage = usageByGrantee.get(share.granteeUserId) ?? {
          memoryMiB: 0n,
          vcpu: 0n,
          diskGiB: 0n,
        };
        return {
          ...share,
          usage: {
            memoryMiB: String(usage.memoryMiB),
            vcpu: String(usage.vcpu),
            diskGiB: String(usage.diskGiB),
          },
        };
      }),
    };
  },
);
export const listPoolInvites = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: z.infer<typeof listPoolMembersInput>) => {
    await requirePoolOwner(owner.ownerId, input.poolId);
    const rows = await prisma.shareInvite.findMany({
      where: withCursor(
        { poolId: input.poolId, ownerUserId: owner.ownerId },
        "createdAt",
        input.cursor,
        "desc",
      ),
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: pageTake(input.limit),
      select: inviteSelect,
    });
    return cursorPage(rows, input.limit, "createdAt");
  },
);

// Qualified by lifecycle-conformance.pg.test.ts: real A/B admission, wire IO,
// STOP/grace/restore/DESTROY and the owner/admin/impersonation oracle matrix.
// These read filters deliberately do not change visiblePool or owner writes.
const activeUser = (): Prisma.UserWhereInput => ({
  deletionRequestedAt: null,
  OR: [{ banned: { not: true } }, { banned: null }, { banExpires: { lte: new Date() } }],
});
function readablePools(
  owner: Principal,
  includeContribute: boolean | "contribute" = false,
): Prisma.SandboxPoolWhereInput {
  const { allowedPoolIds } = viewerOf(owner);
  const selected = allowedPoolIds !== "allUsable" ? { id: { in: [...allowedPoolIds] } } : {};
  return {
    ...selected,
    deletedAt: null,
    User: activeUser(),
    OR: [
      { userId: owner.ownerId },
      {
        ...(includeContribute === "contribute" ? { ownHostsOnly: false } : {}),
        Shares: {
          some: {
            granteeUserId: owner.ownerId,
            Grantee: activeUser(),
            ...(includeContribute === "contribute"
              ? { canContribute: true }
              : includeContribute
                ? {}
                : { canUse: true }),
          },
        },
      },
    ],
  };
}
const sharedReadSelect = {
  ...poolSelect,
  userId: true,
  User: { select: { id: true, name: true } },
} satisfies Prisma.SandboxPoolSelect;
const sharedPermissionSelect = {
  canUse: true,
  canContribute: true,
  maxMemoryMiB: true,
  maxVcpu: true,
  maxDiskGiB: true,
} satisfies Prisma.ShareSelect;

/**
 * The one authority-fenced pool read. A single read is a batch of one, so every
 * caller runs the same fence: caller ticket -> discover -> a ticket per distinct
 * discovered owner -> re-read -> (caller's dependent reads) -> check(). Any id
 * that is not readable at every step fails the WHOLE call with poolNotFound.
 * Constant query count: discover, re-read and check are one findMany each.
 */
async function readPools(
  owner: Principal,
  requested: readonly string[],
  includeContribute: boolean | "contribute" = false,
) {
  const ids = [...new Set(requested)];
  if (ids.length === 0) return { pools: [], check: async () => {} };
  const caller = authorityTicket({ ownerId: owner.ownerId });
  const where = { AND: [readablePools(owner, includeContribute), { id: { in: ids } }] };
  const discovered = await prisma.sandboxPool.findMany({
    where,
    select: sharedReadSelect,
    take: ids.length,
  });
  if (discovered.length !== ids.length) throw poolNotFound();
  const sourceOf = new Map(discovered.map((pool) => [pool.id, pool.userId]));
  const sources = [...new Set(sourceOf.values())].map((ownerId) => authorityTicket({ ownerId }));
  const current = () => caller() && sources.every((source) => source());
  // Re-read after sampling the sources: neither a missed hint/raw SQL revoke nor
  // a source-policy change before sampling may preserve an earlier projection.
  const reread = await prisma.sandboxPool.findMany({
    where,
    select: sharedReadSelect,
    take: ids.length,
  });
  const byId = new Map(reread.map((pool) => [pool.id, pool]));
  const pools = ids.map((id) => {
    const pool = byId.get(id);
    if (!pool || pool.userId !== sourceOf.get(id)) throw poolNotFound();
    return pool;
  });
  if (reread.length !== ids.length || !current()) throw poolNotFound();
  return {
    pools,
    check: async () => {
      if (
        !current() ||
        (await prisma.sandboxPool.findMany({ where, select: { id: true }, take: ids.length }))
          .length !== ids.length
      )
        throw poolNotFound();
      if (!current()) throw poolNotFound();
    },
  };
}
async function readPool(
  owner: Principal,
  id: string,
  includeContribute: boolean | "contribute" = false,
) {
  const { pools, check } = await readPools(owner, [id], includeContribute);
  const [pool] = pools;
  if (!pool) throw poolNotFound();
  return { pool, check };
}
/** Contributor discovery grants no host metadata; callers still query only owned hosts. */
export async function readContributionPool(owner: Principal, id: string) {
  return readPool(owner, id, "contribute");
}

const sharedPermissionByPoolSelect = {
  ...sharedPermissionSelect,
  poolId: true,
} satisfies Prisma.ShareSelect;
/** Views in `ids` order; one fence and a constant number of queries per call.
 * Exported for the batch-equals-single pg proof only; not a service. */
export async function poolReadViews(
  owner: Principal,
  ids: readonly string[],
  includeContribute = false,
) {
  const { pools, check } = await readPools(owner, ids, includeContribute);
  if (pools.length === 0) return [];
  const leases = await poolLeaseViews(prisma, viewerOf(owner), pools);
  if (pools.some((pool) => !leases.has(pool.id))) throw poolNotFound();
  const sharedIds = pools.filter((pool) => pool.userId !== owner.ownerId).map((pool) => pool.id);
  const shares = new Map<
    string,
    Prisma.ShareGetPayload<{ select: typeof sharedPermissionSelect }>
  >();
  if (sharedIds.length > 0)
    for (const { poolId, ...share } of await prisma.share.findMany({
      where: { poolId: { in: sharedIds }, granteeUserId: owner.ownerId },
      select: sharedPermissionByPoolSelect,
      take: sharedIds.length,
    }))
      shares.set(poolId, share);
  if (sharedIds.some((id) => !shares.has(id))) throw poolNotFound();
  const usages = await shareUsageByPool(prisma, sharedIds, owner.ownerId);
  await check();
  return pools.map(({ userId, User, ...view }) => {
    const lease = leases.get(view.id);
    if (!lease) throw poolNotFound();
    const share = userId !== owner.ownerId ? shares.get(view.id) : undefined;
    const usage = share ? usages.get(view.id) : undefined;
    return {
      ...view,
      lease,
      ...(share && usage
        ? {
            owner: User,
            share: {
              ...share,
              usage: {
                memoryMiB: String(usage.memoryMiB),
                vcpu: String(usage.vcpu),
                diskGiB: String(usage.diskGiB),
              },
            },
          }
        : {}),
    };
  });
}
async function poolReadView(owner: Principal, id: string) {
  const [view] = await poolReadViews(owner, [id]);
  if (!view) throw poolNotFound();
  return view;
}

/** Native usable discovery: owned OR current use grant, intersected with SDK selection before paging. */
export const listUsablePools = serviceProcedure(
  { action: "pools.list" },
  async (owner: Principal, input: z.infer<typeof listPoolsInput>) => {
    const rows = await prisma.sandboxPool.findMany({
      where: withCursor(readablePools(owner), "createdAt", input.cursor, "desc"),
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: pageTake(input.limit),
      select: poolSelect,
    });
    const page = cursorPage(rows, input.limit, "createdAt");
    return {
      items: await poolReadViews(
        owner,
        page.items.map((row) => row.id),
      ),
      nextCursor: page.nextCursor,
    };
  },
);
/** Browser shared tab includes independent contribute-only consent. No roster/host relation. */
export const listSharedPools = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: z.infer<typeof listPoolsInput>) => {
    const rows = await prisma.sandboxPool.findMany({
      where: withCursor(
        { AND: [readablePools(owner, true), { userId: { not: owner.ownerId } }] },
        "createdAt",
        input.cursor,
        "desc",
      ),
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: pageTake(input.limit),
      select: poolSelect,
    });
    const page = cursorPage(rows, input.limit, "createdAt");
    return {
      items: await poolReadViews(
        owner,
        page.items.map((row) => row.id),
        true,
      ),
      nextCursor: page.nextCursor,
    };
  },
);

function readableMembers(
  owner: Principal,
  poolId: string,
  poolOwnerId: string,
): Prisma.SandboxPoolMemberWhereInput {
  const { allowedHostIds } = viewerOf(owner);
  const hosts: Prisma.SandboxPoolMemberWhereInput =
    allowedHostIds !== "allOwned"
      ? {
          OR: [
            { hostOwnerId: { not: owner.ownerId } },
            { sandboxHostId: { in: [...allowedHostIds] } },
          ],
        }
      : {};
  return {
    AND: [
      hosts,
      {
        poolId,
        removedAt: null,
        Host: { deletionRequestedAt: null, User: activeUser() },
        OR: [{ hostOwnerId: poolOwnerId }, { contributeWitness: true, ownHostsOnlyWitness: false }],
      },
    ],
  };
}
export const getUsablePool = serviceProcedure(
  { action: "pools.get", target: (input: z.infer<typeof poolIdInput>) => ({ poolId: input.id }) },
  async (owner: Principal, input) => {
    const { pool, check } = await readPool(owner, input.id);
    const memberCount = await prisma.sandboxPoolMember.count({
      where: readableMembers(owner, pool.id, pool.userId),
    });
    const view = await poolReadView(owner, input.id);
    await check();
    return { ...view, memberCount };
  },
);
const ownerMemberReadSelect = {
  id: true,
  poolId: true,
  hostOwnerId: true,
  sandboxHostId: true,
  enabled: true,
  createdAt: true,
  updatedAt: true,
  Host: { select: { id: true, slug: true, label: true, draining: true, status: true } },
} satisfies Prisma.SandboxPoolMemberSelect;
type OwnerMemberRead = Prisma.SandboxPoolMemberGetPayload<{ select: typeof ownerMemberReadSelect }>;
type PoolMemberRead =
  | (OwnerMemberRead & { Host: NonNullable<OwnerMemberRead["Host"]> })
  | { id: string; poolId: string };
async function checkMemberRead(
  owner: Principal,
  pool: { id: string; userId: string },
  ids: string[],
) {
  const where = { AND: [readableMembers(owner, pool.id, pool.userId), { id: { in: ids } }] };
  const sources = await prisma.sandboxPoolMember.findMany({
    where,
    select: { hostOwnerId: true },
    take: ids.length,
  });
  if (sources.length !== ids.length) throw poolNotFound();
  const tickets = [
    ...new Set(
      sources.map((row) => {
        if (!row.hostOwnerId) throw poolNotFound();
        return row.hostOwnerId;
      }),
    ),
  ].map((ownerId) => authorityTicket({ ownerId }));
  if (
    (await prisma.sandboxPoolMember.count({ where })) !== ids.length ||
    tickets.some((current) => !current())
  )
    throw poolNotFound();
  return () => {
    if (tickets.some((current) => !current())) throw poolNotFound();
  };
}
export const listUsablePoolMembers = serviceProcedure(
  {
    action: "pools.members",
    target: (input: z.infer<typeof listPoolMembersInput>) => ({ poolId: input.poolId }),
  },
  async (
    owner: Principal,
    input,
  ): Promise<{ items: PoolMemberRead[]; nextCursor: string | null }> => {
    const { pool, check } = await readPool(owner, input.poolId);
    const where = withCursor(
      readableMembers(owner, pool.id, pool.userId),
      "createdAt",
      input.cursor,
      "desc",
    );
    if (pool.userId === owner.ownerId) {
      const rows = await prisma.sandboxPoolMember.findMany({
        where,
        orderBy: [{ createdAt: "desc" }, { id: "desc" }],
        take: pageTake(input.limit),
        select: ownerMemberReadSelect,
      });
      const membersCurrent = await checkMemberRead(
        owner,
        pool,
        rows.map((row) => row.id),
      );
      await check();
      membersCurrent();
      return cursorPage(
        rows.map((row) => {
          if (!row.Host) throw poolNotFound();
          return { ...row, Host: row.Host };
        }),
        input.limit,
        "createdAt",
      );
    }
    // Never query Host metadata for a use grantee. Exact-image/allocation choices
    // are obtained separately through the existing pool-context template service.
    const rows = await prisma.sandboxPoolMember.findMany({
      where,
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: pageTake(input.limit),
      select: { id: true, poolId: true, createdAt: true } satisfies Prisma.SandboxPoolMemberSelect,
    });
    const page = cursorPage(rows, input.limit, "createdAt");
    const membersCurrent = await checkMemberRead(
      owner,
      pool,
      rows.map((row) => row.id),
    );
    await check();
    membersCurrent();
    return {
      items: page.items.map(({ id, poolId }) => ({ id, poolId })),
      nextCursor: page.nextCursor,
    };
  },
);

/** A contributor sees only its own memberships, including disabled/withdrawn history. */
export const listPoolContributions = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: z.infer<typeof listPoolMembersInput>) => {
    const { pool, check } = await readPool(owner, input.poolId, true);
    const rows = await prisma.sandboxPoolMember.findMany({
      where: withCursor(
        { poolId: pool.id, hostOwnerId: owner.ownerId },
        "createdAt",
        input.cursor,
        "desc",
      ),
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: pageTake(input.limit),
      select: contributedMemberSelect,
    });
    await check();
    return cursorPage(rows, input.limit, "createdAt");
  },
);

const unavailable = () =>
  new ORPCError("CONFLICT", { message: "Sharing state changed. Retry the operation." });
/**
 * Member RAM/vCPU caps bound what a pool may take from a CONTRIBUTED host.
 * An owner-local member (pool owner = host owner) is exempt in placement and
 * in the capacity view, so a cap there would be stored but never applied:
 * refuse it plainly instead of the retryable "state changed" conflict.
 */
const ownerLocalMemberCaps = () =>
  new ORPCError("BAD_REQUEST", {
    message:
      "Member RAM and vCPU caps apply only to hosts contributed by other accounts; your own hosts in your own pool are never capped. Leave the caps empty.",
    data: { code: "pool.member_caps_owner_local" },
  });
const digest = (token: string) => createHash("sha256").update(token).digest("hex");
const newToken = () => `wssp_inv_${randomBytes(32).toString("base64url")}`;
const settings = (input: z.infer<typeof updatePoolShareInput>) => ({
  canUse: input.canUse,
  canContribute: input.canContribute,
  maxMemoryMiB: input.maxMemoryMiB,
  maxVcpu: input.maxVcpu,
  maxDiskGiB: input.maxDiskGiB,
});
function capIncreases(before: number | null, after: number | null) {
  return before !== null && (after === null || after > before);
}
async function ownedPool(tx: Prisma.TransactionClient, ownerId: string, poolId: string) {
  const pool = await tx.sandboxPool.findFirst({
    where: { id: poolId, userId: ownerId, deletedAt: null },
    select: { id: true, label: true },
  });
  if (!pool) throw poolNotFound();
  return pool;
}
async function graphWrite<T>(
  owner: Principal,
  poolId: string,
  ids: string[],
  work: (tx: Prisma.TransactionClient) => Promise<T>,
  removingAuthority = false,
  poolOwnerId = owner.ownerId,
) {
  await consumeSharingWrite(owner.ownerId);
  // Fence SDK reads while the graph changes. Durable rows remain authoritative.
  const result = await withSharingAuthorityChange([owner.ownerId, poolOwnerId], () =>
    prisma.$transaction(async (tx) => {
      await lockSharingPrincipals(
        tx,
        [owner.ownerId, ...ids],
        removingAuthority ? [owner.ownerId] : [owner.ownerId, ...ids],
      );
      await lockPoolGraph(tx, [poolId]);
      return work(tx);
    }),
  );
  notifySharingAccessChanged(poolId);
  return result;
}
async function capacity(tx: Prisma.TransactionClient, poolId: string, granteeUserId: string) {
  if (
    !(await tx.share.findUnique({
      where: { poolId_granteeUserId: { poolId, granteeUserId } },
      select: { id: true },
    })) &&
    (await tx.share.count({ where: { poolId } })) >= 250
  )
    throw unavailable();
}

/** An owner can explicitly change an existing grant. Invite acceptance cannot. */
export const updatePoolShare = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, raw: z.input<typeof updatePoolShareInput>) => {
    const input = updatePoolShareInput.parse(raw);
    return graphWrite(
      owner,
      input.poolId,
      [input.granteeUserId],
      async (tx) => {
        await ownedPool(tx, owner.ownerId, input.poolId);
        const where = {
          poolId: input.poolId,
          ownerUserId: owner.ownerId,
          granteeUserId: input.granteeUserId,
        };
        const existing = await tx.share.findFirst({ where, select: shareSelect });
        if (!existing) throw poolNotFound();
        if (!input.canUse && !input.canContribute) {
          await tx.share.delete({ where: { id: existing.id } });
          return { share: null };
        }
        if (
          (input.canUse && !existing.canUse) ||
          (input.canContribute && !existing.canContribute) ||
          capIncreases(existing.maxMemoryMiB, input.maxMemoryMiB) ||
          capIncreases(existing.maxVcpu, input.maxVcpu) ||
          capIncreases(existing.maxDiskGiB, input.maxDiskGiB)
        )
          await requireSharingPolicies(tx, [owner.ownerId, input.granteeUserId]);
        return {
          share: await tx.share.update({
            where: { id: existing.id },
            data: settings(input),
            select: shareSelect,
          }),
        };
      },
      true,
    );
  },
);
export const revokePoolShare = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, raw: z.input<typeof revokePoolShareInput>) => {
    const input = revokePoolShareInput.parse(raw);
    return graphWrite(
      owner,
      input.poolId,
      [input.granteeUserId],
      async (tx) => {
        await ownedPool(tx, owner.ownerId, input.poolId);
        const result = await tx.share.deleteMany({
          where: { ...input, ownerUserId: owner.ownerId },
        });
        if (!result.count) throw poolNotFound();
        return { ok: true as const };
      },
      true,
    );
  },
);
export const leavePool = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, raw: z.input<typeof leavePoolInput>) => {
    const input = leavePoolInput.parse(raw);
    // Soft-deleted pools retain shares; those no longer authorize a foreign hold.
    const pool = await prisma.sandboxPool.findFirst({
      where: { id: input.poolId, deletedAt: null },
      select: { userId: true },
    });
    if (!pool || pool.userId === owner.ownerId) throw poolNotFound();
    const share = await prisma.share.findUnique({
      where: { poolId_granteeUserId: { poolId: input.poolId, granteeUserId: owner.ownerId } },
      select: { ownerUserId: true },
    });
    if (share?.ownerUserId !== pool.userId) throw poolNotFound();
    return graphWrite(
      owner,
      input.poolId,
      [pool.userId],
      async (tx) => {
        const result = await tx.share.deleteMany({
          where: {
            poolId: input.poolId,
            granteeUserId: owner.ownerId,
            ownerUserId: pool.userId,
            Pool: { deletedAt: null },
          },
        });
        if (!result.count) throw poolNotFound();
        return { ok: true as const };
      },
      true,
      pool.userId,
    );
  },
);

async function deliverInvite(
  invite: Prisma.ShareInviteGetPayload<{ select: typeof inviteSelect }>,
  token: string,
  ownerId: string,
) {
  try {
    const { renderPoolShare, sendEmail } = await import("@wssp/mailer");
    const [owner, pool, recipient] = await Promise.all([
      prisma.user.findUnique({ where: { id: ownerId }, select: { name: true, locale: true } }),
      prisma.sandboxPool.findUnique({ where: { id: invite.poolId }, select: { label: true } }),
      prisma.user.findUnique({ where: { email: invite.email }, select: { locale: true } }),
    ]);
    if (!owner || !pool) return false;
    const locale = (recipient?.locale ?? owner.locale) === "es-MX" ? "es-MX" : "en-US";
    const url = new URL(`/${locale}/settings/pools/invite`, env.CORS_ORIGIN || env.BETTER_AUTH_URL);
    url.hash = token;
    await sendEmail({
      to: invite.email,
      ...renderPoolShare({
        locale,
        url: url.toString(),
        inviter: owner?.name ?? "",
        pool: pool?.label ?? "",
        invite,
      }),
    });
    // sentAt records confirmed delivery only for this exact still-pending digest.
    await prisma.$transaction(async (tx) => {
      await lockPoolGraph(tx, [invite.poolId]);
      await tx.shareInvite.updateMany({
        where: { id: invite.id, tokenDigest: digest(token), pendingKey: { not: null } },
        data: { sentAt: new Date() },
      });
    });
    return true;
  } catch {
    // No dependency errors, token or recipient in logs/errors. A retry rotates.
    return false;
  }
}
export const grantPoolShare = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, raw: z.input<typeof grantPoolShareInput>) => {
    const input = grantPoolShareInput.parse(raw);
    if (!input.canUse && !input.canContribute) throw unavailable();
    const target = await prisma.user.findUnique({
      where: { email: input.email },
      select: { id: true, emailVerified: true },
    });
    if (!target?.emailVerified)
      await consumeInviteIssue(owner.ownerId, input.poolId, input.email, input.signupAllowed);
    const token = newToken();
    const result = await graphWrite(owner, input.poolId, target ? [target.id] : [], async (tx) => {
      await ownedPool(tx, owner.ownerId, input.poolId);
      const recipient = target
        ? await tx.user.findUnique({
            where: { id: target.id },
            select: { id: true, email: true, emailVerified: true },
          })
        : null;
      if (recipient?.id === owner.ownerId) throw unavailable();
      const permissions = settings({ ...input, granteeUserId: recipient?.id ?? "" });
      if (recipient?.email === input.email && recipient.emailVerified) {
        await tx.shareInvite.updateMany({
          where: { poolId: input.poolId, email: input.email, pendingKey: { not: null } },
          data: { revokedAt: new Date(), pendingKey: null },
        });
        await capacity(tx, input.poolId, recipient.id);
        const share = await tx.share.upsert({
          where: { poolId_granteeUserId: { poolId: input.poolId, granteeUserId: recipient.id } },
          create: {
            poolId: input.poolId,
            ownerUserId: owner.ownerId,
            granteeUserId: recipient.id,
            ...permissions,
          },
          update: permissions,
          select: shareSelect,
        });
        return { kind: "share" as const, share };
      }
      if (target?.emailVerified) throw unavailable(); // Proof changed after budget preflight; retry before issuance.
      const [clock] = await tx.$queryRaw<
        { now: Date }[]
      >`SELECT clock_timestamp() AT TIME ZONE 'UTC' AS now`;
      await tx.shareInvite.updateMany({
        where: { poolId: input.poolId, pendingKey: { not: null }, expiresAt: { lte: clock!.now } },
        data: { expiredAt: clock!.now, pendingKey: null },
      });
      if (
        (await tx.shareInvite.count({
          where: { poolId: input.poolId, pendingKey: { not: null } },
        })) >= 100
      )
        throw unavailable();
      if (
        await tx.shareInvite.findUnique({
          where: { pendingKey: `${input.poolId}:${input.email}` },
          select: { id: true },
        })
      )
        throw unavailable();
      const invite = await tx.shareInvite.create({
        data: {
          poolId: input.poolId,
          ownerUserId: owner.ownerId,
          email: input.email,
          ...permissions,
          signupAllowed: input.signupAllowed,
          tokenDigest: digest(token),
          pendingKey: `${input.poolId}:${input.email}`,
          createdAt: clock!.now,
          expiresAt: new Date(clock!.now.getTime() + 7 * 86400000),
        },
        select: inviteSelect,
      });
      return { kind: "invite" as const, invite };
    });
    if (result.kind === "share") return result;
    return { ...result, token, sent: await deliverInvite(result.invite, token, owner.ownerId) };
  },
);
export const resendPoolInvite = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, raw: z.input<typeof poolInviteInput>) => {
    const input = poolInviteInput.parse(raw);
    const known = await prisma.shareInvite.findFirst({
      where: { id: input.inviteId, poolId: input.poolId, ownerUserId: owner.ownerId },
      select: { email: true },
    });
    if (!known) throw poolNotFound();
    // Resends never mint a new signup allowance; signupAllowed is immutable.
    await consumeInviteIssue(owner.ownerId, input.poolId, known.email, false);
    const token = newToken();
    const invite = await graphWrite(owner, input.poolId, [], async (tx) => {
      await ownedPool(tx, owner.ownerId, input.poolId);
      const [clock] = await tx.$queryRaw<
        { now: Date }[]
      >`SELECT clock_timestamp() AT TIME ZONE 'UTC' AS now`;
      const row = await tx.shareInvite.findFirst({
        where: {
          id: input.inviteId,
          poolId: input.poolId,
          ownerUserId: owner.ownerId,
          pendingKey: { not: null },
        },
        select: { id: true, expiresAt: true },
      });
      if (!row) throw unavailable();
      if (row.expiresAt <= clock!.now) {
        await tx.shareInvite.update({
          where: { id: row.id },
          data: { expiredAt: clock!.now, pendingKey: null },
          select: { id: true },
        });
        return null;
      }
      return tx.shareInvite.update({
        where: { id: row.id },
        data: {
          tokenDigest: digest(token),
          expiresAt: new Date(clock!.now.getTime() + 7 * 86400000),
          sentAt: null,
        },
        select: inviteSelect,
      });
    });
    if (!invite) throw unavailable();
    return { invite, token, sent: await deliverInvite(invite, token, owner.ownerId) };
  },
);
export const revokePoolInvite = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, raw: z.input<typeof poolInviteInput>) => {
    const input = poolInviteInput.parse(raw);
    return graphWrite(owner, input.poolId, [], async (tx) => {
      await ownedPool(tx, owner.ownerId, input.poolId);
      const result = await tx.shareInvite.updateMany({
        where: {
          id: input.inviteId,
          poolId: input.poolId,
          ownerUserId: owner.ownerId,
          pendingKey: { not: null },
        },
        data: { revokedAt: new Date(), pendingKey: null },
      });
      if (!result.count) throw unavailable();
      return { ok: true as const };
    });
  },
);
export const acceptPoolInvite = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, raw: z.input<typeof acceptPoolInviteInput>) => {
    // Invalid presentations consume the same durable-actor budget.
    await consumeInviteAccept(owner.ownerId);
    const parsed = acceptPoolInviteInput.safeParse(raw);
    if (!parsed.success || !inviteTokenInput.safeParse(parsed.data.token).success)
      throw unavailable();
    const input = parsed.data;
    const tokenDigest = digest(input.token);
    const known = await prisma.shareInvite.findUnique({
      where: { tokenDigest },
      select: { poolId: true, ownerUserId: true },
    });
    if (!known) throw unavailable();
    const result = await graphWrite(owner, known.poolId, [known.ownerUserId], async (tx) => {
      await ownedPool(tx, known.ownerUserId, known.poolId);
      const user = await tx.user.findUnique({
        where: { id: owner.ownerId },
        select: { email: true, emailVerified: true },
      });
      const invite = await tx.shareInvite.findUnique({
        where: { tokenDigest },
        select: {
          ...inviteSelect,
          ownerUserId: true,
          pendingKey: true,
          acceptedByUserId: true,
          acceptedShareId: true,
        },
      });
      if (!invite || !user?.emailVerified || invite.ownerUserId === owner.ownerId)
        throw unavailable();
      if (input.mode === "email" && invite.email !== user.email.trim().toLowerCase())
        throw unavailable();
      if (invite.acceptedAt && invite.acceptedByUserId === owner.ownerId)
        return { inviteId: invite.id, shareId: invite.acceptedShareId! };
      const [clock] = await tx.$queryRaw<
        { now: Date }[]
      >`SELECT clock_timestamp() AT TIME ZONE 'UTC' AS now`;
      if (!invite.pendingKey) throw unavailable();
      if (invite.expiresAt <= clock!.now) {
        await tx.shareInvite.update({
          where: { id: invite.id },
          data: { expiredAt: clock!.now, pendingKey: null },
          select: { id: true },
        });
        return null;
      }
      if (
        await tx.share.findUnique({
          where: { poolId_granteeUserId: { poolId: invite.poolId, granteeUserId: owner.ownerId } },
          select: { id: true },
        })
      )
        throw unavailable();
      await capacity(tx, invite.poolId, owner.ownerId);
      const share = await tx.share.create({
        data: {
          poolId: invite.poolId,
          ownerUserId: invite.ownerUserId,
          granteeUserId: owner.ownerId,
          ...settings({ ...invite, granteeUserId: owner.ownerId }),
        },
        select: { id: true },
      });
      const changed = await tx.shareInvite.updateMany({
        where: {
          id: invite.id,
          tokenDigest,
          pendingKey: { not: null },
          expiresAt: { gt: clock!.now },
        },
        data: {
          acceptedAt: clock!.now,
          acceptedByUserId: owner.ownerId,
          acceptedShareId: share.id,
          pendingKey: null,
        },
      });
      if (changed.count !== 1) throw unavailable();
      return { inviteId: invite.id, shareId: share.id };
    });
    if (!result) throw unavailable();
    return result;
  },
);

/**
 * What the accept page shows before the invitee accepts: the pool's label and
 * the inviter's name (exactly what the invitation mail already carries), and
 * whether the invitation was addressed to the caller's own email, so the page
 * can pick the right acceptance mode. Only a pending, unexpired invitation of
 * another owner previews, to a caller with a verified email (the same
 * preconditions as accepting); everything else is the one generic CONFLICT,
 * so a token holder learns nothing about why. Read-only: it never expires a
 * row or touches the graph.
 */
export const previewPoolInvite = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, raw: z.input<typeof previewPoolInviteInput>) => {
    // Invalid presentations consume the same durable-actor budget.
    await consumeInvitePreview(owner.ownerId);
    const parsed = previewPoolInviteInput.safeParse(raw);
    if (!parsed.success || !inviteTokenInput.safeParse(parsed.data.token).success)
      throw unavailable();
    const [invite, user, clock] = await Promise.all([
      prisma.shareInvite.findUnique({
        where: { tokenDigest: digest(parsed.data.token) },
        select: {
          email: true,
          ownerUserId: true,
          pendingKey: true,
          expiresAt: true,
          Pool: { select: { label: true, deletedAt: true } },
          Owner: { select: { name: true } },
        },
      }),
      prisma.user.findUnique({
        where: { id: owner.ownerId },
        select: { email: true, emailVerified: true },
      }),
      prisma.$queryRaw<{ now: Date }[]>`SELECT clock_timestamp() AT TIME ZONE 'UTC' AS now`,
    ]);
    if (
      !invite?.pendingKey ||
      !user?.emailVerified ||
      invite.ownerUserId === owner.ownerId ||
      invite.Pool.deletedAt ||
      invite.expiresAt <= clock[0]!.now
    )
      throw unavailable();
    return {
      poolLabel: invite.Pool.label,
      inviterName: invite.Owner.name,
      addressedToYou: invite.email === user.email.trim().toLowerCase(),
      expiresAt: invite.expiresAt,
    };
  },
);

async function contributionReduction(
  tx: Prisma.TransactionClient,
  ownerId: string,
  poolOwnerId: string,
  input: z.infer<typeof contributePoolHostInput>,
) {
  const member = await tx.sandboxPoolMember.findFirst({
    where: {
      poolId: input.poolId,
      sandboxHostId: input.sandboxHostId,
      userId: poolOwnerId,
      hostOwnerId: ownerId,
      removedAt: null,
      Pool: { deletedAt: null },
    },
    select: {
      id: true,
      enabled: true,
      memoryCapPercent: true,
      vcpuCapPercent: true,
      maxLeaseMs: true,
    },
  });
  return member &&
    !(input.enabled && !member.enabled) &&
    !capIncreases(member.memoryCapPercent, input.memoryCapPercent) &&
    !capIncreases(member.vcpuCapPercent, input.vcpuCapPercent) &&
    // Lowering the lease limit needs no consent; raising re-proves the contribution.
    (input.maxLeaseMs === undefined || !capIncreases(member.maxLeaseMs, input.maxLeaseMs))
    ? member
    : null;
}

export const contributePoolHost = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, raw: z.input<typeof contributePoolHostInput>) => {
    const input = contributePoolHostInput.parse(raw);
    const pool = await prisma.sandboxPool.findFirst({
      where: { id: input.poolId, deletedAt: null },
      select: { userId: true },
    });
    if (!pool) throw poolNotFound();
    if (
      pool.userId === owner.ownerId &&
      (input.memoryCapPercent !== null || input.vcpuCapPercent !== null)
    )
      throw ownerLocalMemberCaps();
    // Existing consent permits only reductions without counterparty admission.
    // Prove consent before fencing a foreign pool; recheck under User/G/H.
    if (!(await contributionReduction(prisma, owner.ownerId, pool.userId, input)))
      await requirePoolContribution(prisma, owner.ownerId, input.poolId, input.sandboxHostId);
    return graphWrite(
      owner,
      input.poolId,
      [pool.userId],
      async (tx) => {
        const reduction = await contributionReduction(tx, owner.ownerId, pool.userId, input);
        if (reduction) {
          const host = await lockCurrentHostEpoch(tx, input.sandboxHostId);
          requireRelayFence(host.userId === owner.ownerId);
          return tx.sandboxPoolMember.update({
            where: { id: reduction.id },
            data: {
              enabled: input.enabled,
              memoryCapPercent: input.memoryCapPercent,
              vcpuCapPercent: input.vcpuCapPercent,
              maxLeaseMs: input.maxLeaseMs,
            },
            select: contributedMemberSelect,
          });
        }
        await requireSharingPolicies(tx, [owner.ownerId, pool.userId]);
        const context = await requirePoolContribution(
          tx,
          owner.ownerId,
          input.poolId,
          input.sandboxHostId,
        );
        await lockHostForSandboxOperation(tx, input.sandboxHostId, owner.ownerId);
        await requirePoolContribution(tx, owner.ownerId, input.poolId, input.sandboxHostId);
        // No share: the contributor owns the pool (owner-local membership).
        if (!context.share && (input.memoryCapPercent !== null || input.vcpuCapPercent !== null))
          throw ownerLocalMemberCaps();
        const existing = await tx.sandboxPoolMember.findUnique({
          where: {
            poolId_sandboxHostId: { poolId: input.poolId, sandboxHostId: input.sandboxHostId },
          },
          select: { id: true, removedAt: true },
        });
        if (!existing || existing.removedAt) {
          if (
            (await tx.sandboxPoolMember.count({
              where: { poolId: input.poolId, removedAt: null },
            })) >= MAX_ACTIVE_POOL_MEMBERSHIPS ||
            (await tx.sandboxPoolMember.count({
              where: { sandboxHostId: input.sandboxHostId, removedAt: null },
            })) >= MAX_ACTIVE_POOL_MEMBERSHIPS
          )
            throw new ORPCError("CONFLICT", {
              message: "Membership limit reached. Remove pool memberships before retrying.",
            });
        }
        const witness = context.share
          ? { shareId: context.share.id, contributeWitness: true, ownHostsOnlyWitness: false }
          : { shareId: null, contributeWitness: null, ownHostsOnlyWitness: null };
        const data = {
          enabled: input.enabled,
          memoryCapPercent: input.memoryCapPercent,
          vcpuCapPercent: input.vcpuCapPercent,
          // Omitted means unchanged on an active row; a new or re-activated
          // membership (N4) starts from the given value or no limit.
          maxLeaseMs:
            !existing || existing.removedAt ? (input.maxLeaseMs ?? null) : input.maxLeaseMs,
          removedAt: null,
          ...witness,
        };
        return tx.sandboxPoolMember.upsert({
          where: {
            poolId_sandboxHostId: { poolId: input.poolId, sandboxHostId: input.sandboxHostId },
          },
          create: {
            poolId: input.poolId,
            sandboxHostId: input.sandboxHostId,
            userId: pool.userId,
            hostOwnerId: owner.ownerId,
            ...data,
          },
          update: data,
          select: contributedMemberSelect,
        });
      },
      true,
      pool.userId,
    );
  },
);
export const withdrawPoolHost = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: { poolId: string; sandboxHostId: string }) => {
    // Historical ownership alone must not authorize a foreign owner's hold.
    const member = await prisma.sandboxPoolMember.findUnique({
      where: { poolId_sandboxHostId: input },
      select: { userId: true, hostOwnerId: true, removedAt: true },
    });
    if (
      !member?.hostOwnerId ||
      member.removedAt !== null ||
      (owner.ownerId !== member.userId && owner.ownerId !== member.hostOwnerId)
    )
      throw poolNotFound();
    return graphWrite(
      owner,
      input.poolId,
      [member.userId, member.hostOwnerId],
      async (tx) => {
        const host = await lockCurrentHostEpoch(tx, input.sandboxHostId);
        requireRelayFence(host.userId === member.hostOwnerId);
        const result = await tx.sandboxPoolMember.updateMany({
          where: {
            ...input,
            userId: member.userId,
            hostOwnerId: member.hostOwnerId,
            removedAt: null,
          },
          data: { removedAt: new Date(), enabled: false },
        });
        if (!result.count) throw poolNotFound();
        return { ok: true as const };
      },
      true,
      member.userId,
    );
  },
);
