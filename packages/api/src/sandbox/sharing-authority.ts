import { ORPCError } from "@orpc/server";
import type { Prisma } from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { holdAuthorityChange } from "@wssp/db/authority";
import type { Principal } from "./contracts";
import { hostNotFound, poolNotFound, sandboxNotFound, sandboxStateConflict } from "./errors";
import { MAX_ACTIVE_POOL_MEMBERSHIPS } from "./pool-locks";
import { viewerOf } from "./principal-kinds";

export const shareSelect = {
  id: true,
  poolId: true,
  ownerUserId: true,
  granteeUserId: true,
  canUse: true,
  canContribute: true,
  maxMemoryMiB: true,
  maxVcpu: true,
  maxDiskGiB: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.ShareSelect;
const sharingPoolSelect = {
  id: true,
  userId: true,
  slug: true,
  label: true,
  ownHostsOnly: true,
  disconnectGraceSeconds: true,
  deletedAt: true,
} satisfies Prisma.SandboxPoolSelect;

/** Discover the complete set first; never call this after K/G/H.
 * Removal serializes every principal but applies admission policy only to the actor.
 */
export async function lockSharingPrincipals(
  tx: Prisma.TransactionClient,
  ids: readonly string[],
  admissionIds: readonly string[] = ids,
) {
  const eligible = new Set(admissionIds);
  for (const id of [...new Set(ids)].sort()) {
    if (!eligible.has(id)) {
      await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${id} FOR SHARE`;
      continue;
    }
    await lockOwnerForAdmission(tx, id);
    const user = await tx.user.findUnique({
      where: { id },
      select: { banned: true, banExpires: true },
    });
    const [clock] = await tx.$queryRaw<
      { now: Date }[]
    >`SELECT clock_timestamp() AT TIME ZONE 'UTC' AS now`;
    if (!user || (user.banned && (!user.banExpires || user.banExpires > clock!.now)))
      throw poolNotFound();
  }
}

/** Hold every affected owner through commit/rollback, including a pool owner
 * who is neither the withdrawing contributor nor the guest creator.
 */
export async function withSharingAuthorityChange<T>(
  ids: readonly string[],
  change: () => Promise<T>,
): Promise<T> {
  const holds = [...new Set(ids)].map((ownerId) => holdAuthorityChange({ ownerId }));
  let committed = false;
  try {
    const result = await change();
    committed = true;
    return result;
  } finally {
    for (const hold of holds) hold.settle(committed);
  }
}

export async function requireSharingPolicies(tx: Prisma.TransactionClient, ids: readonly string[]) {
  const principals = [...new Set(ids)];
  const [clock] = await tx.$queryRaw<
    { now: Date }[]
  >`SELECT clock_timestamp() AT TIME ZONE 'UTC' AS now`;
  const count = await tx.user.count({
    where: {
      id: { in: principals },
      deletionRequestedAt: null,
      OR: [{ banned: { not: true } }, { banned: null }, { banExpires: { lte: clock!.now } }],
    },
  });
  if (count !== principals.length) throw poolNotFound();
}

export async function requirePoolUse(
  tx: Prisma.TransactionClient,
  principal: Principal,
  poolId: string,
) {
  const { allowedPoolIds } = viewerOf(principal);
  if (allowedPoolIds !== "allUsable" && !allowedPoolIds.has(poolId)) throw poolNotFound();
  const pool = await tx.sandboxPool.findFirst({
    where: { id: poolId, deletedAt: null },
    select: sharingPoolSelect,
  });
  if (!pool) throw poolNotFound();
  const share =
    pool.userId === principal.ownerId
      ? null
      : await tx.share.findUnique({
          where: { poolId_granteeUserId: { poolId, granteeUserId: principal.ownerId } },
          select: shareSelect,
        });
  if (pool.userId !== principal.ownerId && !share?.canUse) throw poolNotFound();
  await requireSharingPolicies(tx, [principal.ownerId, pool.userId]);
  return { pool, share, creatorId: principal.ownerId };
}

export async function requirePoolContribution(
  tx: Prisma.TransactionClient,
  ownerId: string,
  poolId: string,
  hostId: string,
) {
  const pool = await tx.sandboxPool.findFirst({
    where: { id: poolId, deletedAt: null },
    select: sharingPoolSelect,
  });
  if (!pool) throw poolNotFound();
  const host = await tx.sandboxHost.findFirst({
    where: { id: hostId, userId: ownerId, deletionRequestedAt: null },
    select: { id: true, userId: true },
  });
  if (!host) throw hostNotFound();
  const share =
    pool.userId === ownerId
      ? null
      : await tx.share.findUnique({
          where: { poolId_granteeUserId: { poolId, granteeUserId: ownerId } },
          select: shareSelect,
        });
  if (pool.userId !== ownerId && (pool.ownHostsOnly || !share?.canContribute)) throw poolNotFound();
  await requireSharingPolicies(tx, [ownerId, pool.userId]);
  return { pool, host, share, hostOwnerId: ownerId };
}

/** No host relation: grantees receive opaque members and compatible choices only. */
export const usableMemberSelect = {
  id: true,
  poolId: true,
} satisfies Prisma.SandboxPoolMemberSelect;
/** Contributors inspect only their own contributions, never other hosts/workloads. */
export const contributedMemberSelect = {
  id: true,
  poolId: true,
  sandboxHostId: true,
  enabled: true,
  removedAt: true,
  memoryCapPercent: true,
  vcpuCapPercent: true,
  maxLeaseMs: true,
  createdAt: true,
} satisfies Prisma.SandboxPoolMemberSelect;

/** Internal transport context only. Placement.hostOwnerId is evidence, never independent authority. */
export async function requireOwnedSandboxPlacement(
  tx: Prisma.TransactionClient,
  creatorId: string,
  sandboxId: string,
  // STOP/cold start may reference the immutable prior launch generation.
  // Execution IO and warm renewal require the current launch generation.
  allowHistoricalGeneration = false,
) {
  const row = await tx.sandbox.findFirst({
    where: { id: sandboxId, userId: creatorId },
    select: {
      id: true,
      userId: true,
      hostOwnerId: true,
      sandboxHostId: true,
      generation: true,
      storagePoolId: true,
      storageMarker: true,
      storagePoolName: true,
      leaseRevision: true,
      leaseExpiresAt: true,
      state: true,
      accessGraceUntil: true,
      SandboxHost: {
        select: { id: true, userId: true, connectionEpoch: true, deletionRequestedAt: true },
      },
      CurrentPlacement: {
        select: {
          id: true,
          userId: true,
          sandboxId: true,
          generation: true,
          originHostId: true,
          hostOwnerId: true,
          acceptedGraceSeconds: true,
          originShareId: true,
          storagePoolId: true,
          storageMarker: true,
          storagePoolName: true,
        },
      },
    },
  });
  if (!row) throw sandboxNotFound();
  const host = row.SandboxHost,
    placement = row.CurrentPlacement;
  if (
    !host ||
    !placement ||
    row.hostOwnerId !== host.userId ||
    placement.hostOwnerId !== row.hostOwnerId ||
    placement.userId !== row.userId ||
    placement.sandboxId !== row.id ||
    (allowHistoricalGeneration
      ? placement.generation > row.generation
      : placement.generation !== row.generation) ||
    placement.originHostId !== host.id ||
    row.sandboxHostId !== host.id ||
    placement.storagePoolId !== row.storagePoolId ||
    placement.storageMarker !== row.storageMarker ||
    placement.storagePoolName !== row.storagePoolName
  )
    throw sandboxStateConflict("Sandbox placement changed.");
  return { sandbox: row, placement, host, creatorId, hostOwnerId: host.userId };
}
/** Discovery is read-only and runs before User/K/G/H. New membership or
 * attribution discovered later must retry instead of acquiring User after H. */
const placementPrincipals = new WeakMap<object, ReadonlySet<string>>();
export async function discoverPlacementPrincipals(
  tx: Prisma.TransactionClient,
  owner: Principal,
  target: {
    poolId?: string;
    sandboxId?: string;
    idempotencyKey: string;
    /** Restore of an OFFLOADED sandbox: the hinted host or pool (§8.3). */
    restoreTarget?: { hostId: string } | { poolId: string } | null;
  },
) {
  if (
    await tx.sandboxOperation.findUnique({
      where: {
        userId_idempotencyKey: { userId: owner.ownerId, idempotencyKey: target.idempotencyKey },
      },
      select: { id: true },
    })
  )
    return [owner.ownerId];
  let poolId = target.poolId;
  const ids = new Set([owner.ownerId]);
  if (target.sandboxId) {
    const sandbox = await tx.sandbox.findFirst({
      where: { id: target.sandboxId, userId: owner.ownerId },
      select: { hostOwnerId: true, usagePoolId: true, state: true, originPoolId: true },
    });
    if (!sandbox) throw sandboxNotFound();
    // a restore may place through its origin pool (or
    // the hinted one): that pool's owner and its members' host owners.
    if (sandbox.state === "OFFLOADED") {
      const hint = target.restoreTarget ?? null;
      if (hint && "hostId" in hint) return [owner.ownerId];
      const restorePool = hint && "poolId" in hint ? hint.poolId : sandbox.originPoolId;
      if (!restorePool) return [owner.ownerId];
      const pool = await tx.sandboxPool.findUnique({
        where: { id: restorePool },
        select: { userId: true },
      });
      if (pool) ids.add(pool.userId);
      const members = await tx.sandboxPoolMember.findMany({
        where: { poolId: restorePool, removedAt: null },
        select: { hostOwnerId: true },
        take: MAX_ACTIVE_POOL_MEMBERSHIPS + 1,
      });
      if (members.length > MAX_ACTIVE_POOL_MEMBERSHIPS)
        throw sandboxStateConflict("Remove pool memberships before retrying.");
      for (const member of members) if (member.hostOwnerId) ids.add(member.hostOwnerId);
      return [...ids].sort();
    }
    // Warm renewal adds no holds and retains the initial CREATE key's
    // authority even after cap-fitting attribution moved to an unselected pool.
    if (sandbox.state !== "STOPPED") return [owner.ownerId];
    if (sandbox.hostOwnerId) ids.add(sandbox.hostOwnerId);
    poolId = sandbox.usagePoolId ?? undefined;
    if (sandbox.hostOwnerId === owner.ownerId) {
      const pool = poolId
        ? await tx.sandboxPool.findUnique({ where: { id: poolId }, select: { userId: true } })
        : null;
      if (pool) ids.add(pool.userId);
      return [...ids].sort();
    }
  }
  if (poolId) {
    const { pool } = await requirePoolUse(tx, owner, poolId);
    ids.add(pool.userId);
    if (!target.sandboxId) {
      const members = await tx.sandboxPoolMember.findMany({
        where: { poolId, removedAt: null },
        select: { hostOwnerId: true },
        take: MAX_ACTIVE_POOL_MEMBERSHIPS + 1,
      });
      if (members.length > MAX_ACTIVE_POOL_MEMBERSHIPS)
        throw sandboxStateConflict("Remove pool memberships before retrying.");
      for (const member of members) if (member.hostOwnerId) ids.add(member.hostOwnerId);
    }
  }
  return [...ids].sort();
}
export async function lockPlacementPrincipals(tx: Prisma.TransactionClient, ids: string[]) {
  // Admission/deletion locks only; policy is checked for the selected path.
  // A banned host in one candidate must not deny all other hosts in the pool.
  for (const id of [...new Set(ids)].sort()) await lockOwnerForAdmission(tx, id);
  placementPrincipals.set(tx, new Set(ids));
}
export function requirePlacementPrincipals(tx: Prisma.TransactionClient, ids: string[]) {
  if (ids.some((id) => !placementPrincipals.get(tx)?.has(id)))
    throw new ORPCError("CONFLICT", { message: "Placement authority changed. Retry the request." });
}
