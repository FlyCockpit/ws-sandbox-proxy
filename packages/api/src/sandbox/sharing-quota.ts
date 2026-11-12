import { ORPCError } from "@orpc/server";
import type { Prisma } from "@wssp/db";
import type { Principal } from "./contracts";
import { requirePoolUse } from "./sharing-authority";

export type ResourceCharge = { memoryMiB: bigint; vcpu: bigint; diskGiB: bigint };
export type ShareCaps = {
  maxMemoryMiB: number | null;
  maxVcpu: number | null;
  maxDiskGiB: number | null;
};

const incompleteUsage = () =>
  new ORPCError("CONFLICT", { message: "Resource accounting evidence is incomplete." });
/** Caller holds G through the acquisition commit. History/Share IDs are never ledgers. */
export async function shareUsage(
  tx: Prisma.TransactionClient,
  poolId: string,
  creatorId: string,
  excludeSandboxId: string | null = null,
): Promise<ResourceCharge> {
  const usage = (await shareUsageByPool(tx, [poolId], creatorId, excludeSandboxId)).get(poolId);
  if (!usage) throw incompleteUsage();
  return usage;
}

/** The single definition of share usage: one grouped read of a creator's
 * charge in each pool. Every requested pool gets an entry (zero when the
 * creator holds nothing there); incomplete evidence in ANY pool fails the call. */
export async function shareUsageByPool(
  tx: Prisma.TransactionClient,
  poolIds: readonly string[],
  creatorId: string,
  excludeSandboxId: string | null = null,
): Promise<Map<string, ResourceCharge>> {
  const usage = new Map<string, ResourceCharge>();
  if (poolIds.length === 0) return usage;
  // S10: a detached copy (`SandboxDiskCopy` holding its root reservation)
  // keeps its share attribution after the sandbox left the host.
  const pools = [...new Set(poolIds)];
  const rows = await tx.$queryRaw<(ResourceCharge & { poolId: string; incomplete: bigint })[]>`
    SELECT u."poolId", COALESCE(sum(u.incomplete), 0)::bigint AS incomplete,
      COALESCE(sum(u."memoryMiB"), 0)::bigint AS "memoryMiB",
      COALESCE(sum(u.vcpu), 0)::bigint AS vcpu, COALESCE(sum(u."diskGiB"), 0)::bigint AS "diskGiB"
    FROM (
      SELECT s."usagePoolId" AS "poolId",
        count(*) FILTER (WHERE (s."liveResourcesHeld" AND (p.id IS NULL OR p."chargedMemoryMiB" IS NULL OR p."chargedVcpu" IS NULL)) OR (s."diskReservationHeld" AND s."rootChargeGiB" IS NULL))::bigint AS incomplete,
        COALESCE(sum(CASE WHEN s."liveResourcesHeld" THEN p."chargedMemoryMiB"::bigint ELSE 0 END), 0)::bigint AS "memoryMiB",
        COALESCE(sum(CASE WHEN s."liveResourcesHeld" THEN p."chargedVcpu"::bigint ELSE 0 END), 0)::bigint AS vcpu,
        COALESCE(sum(CASE WHEN s."diskReservationHeld" THEN s."rootChargeGiB"::bigint ELSE 0 END), 0)::bigint AS "diskGiB"
      FROM sandbox_instance s LEFT JOIN sandbox_placement p ON p.id = s."currentPlacementId" AND p."sandboxId" = s.id AND p."userId" = s."userId"
      WHERE s."usagePoolId" = ANY(${pools}::text[]) AND s."userId" = ${creatorId}
        AND (${excludeSandboxId}::text IS NULL OR s.id <> ${excludeSandboxId})
      GROUP BY s."usagePoolId"
      UNION ALL
      SELECT c."usagePoolId", 0::bigint, 0::bigint, 0::bigint, COALESCE(sum(c."rootChargeGiB"::bigint), 0)::bigint
      FROM sandbox_disk_copy c
      WHERE c."diskReservationHeld" AND c."usagePoolId" = ANY(${pools}::text[]) AND c."userId" = ${creatorId}
      GROUP BY c."usagePoolId"
    ) u
    GROUP BY u."poolId"
  `;
  for (const row of rows) {
    if (row.incomplete > 0n) throw incompleteUsage();
    usage.set(row.poolId, { memoryMiB: row.memoryMiB, vcpu: row.vcpu, diskGiB: row.diskGiB });
  }
  for (const poolId of poolIds)
    if (!usage.has(poolId)) usage.set(poolId, { memoryMiB: 0n, vcpu: 0n, diskGiB: 0n });
  return usage;
}

/** Read-only listing helper: the same sums as `shareUsage`, grouped by creator
 * in one statement. Creators with no rows charge zero; any incomplete group
 * refuses the whole read exactly as a per-creator `shareUsage` would. */
export async function shareUsageByCreator(
  tx: Prisma.TransactionClient,
  poolId: string,
  creatorIds: readonly string[],
): Promise<Map<string, ResourceCharge>> {
  const usage = new Map<string, ResourceCharge>(
    creatorIds.map((id) => [id, { memoryMiB: 0n, vcpu: 0n, diskGiB: 0n }]),
  );
  if (creatorIds.length === 0) return usage;
  const creators = [...creatorIds];
  // S10: detached copies holding their root reservation, as in shareUsageByPool.
  const rows = await tx.$queryRaw<(ResourceCharge & { userId: string; incomplete: bigint })[]>`
    SELECT u."userId", COALESCE(sum(u.incomplete), 0)::bigint AS incomplete,
      COALESCE(sum(u."memoryMiB"), 0)::bigint AS "memoryMiB",
      COALESCE(sum(u.vcpu), 0)::bigint AS vcpu, COALESCE(sum(u."diskGiB"), 0)::bigint AS "diskGiB"
    FROM (
      SELECT s."userId" AS "userId",
        count(*) FILTER (WHERE (s."liveResourcesHeld" AND (p.id IS NULL OR p."chargedMemoryMiB" IS NULL OR p."chargedVcpu" IS NULL)) OR (s."diskReservationHeld" AND s."rootChargeGiB" IS NULL))::bigint AS incomplete,
        COALESCE(sum(CASE WHEN s."liveResourcesHeld" THEN p."chargedMemoryMiB"::bigint ELSE 0 END), 0)::bigint AS "memoryMiB",
        COALESCE(sum(CASE WHEN s."liveResourcesHeld" THEN p."chargedVcpu"::bigint ELSE 0 END), 0)::bigint AS vcpu,
        COALESCE(sum(CASE WHEN s."diskReservationHeld" THEN s."rootChargeGiB"::bigint ELSE 0 END), 0)::bigint AS "diskGiB"
      FROM sandbox_instance s LEFT JOIN sandbox_placement p ON p.id = s."currentPlacementId" AND p."sandboxId" = s.id AND p."userId" = s."userId"
      WHERE s."usagePoolId" = ${poolId} AND s."userId" = ANY(${creators}::text[])
      GROUP BY s."userId"
      UNION ALL
      SELECT c."userId", 0::bigint, 0::bigint, 0::bigint, COALESCE(sum(c."rootChargeGiB"::bigint), 0)::bigint
      FROM sandbox_disk_copy c
      WHERE c."diskReservationHeld" AND c."usagePoolId" = ${poolId} AND c."userId" = ANY(${creators}::text[])
      GROUP BY c."userId"
    ) u
    GROUP BY u."userId"
  `;
  for (const row of rows) {
    if (row.incomplete > 0n)
      throw new ORPCError("CONFLICT", { message: "Resource accounting evidence is incomplete." });
    usage.set(row.userId, { memoryMiB: row.memoryMiB, vcpu: row.vcpu, diskGiB: row.diskGiB });
  }
  return usage;
}

export function shareQuotaFailure(caps: ShareCaps, used: ResourceCharge, added: ResourceCharge) {
  for (const [resource, field, cap] of [
    ["memory", "memoryMiB", caps.maxMemoryMiB],
    ["vcpu", "vcpu", caps.maxVcpu],
    ["disk", "diskGiB", caps.maxDiskGiB],
  ] as const)
    if (cap !== null && added[field] > 0n && used[field] + added[field] > BigInt(cap))
      return resource;
  return null;
}
const ZERO_CHARGE: ResourceCharge = { memoryMiB: 0n, vcpu: 0n, diskGiB: 0n };
export function requireShareQuota(caps: ShareCaps, used: ResourceCharge, added: ResourceCharge) {
  const resource = shareQuotaFailure(caps, used, added);
  if (resource)
    throw new ORPCError("CONFLICT", {
      message: "Share resource quota exceeded.",
      // Permanent when this request alone exceeds a cap (no usage to wait out).
      data: {
        code: "sandbox.share_quota",
        resource,
        retryable: shareQuotaFailure(caps, ZERO_CHARGE, added) === null,
      },
    });
}

export function memberQuotaFailure(
  input: {
    ownerLocal: boolean;
    memoryBudgetMiB: number;
    vcpuBudget: number;
    memoryCapPercent: number | null;
    vcpuCapPercent: number | null;
  },
  used: ResourceCharge,
  added: ResourceCharge,
) {
  if (input.ownerLocal) return null;
  for (const [resource, field, budget, percent] of [
    ["memory", "memoryMiB", input.memoryBudgetMiB, input.memoryCapPercent],
    ["vcpu", "vcpu", input.vcpuBudget, input.vcpuCapPercent],
  ] as const)
    if (
      percent !== null &&
      added[field] > 0n &&
      used[field] + added[field] > (BigInt(budget) * BigInt(percent)) / 100n
    )
      return resource;
  return null;
}
/** G and H are held. Attribute all creators' live charges to this pool/host. */
export async function memberUsage(
  tx: Prisma.TransactionClient,
  poolId: string,
  hostId: string,
  excludeSandboxId: string | null = null,
): Promise<ResourceCharge> {
  const [usage] = await tx.$queryRaw<(ResourceCharge & { incomplete: bigint })[]>`
    SELECT count(*) FILTER (WHERE p.id IS NULL OR p."chargedMemoryMiB" IS NULL OR p."chargedVcpu" IS NULL)::bigint AS incomplete,
      COALESCE(sum(p."chargedMemoryMiB"::bigint), 0)::bigint AS "memoryMiB",
      COALESCE(sum(p."chargedVcpu"::bigint), 0)::bigint AS vcpu, 0::bigint AS "diskGiB"
    FROM sandbox_instance s LEFT JOIN sandbox_placement p
      ON p.id = s."currentPlacementId" AND p."sandboxId" = s.id AND p."userId" = s."userId"
    WHERE s."sandboxHostId" = ${hostId} AND s."usagePoolId" = ${poolId} AND s."liveResourcesHeld"
      AND (${excludeSandboxId}::text IS NULL OR s.id <> ${excludeSandboxId})
  `;
  if (!usage || usage.incomplete > 0n)
    throw new ORPCError("CONFLICT", { message: "Resource accounting evidence is incomplete." });
  return { memoryMiB: usage.memoryMiB, vcpu: usage.vcpu, diskGiB: 0n };
}

function requireMemberQuota(
  input: Parameters<typeof memberQuotaFailure>[0],
  used: ResourceCharge,
  added: ResourceCharge,
) {
  const resource = memberQuotaFailure(input, used, added);
  if (resource)
    throw new ORPCError("CONFLICT", {
      message: "Member resource quota exceeded.",
      // Permanent when this request alone exceeds the member cap on this host.
      data: {
        code: "sandbox.member_quota",
        resource,
        retryable: memberQuotaFailure(input, ZERO_CHARGE, added) === null,
      },
    });
}

/** G is held; all creators and keys charge the same current-placement sums. */
export async function requirePoolShareAcquisition(
  tx: Prisma.TransactionClient,
  owner: Principal,
  poolId: string,
  added: ResourceCharge,
) {
  const context = await requirePoolUse(tx, owner, poolId);
  if (context.share)
    requireShareQuota(context.share, await shareUsage(tx, poolId, owner.ownerId), added);
  return context;
}
/** G then H are held. A disabled member still permits cold start on retained
 * storage; removal, permission withdrawal or a mismatched transport does not. */
export async function requirePoolMemberAcquisition(
  tx: Prisma.TransactionClient,
  input: {
    poolId: string;
    memberId: string;
    hostId: string;
    hostOwnerId: string;
    newRoot: boolean;
  },
  added: ResourceCharge,
) {
  const member = await tx.sandboxPoolMember.findFirst({
    where: {
      id: input.memberId,
      poolId: input.poolId,
      sandboxHostId: input.hostId,
      hostOwnerId: input.hostOwnerId,
      removedAt: null,
      ...(input.newRoot ? { enabled: true } : {}),
    },
    select: {
      userId: true,
      hostOwnerId: true,
      memoryCapPercent: true,
      vcpuCapPercent: true,
      Host: { select: { daemonMemoryBudgetMiB: true, daemonVcpuBudget: true } },
    },
  });
  if (
    !member?.Host ||
    member.Host.daemonMemoryBudgetMiB == null ||
    member.Host.daemonVcpuBudget == null
  )
    throw new ORPCError("CONFLICT", { message: "Pool member changed. Retry the request." });
  requireMemberQuota(
    {
      ownerLocal: member.userId === member.hostOwnerId,
      memoryBudgetMiB: member.Host.daemonMemoryBudgetMiB,
      vcpuBudget: member.Host.daemonVcpuBudget,
      memoryCapPercent: member.memoryCapPercent,
      vcpuCapPercent: member.vcpuCapPercent,
    },
    await memberUsage(tx, input.poolId, input.hostId),
    added,
  );
}
