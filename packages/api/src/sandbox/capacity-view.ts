import prisma, { type Prisma } from "@wssp/db";
import { Prisma as PrismaValue } from "@wssp/db/client";
import {
  type PoolCapacityDto,
  resolveVmSize,
  VM_SIZE_LIMITS,
  type VmSize,
  vmLiveMemoryChargeMiB,
  vmRootChargeGiB,
} from "@wssp/sandbox-contracts";
import { serviceProcedure } from "../lib/sdk-key-access";
import { poolCapacityLimits } from "./capacity-limits";
import { reservedHostIds } from "./capacity-queue";
import type { Principal } from "./contracts";
import { poolNotFound } from "./errors";
import { STORAGE_HEALTH_STALE_MS } from "./host-admission";
import { imageFetchPlan, STATEMENT_NOW } from "./image-placement";
import { poolLeaseViews } from "./lease-policy";
import { MAX_ACTIVE_POOL_MEMBERSHIPS } from "./pool-locks";
import { placementSql, revisionNeedsStartup } from "./pool-placement";
import { poolSelect } from "./pool-visibility";
import { grantOf, viewerOf } from "./principal-kinds";
import { hostDatabaseNow } from "./relay-fence";
import { getUsablePool } from "./services/sharing";
import { consumePoolCapacityRead } from "./sharing-budgets";
import { shareUsage } from "./sharing-quota";
import { resolveTemplateRevision } from "./template-resolution";
import { assertDiskFitsImage } from "./vm-size-input";

export type PoolCapacityInput = {
  id: string;
  template?: string;
  cpuCount?: number;
  memoryMiB?: number;
  diskGiB?: number;
};

/**
 * TS mirror of the placement rank's dominant share (`placementSql`'s
 * `dominantShare`): the largest of charged RAM, vCPU and the chosen storage
 * pool's committed GiB after this request, over their budgets. Null when a
 * budget is unknown or zero (the view, unlike placement, includes such hosts).
 */
export function dominantShareAfter(
  host: {
    memoryReservedMiB: number;
    daemonMemoryBudgetMiB: number | null;
    vcpuReserved: number;
    daemonVcpuBudget: number | null;
  },
  storage: { capacityGiB: number; reservedGiB: number } | null,
  size: VmSize,
): number | null {
  const ratio = (used: number, budget: number | null) =>
    budget === null || budget <= 0 ? null : used / budget;
  const parts = [
    ratio(
      host.memoryReservedMiB + vmLiveMemoryChargeMiB(size.memoryMiB),
      host.daemonMemoryBudgetMiB,
    ),
    ratio(host.vcpuReserved + size.cpuCount, host.daemonVcpuBudget),
    storage
      ? ratio(storage.reservedGiB + vmRootChargeGiB(size.diskGiB), storage.capacityGiB)
      : null,
  ].filter((value): value is number => value !== null);
  return parts.length === 0 ? null : Math.max(...parts);
}

type HostRow = {
  id: string;
  slug: string;
  label: string;
  status: "DISCONNECTED" | "CONNECTED" | "STALE" | "REVOKED";
  draining: boolean;
  own: boolean;
  ownerLocal: boolean;
  memoryBudget: number | null;
  memoryReserved: number;
  vcpuBudget: number | null;
  vcpuReserved: number;
  maxCpu: number | null;
  rootCount: number;
  liveCount: number;
  memoryCap: number | null;
  vcpuCap: number | null;
  memberMaxLeaseMs: number | null;
  usageMemory: bigint;
  usageVcpu: bigint;
  enabled: boolean;
  compatible: boolean;
  startup: boolean;
  online: boolean;
  guard: boolean;
  known: boolean;
  current: boolean;
  leaseFits: boolean;
  perVm: boolean;
};
type StorageRow = {
  hostId: string;
  name: string;
  capacityGiB: number;
  reservedGiB: number;
  usable: boolean;
};

const floorDiv = (a: number, b: number) => (b <= 0 ? 0 : Math.max(0, Math.floor(a / b)));

type Largest = NonNullable<PoolCapacityDto["largest"]>;
const floorStep = (value: number, step: number) => Math.max(0, Math.floor(value / step) * step);

/**
 * The largest single sandbox one eligible host could take now, per dimension:
 * vCPU within its free vCPU and per-VM maximum, memory within its free budget
 * and per-VM ceiling less the VM overhead (in 256 MiB steps), root disk within
 * the freest usable storage pool less the root overhead, all within the
 * create limits.
 */
export function hostLargest(
  host: { maxCpu: number | null; memoryBudget: number | null },
  memoryFree: number,
  vcpuFree: number,
  usablePools: readonly { capacityGiB: number; reservedGiB: number }[],
): Largest {
  const overhead = VM_SIZE_LIMITS.vmHostOverheadMiB;
  return {
    cpuCount: Math.max(0, Math.min(vcpuFree, host.maxCpu ?? 0, VM_SIZE_LIMITS.cpuCountMax)),
    memoryMiB: floorStep(
      Math.min(
        VM_SIZE_LIMITS.memoryMiBMax,
        (host.memoryBudget ?? 0) - overhead,
        memoryFree - overhead,
      ),
      VM_SIZE_LIMITS.memoryMiBStep,
    ),
    diskGiB: Math.min(
      VM_SIZE_LIMITS.diskGiBMax,
      Math.max(
        0,
        ...usablePools.map(
          (row) => row.capacityGiB - row.reservedGiB - VM_SIZE_LIMITS.rootDiskOverheadGiB,
        ),
      ),
    ),
  };
}

/** `largest` within what the caller's share caps still leave (one sandbox's charge). */
export function shareCappedLargest(
  largest: Largest,
  share: { maxMemoryMiB: number | null; maxVcpu: number | null; maxDiskGiB: number | null },
  used: { memoryMiB: bigint; vcpu: bigint; diskGiB: bigint },
): Largest {
  const left = (cap: number | null, spent: bigint, overhead: number) =>
    cap === null ? Number.POSITIVE_INFINITY : cap - Number(spent) - overhead;
  return {
    cpuCount: Math.max(0, Math.min(largest.cpuCount, left(share.maxVcpu, used.vcpu, 0))),
    memoryMiB: floorStep(
      Math.min(
        largest.memoryMiB,
        left(share.maxMemoryMiB, used.memoryMiB, VM_SIZE_LIMITS.vmHostOverheadMiB),
      ),
      VM_SIZE_LIMITS.memoryMiBStep,
    ),
    diskGiB: Math.max(
      0,
      Math.min(
        largest.diskGiB,
        left(share.maxDiskGiB, used.diskGiB, VM_SIZE_LIMITS.rootDiskOverheadGiB),
      ),
    ),
  };
}

/**
 * The capacity view (§6). One query over the placement visibility
 * fragments (stage-0 visibility including the key host filter, plus enabled,
 * compatible, template stages when a template is given). Aggregates sum
 * pool-usable free capacity (host free capped by member caps) over currently
 * schedulable visible hosts; `fits` is capped by the caller's share caps
 * and leaves out hosts the queue gate reserves for a strict head.
 * Per-host detail is only for the caller's OWN hosts and only with
 * hosts:read: foreign host ids, counts, status and numbers never appear.
 */
export async function poolCapacityView(
  owner: Principal,
  input: PoolCapacityInput,
): Promise<PoolCapacityDto> {
  // Owned or currently usable (share canUse), intersected with key selection:
  // exactly `GET /v1/pools/{id}` (the same service, so visibility cannot drift).
  const visible = await getUsablePool(owner, { id: input.id });
  const pool = await prisma.sandboxPool.findFirst({
    where: { id: visible.id, deletedAt: null },
    select: { ...poolSelect, userId: true },
  });
  if (!pool) throw poolNotFound();
  const poolOwner = { userId: pool.userId };
  const revision = input.template
    ? await resolveTemplateRevision(prisma, owner, input.template)
    : null;
  const overrides = {
    cpuCount: input.cpuCount,
    memoryMiB: input.memoryMiB,
    diskGiB: input.diskGiB,
  };
  const size: VmSize | null = revision
    ? resolveVmSize(
        {
          cpuCount: revision.cpuCount,
          memoryMiB: revision.memoryMiB,
          diskGiB: revision.defaultDiskGiB,
        },
        overrides,
      )
    : input.cpuCount !== undefined && input.memoryMiB !== undefined && input.diskGiB !== undefined
      ? resolveVmSize(
          { cpuCount: input.cpuCount, memoryMiB: input.memoryMiB, diskGiB: input.diskGiB },
          {},
        )
      : null;
  // The same refusal as the create: a disk below the image's root never fits.
  if (revision && size) assertDiskFitsImage(revision, size.diskGiB);
  const now = await hostDatabaseNow(prisma);
  const sql = placementSql({
    viewer: viewerOf(owner),
    poolId: pool.id,
    // Template stages are only read when a template was given.
    revision: revision ?? { id: "", incusFingerprint: "", architecture: "", manifestDigest: "" },
    size: size ?? { cpuCount: 1, memoryMiB: 512, diskGiB: 1 },
    now,
    plan: revision ? await imageFetchPlan(prisma, owner.ownerId, revision) : null,
    startup: revision
      ? await revisionNeedsStartup(prisma, owner.ownerId, revision.id, null)
      : false,
  });
  const flag = (part: Prisma.Sql) => PrismaValue.sql`COALESCE((${part}), false)`;
  const hosts = await prisma.$queryRaw<HostRow[]>`
    SELECT h.id, h.slug, h.label, h.status::text AS status, h.draining,
      (h."userId" = ${owner.ownerId}) AS own, (h."userId" = pool."userId") AS "ownerLocal",
      h."daemonMemoryBudgetMiB" AS "memoryBudget", h."memoryReservedMiB" AS "memoryReserved",
      h."daemonVcpuBudget" AS "vcpuBudget", h."vcpuReserved", h."daemonMaxCpuCount" AS "maxCpu", h."rootCount", h."liveCount",
      m."memoryCapPercent" AS "memoryCap", m."vcpuCapPercent" AS "vcpuCap",
      m."maxLeaseMs" AS "memberMaxLeaseMs", usage.memory AS "usageMemory", usage.vcpu AS "usageVcpu",
      ${flag(sql.stages.enabled)} AS enabled, ${flag(sql.stages.compatible)} AS compatible,
      ${flag(sql.stages.startup)} AS startup, ${flag(sql.stages.guard)} AS guard,
      ${flag(sql.stages.online)} AS online, ${flag(sql.stages.templateKnown)} AS known,
      ${flag(sql.stages.templateCurrent)} AS current, ${flag(sql.stages.lease)} AS "leaseFits",
      ${flag(sql.stages.perVm)} AS "perVm"
    ${sql.from} WHERE ${sql.visible}
    ORDER BY h.id LIMIT ${MAX_ACTIVE_POOL_MEMBERSHIPS}`;
  const storageOldest = new Date(now.getTime() - STORAGE_HEALTH_STALE_MS);
  const storage = hosts.length
    ? await prisma.$queryRaw<StorageRow[]>`
        SELECT p."sandboxHostId" AS "hostId", p.name, p."capacityGiB", p."diskReservedGiB" AS "reservedGiB",
          (p."newRootsAllowed" AND p.health = 'healthy' AND NOT p.draining
            AND p."reportedAt" BETWEEN ${storageOldest} AND ${STATEMENT_NOW}) AS usable
        FROM sandbox_host_storage_pool p JOIN sandbox_host h
          ON h.id = p."sandboxHostId" AND h."userId" = p."userId" AND p."connectionEpoch" = h."connectionEpoch"
        WHERE p."sandboxHostId" = ANY(${hosts.map((host) => host.id)}::text[])
        ORDER BY p."sandboxHostId", p.marker LIMIT 4096`
    : [];
  // The create gate's pre-selection exclusion for a new arrival: hosts held
  // for a strict head fit nothing for the caller now. Only ids come back.
  const reserved = new Set(hosts.length ? await reservedHostIds(prisma, pool.id, null) : []);
  const charge = size ? vmLiveMemoryChargeMiB(size.memoryMiB) : 0;
  const root = size ? vmRootChargeGiB(size.diskGiB) : 0;
  const free = { memoryMiB: 0, vcpu: 0, diskGiB: 0 };
  const budget = { memoryMiB: 0, vcpu: 0, diskGiB: 0 };
  let fits = 0;
  let largest: Largest | null = null;
  const detail: PoolCapacityDto["hosts"] = [];
  for (const host of hosts) {
    const pools = storage.filter((row) => row.hostId === host.id);
    const usablePools = pools.filter((row) => row.usable);
    const capped = (cap: number | null, hostBudget: number | null) =>
      host.ownerLocal || cap === null || hostBudget === null
        ? null
        : Math.floor((hostBudget * cap) / 100);
    const memoryCapBudget = capped(host.memoryCap, host.memoryBudget);
    const vcpuCapBudget = capped(host.vcpuCap, host.vcpuBudget);
    const memoryFree = Math.max(
      0,
      Math.min(
        (host.memoryBudget ?? 0) - host.memoryReserved,
        memoryCapBudget === null
          ? Number.POSITIVE_INFINITY
          : memoryCapBudget - Number(host.usageMemory),
      ),
    );
    const vcpuFree = Math.max(
      0,
      Math.min(
        (host.vcpuBudget ?? 0) - host.vcpuReserved,
        vcpuCapBudget === null ? Number.POSITIVE_INFINITY : vcpuCapBudget - Number(host.usageVcpu),
      ),
    );
    const diskFree = usablePools.reduce(
      (sum, row) => sum + Math.max(0, row.capacityGiB - row.reservedGiB),
      0,
    );
    const schedulable =
      host.enabled &&
      host.compatible &&
      host.startup &&
      host.online &&
      host.guard &&
      (revision ? host.current : true);
    if (schedulable) {
      free.memoryMiB += memoryFree;
      free.vcpu += vcpuFree;
      free.diskGiB += diskFree;
      budget.memoryMiB += Math.min(
        host.memoryBudget ?? 0,
        memoryCapBudget ?? Number.POSITIVE_INFINITY,
      );
      budget.vcpu += Math.min(host.vcpuBudget ?? 0, vcpuCapBudget ?? Number.POSITIVE_INFINITY);
      budget.diskGiB += usablePools.reduce((sum, row) => sum + row.capacityGiB, 0);
    }
    const hostFits =
      size && schedulable && host.leaseFits && host.perVm && !reserved.has(host.id)
        ? Math.min(
            floorDiv(memoryFree, charge),
            floorDiv(vcpuFree, size.cpuCount),
            usablePools.reduce(
              (sum, row) => sum + floorDiv(row.capacityGiB - row.reservedGiB, root),
              0,
            ),
            Math.max(0, VM_SIZE_LIMITS.hostManagedSandboxCeiling - host.rootCount),
          )
        : size
          ? 0
          : null;
    fits += hostFits ?? 0;
    if (
      schedulable &&
      host.leaseFits &&
      !reserved.has(host.id) &&
      host.rootCount < VM_SIZE_LIMITS.hostManagedSandboxCeiling
    ) {
      const one = hostLargest(host, memoryFree, vcpuFree, usablePools);
      largest = largest
        ? {
            cpuCount: Math.max(largest.cpuCount, one.cpuCount),
            memoryMiB: Math.max(largest.memoryMiB, one.memoryMiB),
            diskGiB: Math.max(largest.diskGiB, one.diskGiB),
          }
        : one;
    }
    const hostDetail = grantOf(owner).has("hosts:read");
    if (host.own && hostDetail) {
      const chosen = usablePools
        .slice()
        .sort((a, b) => b.capacityGiB - b.reservedGiB - (a.capacityGiB - a.reservedGiB))[0];
      detail.push({
        id: host.id,
        slug: host.slug,
        label: host.label,
        status: host.status,
        draining: host.draining,
        schedulable,
        memory: { budgetMiB: host.memoryBudget ?? 0, reservedMiB: host.memoryReserved },
        vcpu: { budget: host.vcpuBudget ?? 0, reserved: host.vcpuReserved },
        storagePools: pools.slice(0, 64).map((row) => ({
          name: row.name,
          capacityGiB: row.capacityGiB,
          reservedGiB: row.reservedGiB,
          healthy: row.usable,
        })),
        liveCount: host.liveCount,
        member: {
          memoryCapPercent: host.memoryCap,
          vcpuCapPercent: host.vcpuCap,
          maxLeaseMs: host.memberMaxLeaseMs,
        },
        fits: hostFits,
        dominantShareAfter: size
          ? dominantShareAfter(
              {
                memoryReservedMiB: host.memoryReserved,
                daemonMemoryBudgetMiB: host.memoryBudget,
                vcpuReserved: host.vcpuReserved,
                daemonVcpuBudget: host.vcpuBudget,
              },
              chosen ? { capacityGiB: chosen.capacityGiB, reservedGiB: chosen.reservedGiB } : null,
              size,
            )
          : null,
        excludedBy:
          revision && !host.startup
            ? "template_startup"
            : revision && !host.known
              ? "template_unavailable"
              : !host.leaseFits
                ? "lease_policy"
                : size && !host.perVm
                  ? "vm_size"
                  : host.draining
                    ? "draining"
                    : !host.online
                      ? "offline"
                      : reserved.has(host.id)
                        ? "reserved"
                        : null,
      });
    }
  }
  if ((size || largest) && poolOwner.userId !== owner.ownerId) {
    const share = await prisma.share.findUnique({
      where: { poolId_granteeUserId: { poolId: pool.id, granteeUserId: owner.ownerId } },
      select: { maxMemoryMiB: true, maxVcpu: true, maxDiskGiB: true },
    });
    if (share) {
      const used = await shareUsage(prisma, pool.id, owner.ownerId);
      if (size) {
        const remaining = (cap: number | null, used: bigint, each: number) =>
          cap === null ? Number.POSITIVE_INFINITY : floorDiv(cap - Number(used), each);
        fits = Math.min(
          fits,
          remaining(share.maxMemoryMiB, used.memoryMiB, charge),
          remaining(share.maxVcpu, used.vcpu, size.cpuCount),
          remaining(share.maxDiskGiB, used.diskGiB, root),
        );
      }
      if (largest) largest = shareCappedLargest(largest, share, used);
    }
  }
  const lease = (await poolLeaseViews(prisma, viewerOf(owner), [pool], now)).get(pool.id) ?? {
    maxTimeoutMs: 300000,
    timeoutZero: false,
  };
  const [waiting, mine] = await Promise.all([
    prisma.sandboxCapacityWait.count({ where: { poolId: pool.id, state: "WAITING" } }),
    prisma.sandboxCapacityWait.findMany({
      where: { poolId: pool.id, state: "WAITING", userId: owner.ownerId },
      orderBy: { seq: "asc" },
      take: 1,
      select: { seq: true },
    }),
  ]);
  const mineCount = await prisma.sandboxCapacityWait.count({
    where: { poolId: pool.id, state: "WAITING", userId: owner.ownerId },
  });
  const oldest = mine[0]
    ? await prisma.sandboxCapacityWait.count({
        where: { poolId: pool.id, state: "WAITING", seq: { lte: mine[0].seq } },
      })
    : null;
  return {
    poolId: pool.id,
    templateRevisionId: revision?.id ?? null,
    size,
    aggregate: { free, budget },
    fits: size ? fits : null,
    largest,
    lease,
    queue: {
      waiting,
      mine: mineCount,
      myOldestPosition: oldest,
      limits: poolCapacityLimits(pool),
      preferOwnHosts: pool.preferOwnHosts,
    },
    hosts: detail,
  };
}

/** Both planes; 30/min per owner (one `/rpc` batch can carry many calls). */
export const getPoolCapacity = serviceProcedure(
  { action: "pools.capacity", target: (input: PoolCapacityInput) => ({ poolId: input.id }) },
  async (owner: Principal, input: PoolCapacityInput) => {
    await consumePoolCapacityRead(owner.ownerId);
    return poolCapacityView(owner, input);
  },
);
