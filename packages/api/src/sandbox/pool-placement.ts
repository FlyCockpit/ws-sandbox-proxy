import { ORPCError } from "@orpc/server";
import { HOST_HEARTBEAT_STALE_AFTER_MS } from "@wssp/config/host-status";
import type { Prisma } from "@wssp/db";
import { Prisma as PrismaValue } from "@wssp/db/client";
import {
  type EgressMode,
  isRetryableRefusalCode,
  resolveVmSize,
  VM_SIZE_LIMITS,
  type VmSize,
  type VmSizeOverrides,
  vmLiveMemoryChargeMiB,
  vmRootChargeGiB,
} from "@wssp/sandbox-contracts";
import { credentialError } from "../credentials/errors";
import {
  type CredentialPlacementContext,
  credentialCapabilitySql,
  credentialOwnerSql,
} from "../credentials/placement";
import {
  type BuildPlacement,
  builderSql,
  requireBuildPlacement,
} from "../template-builds/placement";
import { rebuildOnMissLocked, rebuildRefusal } from "../template-builds/rebuild";
import type { Principal } from "./contracts";
import { lockOwnerPlacement, resolveDirectPlacement } from "./direct-placement";
import {
  type BuildSkipped,
  buildNoBuilder,
  egressRefused,
  leaseExceedsPolicy,
  memberQuota,
  poolFull,
  poolNoCompatibleHost,
  poolUnavailable,
  templateImageMissing,
  templateUnavailable,
  tunnelRefused,
  unsupportedCapability,
  vmSizeUnsupported,
  withRetryable,
} from "./errors";
import { STORAGE_HEALTH_STALE_MS } from "./host-admission";
import { requestDigestMetadata } from "./idempotency";
import {
  fetchableCurrentSql,
  fetchableStaticSql,
  hasCurrentImageSql,
  type ImageFetchPlan,
  imageFetchPlan,
  lockImageFetchSuffix,
} from "./image-placement";
import { foreignCopyUsableSql } from "./image-store/access";
import { hostImageFeatures } from "./image-store/config";
import { LEASE_DEFAULT_MS } from "./lease-limits";
import {
  deploymentFiniteMaxMs,
  deploymentLeaseMaxMs,
  deploymentPathLimit,
  effectiveLeaseLimit,
  type LeaseRequest,
  leaseFitsSql,
  leaseRequestOf,
  pathLimitSql,
  requireLeaseWithinPolicy,
} from "./lease-policy";
import { lockPoolGraph, MAX_ACTIVE_POOL_MEMBERSHIPS } from "./pool-locks";
import { type PlacementViewer, viewerOf } from "./principal-kinds";
import { hostDatabaseNow } from "./relay-fence";
import { requirePlacementPrincipals } from "./sharing-authority";
import { requirePoolMemberAcquisition, requirePoolShareAcquisition } from "./sharing-quota";
import { resolveTemplateRevision } from "./template-resolution";
import { assertDiskFitsImage } from "./vm-size-input";

export class PlacementChanged extends Error {}

/** Only selected-host admission failures trigger pool reselection. Other
 * errors (authorization, revision ownership, DB faults) retain their meaning. */
export async function poolHostRecheck<T>(
  poolId: string | null,
  work: () => Promise<T>,
): Promise<T> {
  try {
    return await work();
  } catch (error) {
    if (
      poolId &&
      error instanceof ORPCError &&
      ([
        "sandbox.host_capacity",
        "sandbox.vm_size_unsupported",
        "sandbox.host_unavailable",
        "sandbox.host_draining",
        "sandbox.template_image_rejected",
        "sandbox.template_image_missing",
        "sandbox.template_image_unavailable",
      ].includes(error.data?.code) ||
        (error.data?.code === "UNSUPPORTED_CAPABILITY" && error.data?.capability === "egress"))
    )
      throw new PlacementChanged();
    throw error;
  }
}

/** Each retry starts AFTER rollback, so no H survives into another selection. */
export async function retryPlacement<T>(work: () => Promise<T>): Promise<T> {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      return await work();
    } catch (error) {
      if (!(error instanceof PlacementChanged)) throw error;
    }
  }
  throw new ORPCError("SERVICE_UNAVAILABLE", {
    message: "Placement changed. Retry the same request.",
  });
}

type Revision = Pick<
  Awaited<ReturnType<typeof resolveTemplateRevision>>,
  "id" | "incusFingerprint" | "architecture" | "manifestDigest"
>;

/**
 * Named placement predicates, in cascade order. Every consumer composes these
 * same fragments (selection, the refusal cascade, static feasibility, queue
 * head eligibility and the capacity view), so the predicates cannot drift.
 * `visible` (pool, share, host owner, key host filter) always applies.
 */
export const PLACEMENT_STAGES = [
  "enabled",
  "compatible",
  // Template builds only (TRUE otherwise): a builder node for this owner (§4).
  "builder",
  // Revisions with a start command only (TRUE otherwise): `templateStartup`.
  "startup",
  // Creates with declared tunnel ports only (TRUE otherwise): a verified
  // tunnel client the host owner lets this owner use.
  "tunnel",
  // CLI logins (§8, TRUE without logins): hosts the logins' owner policy admits.
  "credentialOwner",
  "templateKnown",
  "online",
  "guard",
  "credentialCapability",
  "templateCurrent",
  "lease",
  "perVm",
  "storagePresent",
  "ram",
  "ceiling",
  "vcpu",
  "disk",
  "memberMemory",
  "memberVcpu",
] as const;
export type PlacementStage = (typeof PLACEMENT_STAGES)[number];

function stagesThrough(stage: PlacementStage | null): readonly PlacementStage[] {
  return stage === null ? [] : PLACEMENT_STAGES.slice(0, PLACEMENT_STAGES.indexOf(stage) + 1);
}

/** Static feasibility: could this request ever fit a visible host, ignoring
 * current load and connectivity (`fitsEmpty` adds the member-cap check). */
export const STATIC_STAGES: readonly PlacementStage[] = [
  "enabled",
  "compatible",
  "builder",
  "startup",
  "tunnel",
  "credentialOwner",
  "templateKnown",
  "lease",
  "perVm",
];

/** Who the predicates are evaluated for (`viewerOf`: session or SDK key host filter). */
export type { PlacementViewer } from "./principal-kinds";

export type PlacementQuery = {
  viewer: PlacementViewer;
  poolId: string;
  revision: Revision;
  size: VmSize;
  now: Date;
  lease?: LeaseRequest;
  selectedId?: string | null;
  /** Queue gate: hosts reserved for an older waiting request (§4.3). */
  excludedHostIds?: readonly string[];
  /** Image distribution: the owner's fetch plan for this revision (null: none). */
  plan?: ImageFetchPlan | null;
  /** Template build create: activates the `builder` stage (null/absent: not a build). */
  build?: BuildPlacement | null;
  /** The launch carries start/ready commands (`revisionNeedsStartup`):
   * activates the `startup` stage. */
  startup?: boolean;
  /** CLI logins (§8): what the attached logins need from a host (null: none). */
  credential?: CredentialPlacementContext | null;
  /** The requested egress mode: `open` ranks hosts that would grant it first. */
  egressMode?: EgressMode;
  /** Preview tunnels: activates the `tunnel` stage. */
  tunnel?: boolean;
};

/**
 * B9: a launch of this revision carries start/ready commands, so it may be
 * placed only on hosts whose daemon admitted `templateStartup` on the current
 * connection (the `startup` stage). A build VM never runs them: it boots its
 * base revision only to run recipe steps. The outbox keeps refusing such a
 * launch on an unsupported daemon as a backstop (`templateStartupHostUnsupported`).
 */
export async function revisionNeedsStartup(
  tx: Prisma.TransactionClient,
  ownerId: string,
  revisionId: string,
  buildId: string | null | undefined,
): Promise<boolean> {
  if (buildId) return false;
  const row = await tx.sandboxTemplateRevision.findFirst({
    where: { id: revisionId, userId: ownerId },
    select: { startCmd: true },
  });
  return row?.startCmd != null;
}

/** The daemon admitted `templateStartup` on its current connection (host
 * admission writes it per epoch; the `startup` stage's SQL in TS). */
function hostAdmitsTemplateStartup(features: Prisma.JsonValue | null): boolean {
  return (
    features != null &&
    typeof features === "object" &&
    !Array.isArray(features) &&
    features.templateStartup === true
  );
}

const AND = (parts: Prisma.Sql[]) =>
  parts.length === 0 ? PrismaValue.sql`TRUE` : PrismaValue.join(parts, " AND ");

/** FROM clause (aliases m, h, pool, host_owner, storage, usage) and fragments. */
export function placementSql(q: PlacementQuery) {
  const { viewer: owner, poolId, revision, size, now } = q;
  const lease = q.lease ?? { kind: "deadline" as const, ms: LEASE_DEFAULT_MS };
  const allHosts = owner.allowedHostIds === "allOwned";
  const hostIds = owner.allowedHostIds === "allOwned" ? [] : [...owner.allowedHostIds];
  const oldest = new Date(now.getTime() - HOST_HEARTBEAT_STALE_AFTER_MS);
  const storageOldest = new Date(now.getTime() - STORAGE_HEALTH_STALE_MS);
  const keyId = requestDigestMetadata().requestDigestKeyId;
  const deployment = deploymentLeaseMaxMs();
  const charge = vmLiveMemoryChargeMiB(size.memoryMiB);
  const root = vmRootChargeGiB(size.diskGiB);
  const excluded = [...(q.excludedHostIds ?? [])];
  const builder = q.build ? builderSql(owner.ownerId, q.build) : null;
  const from = PrismaValue.sql`
    FROM sandbox_pool_member m JOIN sandbox_host h
      ON h.id = m."sandboxHostId" AND h."userId" = m."hostOwnerId"
    JOIN sandbox_pool pool ON pool.id = m."poolId" AND pool."userId" = m."userId"
    JOIN "user" host_owner ON host_owner.id = h."userId"
    LEFT JOIN LATERAL (
      SELECT p.id, p."capacityGiB" - p."diskReservedGiB" AS free,
        p."capacityGiB" AS capacity, p."diskReservedGiB" AS reserved
      FROM sandbox_host_storage_pool p
      WHERE p."sandboxHostId" = h.id AND p."userId" = h."userId"
        AND p."connectionEpoch" = h."connectionEpoch" AND p."newRootsAllowed"
        AND p.health = 'healthy' AND NOT p.draining
        AND p."reportedAt" BETWEEN ${storageOldest} AND ${now}
      ORDER BY p."capacityGiB" - p."diskReservedGiB" DESC, p.marker ASC LIMIT 1
    ) storage ON true
    LEFT JOIN LATERAL (
      SELECT COALESCE(sum(p."chargedMemoryMiB"::bigint), 0)::bigint AS memory,
        COALESCE(sum(p."chargedVcpu"::bigint), 0)::bigint AS vcpu,
        count(*) FILTER (WHERE p.id IS NULL OR p."chargedMemoryMiB" IS NULL OR p."chargedVcpu" IS NULL)::int AS incomplete
      FROM sandbox_instance s LEFT JOIN sandbox_placement p
        ON p.id = s."currentPlacementId" AND p."sandboxId" = s.id AND p."userId" = s."userId"
      WHERE s."sandboxHostId" = h.id AND s."usagePoolId" = pool.id AND s."liveResourcesHeld"
    ) usage ON true`;
  const visible = PrismaValue.sql`m."poolId" = ${poolId} AND pool."deletedAt" IS NULL
      AND (pool."userId" = ${owner.ownerId} OR EXISTS (
        SELECT 1 FROM share sh WHERE sh."poolId" = pool.id AND sh."granteeUserId" = ${owner.ownerId} AND sh."canUse"))
      AND host_owner."deletionRequestedAt" IS NULL
      AND (host_owner.banned IS NOT TRUE OR host_owner."banExpires" <= ${now})
      AND m."removedAt" IS NULL
      AND (${allHosts} OR h.id = ANY(${hostIds}::text[]) OR h."userId" <> ${owner.ownerId})
      AND (${q.selectedId ?? null}::text IS NULL OR h.id = ${q.selectedId ?? null})
      AND NOT (h.id = ANY(${excluded}::text[]))`;
  const stages: Record<PlacementStage, Prisma.Sql> = {
    enabled: PrismaValue.sql`m.enabled = true`,
    compatible: PrismaValue.sql`(h."admissionRuntime" IN ('FAKE', 'INCUS_KVM')
        AND h."egressEnforcement" = true AND (h."daemonFeatures"->'egressPolicy') = 'true'::jsonb)`,
    builder: builder ? builder.admits : PrismaValue.sql`TRUE`,
    startup: q.startup
      ? PrismaValue.sql`COALESCE((h."daemonFeatures"->'templateStartup') = 'true'::jsonb, false)`
      : PrismaValue.sql`TRUE`,
    tunnel: q.tunnel
      ? PrismaValue.sql`(h."daemonTunnelPorts" AND h."daemonTunnel" IS NOT NULL AND (h."userId" = ${owner.ownerId}
          OR COALESCE((h."daemonTunnel"->'allowForOthers') = 'true'::jsonb, false)))`
      : PrismaValue.sql`TRUE`,
    credentialOwner: credentialOwnerSql(q.credential, owner.ownerId),
    // Extended (image distribution): known here, OR fetchable to this host.
    templateKnown: PrismaValue.sql`(EXISTS (SELECT 1 FROM sandbox_template_availability a
          WHERE a."hostId" = h.id AND a."userId" = ${owner.ownerId}
            AND a."revisionId" = ${revision.id}
            AND a."localFingerprint" = ${revision.incusFingerprint}
            AND a.architecture = ${revision.architecture}
            AND a."manifestDigest" = ${revision.manifestDigest})
          OR ${fetchableStaticSql(q.plan ?? null, owner.ownerId)})`,
    online: PrismaValue.sql`(h.status = 'CONNECTED' AND h."lastHeartbeatAt" BETWEEN ${oldest} AND ${now}
        AND h.draining = false AND h."deletionRequestedAt" IS NULL AND h."quarantinedAt" IS NULL
        AND h."daemonSchedulable" = true AND h."daemonVcpuBudget" IS NOT NULL
        AND h."daemonMemoryBudgetMiB" IS NOT NULL AND h."daemonMaxCpuCount" IS NOT NULL
        AND h."admissionEpoch" = h."connectionEpoch"
        AND h."inventoryAcknowledgedEpoch" = h."connectionEpoch"
        AND h."journalKeyVersion" = 1 AND h."journalKeyId" = ${keyId}
        AND h."journalKeyAcknowledgedEpoch" = h."connectionEpoch")`,
    // M11/M18: an active egress guard lease (server clock), both modes;
    // `egressGuardLeased` (egress-guard.ts) is the same predicate.
    guard: PrismaValue.sql`(h."daemonEgressGuardOk" = true
        AND h."daemonEgressGuardEpoch" = h."connectionEpoch"
        AND h."daemonEgressGuardLeaseUntil" > ${now})`,
    credentialCapability: credentialCapabilitySql(q.credential),
    // Extended: verified on this connection, OR a fetch is admissible now.
    // A distributed foreign copy is reused only while its access holds (round-2 P1-1).
    templateCurrent: PrismaValue.sql`((EXISTS (SELECT 1 FROM sandbox_template_availability a
          WHERE a."hostId" = h.id AND a."userId" = ${owner.ownerId}
            AND a."revisionId" = ${revision.id} AND a.status = 'AVAILABLE'
            AND a."verifiedConnectionEpoch" = h."connectionEpoch")
            AND ${foreignCopyUsableSql(owner.ownerId, revision.incusFingerprint)})
          OR ${fetchableCurrentSql(q.plan ?? null, owner.ownerId, now, PrismaValue.raw("h"), PrismaValue.sql`pool."userId"`, PrismaValue.sql`pool."memberImageCacheMaxGiB"`)})`,
    lease: leaseFitsSql(lease, owner.ownerId, deployment),
    perVm: PrismaValue.sql`(${size.cpuCount} <= h."daemonMaxCpuCount"
        AND ${size.memoryMiB} <= LEAST(${VM_SIZE_LIMITS.memoryMiBMax}, h."daemonMemoryBudgetMiB" - ${VM_SIZE_LIMITS.vmHostOverheadMiB})
        AND EXISTS (SELECT 1 FROM sandbox_host_storage_pool p
          WHERE p."sandboxHostId" = h.id AND p."userId" = h."userId"
            AND p."connectionEpoch" = h."connectionEpoch"
            AND p."capacityGiB" >= ${root}))`,
    storagePresent: PrismaValue.sql`storage.id IS NOT NULL`,
    ram: PrismaValue.sql`h."memoryReservedMiB"::bigint + ${charge}::bigint <= h."daemonMemoryBudgetMiB"`,
    ceiling: PrismaValue.sql`h."rootCount" < ${VM_SIZE_LIMITS.hostManagedSandboxCeiling}`,
    vcpu: PrismaValue.sql`h."vcpuReserved" + ${size.cpuCount} <= h."daemonVcpuBudget"`,
    disk: PrismaValue.sql`storage.free >= ${root}`,
    memberMemory: PrismaValue.sql`(usage.incomplete = 0 AND (h."userId" = pool."userId" OR m."memoryCapPercent" IS NULL
        OR usage.memory + ${charge}::bigint <= (h."daemonMemoryBudgetMiB"::bigint * m."memoryCapPercent" / 100)))`,
    memberVcpu: PrismaValue.sql`(h."userId" = pool."userId" OR m."vcpuCapPercent" IS NULL
        OR usage.vcpu + ${size.cpuCount}::bigint <= (h."daemonVcpuBudget"::bigint * m."vcpuCapPercent" / 100))`,
  };
  /** The request fits an EMPTY host within its member caps (static). */
  const fitsEmpty = PrismaValue.sql`(${charge}::bigint <= h."daemonMemoryBudgetMiB"
        AND ${size.cpuCount} <= h."daemonVcpuBudget"
        AND (h."userId" = pool."userId" OR m."memoryCapPercent" IS NULL
          OR ${charge}::bigint <= (h."daemonMemoryBudgetMiB"::bigint * m."memoryCapPercent" / 100))
        AND (h."userId" = pool."userId" OR m."vcpuCapPercent" IS NULL
          OR ${size.cpuCount}::bigint <= (h."daemonVcpuBudget"::bigint * m."vcpuCapPercent" / 100)))`;
  /** Dominant resource share after this request (memory, vCPU, the storage
   * pool the root is charged to); `capacity-view.ts` mirrors it in TS. */
  const dominantShare = PrismaValue.sql`GREATEST(
      (h."memoryReservedMiB"::float8 + ${charge}) / NULLIF(h."daemonMemoryBudgetMiB", 0),
      (h."vcpuReserved"::float8 + ${size.cpuCount}) / NULLIF(h."daemonVcpuBudget", 0),
      (storage.reserved::float8 + ${root}) / NULLIF(storage.capacity, 0))`;
  const where = (include: readonly PlacementStage[]) =>
    AND([visible, ...include.map((stage) => PrismaValue.sql`(${stages[stage]})`)]);
  /** The host would grant this viewer open egress (§1.3): a soft rank only,
   * never a filter. Own capable hosts always satisfy it. NULL-safe: a host
   * without the feature key is simply not open-capable. */
  const egressOpenOk = PrismaValue.sql`COALESCE((h."daemonFeatures"->'egressOpen') = 'true'::jsonb
      AND (h."userId" = ${owner.ownerId} OR h."daemonOpenEgressForOthers"), false)`;
  return {
    from,
    visible,
    stages,
    fitsEmpty,
    dominantShare,
    egressOpenOk,
    where,
    charge,
    root,
    builder,
  };
}

/** Best host: own-hosts tier (pool preference), then (open requests only)
 * hosts that would grant open egress, then hosts that already have
 * the image on their current connection, then the lowest dominant
 * share after placement, then memory share, then host id. `lastPlacedAt` is
 * observability only. The WHERE stages exclude zero budgets and missing
 * storage, so the NULLIF guards never change a selected host's rank. */
function selectCandidate(tx: Prisma.TransactionClient, q: PlacementQuery) {
  return selectPoolTarget(tx, q);
}

export type PoolTargetCandidate = { id: string; memberId: string; hostOwnerId: string };

/** Candidates one page of a filtered selection reads (restore admission). */
const FILTERED_CANDIDATES_PAGE = 16;

/**
 * Authorization-neutral pool target selection:
 * the best member host of `q.poolId` that passes `stages` (every stage by
 * default) under the viewer's visibility and host filter, ranked as
 * placement ranks. With `admit`, candidates are read in ranked pages of
 * `FILTERED_CANDIDATES_PAGE` and the first one `admit` accepts is returned
 * (restore applies `restoreHostEligibility` and the requester's destination
 * grants there): an ineligible head of the ranking never hides an eligible
 * host behind it. The scan is bounded by the pool membership bound
 * (`MAX_ACTIVE_POOL_MEMBERSHIPS`); `where` narrows candidates in SQL first.
 * Takes no lock and authorizes nothing: create calls it through
 * `resolvePlacement`, which authorizes the pool and host first.
 */
export async function selectPoolTarget(
  tx: Prisma.TransactionClient,
  q: PlacementQuery,
  options: {
    stages?: readonly PlacementStage[];
    admit?: (candidate: PoolTargetCandidate) => Promise<boolean>;
    where?: Prisma.Sql;
  } = {},
): Promise<PoolTargetCandidate | undefined> {
  const sql = placementSql(q);
  const limit = options.admit ? FILTERED_CANDIDATES_PAGE : 1;
  const extra = options.where ?? PrismaValue.sql`TRUE`;
  for (let offset = 0; offset < MAX_ACTIVE_POOL_MEMBERSHIPS; offset += limit) {
    const rows = await tx.$queryRaw<PoolTargetCandidate[]>`
      SELECT h.id, m.id AS "memberId", h."userId" AS "hostOwnerId" ${sql.from}
      WHERE ${sql.where(options.stages ?? PLACEMENT_STAGES)} AND ${extra}
      ORDER BY (CASE WHEN (pool."preferOwnHosts" OR ${q.credential?.hasCreds === true})
          AND h."userId" = ${q.viewer.ownerId} THEN 0 ELSE 1 END),
        (CASE WHEN ${q.egressMode === "open"} AND NOT ${sql.egressOpenOk} THEN 1 ELSE 0 END),
        ${hasCurrentImageSql(q.viewer.ownerId, q.revision.id)} ASC,
        ${sql.dominantShare} ASC NULLS LAST,
        (h."memoryReservedMiB"::float8 + ${sql.charge}) / NULLIF(h."daemonMemoryBudgetMiB", 0) ASC NULLS LAST,
        h.id ASC LIMIT ${limit} OFFSET ${offset}`;
    if (!options.admit) return rows[0];
    for (const row of rows) if (await options.admit(row)) return row;
    if (rows.length < limit) return undefined;
  }
  return undefined;
}

async function candidateExists(
  tx: Prisma.TransactionClient,
  q: PlacementQuery,
  include: readonly PlacementStage[],
): Promise<boolean> {
  const sql = placementSql(q);
  const rows = await tx.$queryRaw<{ ok: number }[]>`
    SELECT 1 AS ok ${sql.from} WHERE ${sql.where(include)} LIMIT 1`;
  return rows.length > 0;
}

/** Largest finite lease over the hosts passing `include` (never the lease
 * stage), with the same visibility and key predicates as selection. */
async function maxPathLimit(
  tx: Prisma.TransactionClient,
  q: PlacementQuery,
  include: readonly PlacementStage[],
): Promise<number> {
  const sql = placementSql(q);
  const rows = await tx.$queryRaw<{ max: number | null }[]>`
    SELECT max(${pathLimitSql(deploymentLeaseMaxMs())}) AS max ${sql.from} WHERE ${sql.where(include)}`;
  const value = rows[0]?.max;
  return value == null ? deploymentFiniteMaxMs() : Number(value);
}

const SKIPPED_REASONS = [
  "template_startup",
  "template_unavailable",
  "lease_policy",
  "vm_size",
  "credential_policy",
] as const;
export type SkippedReason = (typeof SKIPPED_REASONS)[number];

/** Static exclusions among hosts the caller can see (stage-0 visibility,
 * including the key host filter): booleans only, never counts, and never
 * online status (no connectivity predicate is evaluated). */
async function skippedReasons(
  tx: Prisma.TransactionClient,
  q: PlacementQuery,
): Promise<SkippedReason[]> {
  const sql = placementSql({ ...q, selectedId: null, excludedHostIds: [] });
  const startup = PrismaValue.sql`COALESCE((${sql.stages.startup}), false)`;
  const known = PrismaValue.sql`COALESCE((${sql.stages.templateKnown}), false)`;
  const lease = PrismaValue.sql`COALESCE((${sql.stages.lease}), false)`;
  const perVm = PrismaValue.sql`COALESCE((${sql.stages.perVm}), false)`;
  const credential = PrismaValue.sql`COALESCE((${sql.stages.credentialOwner}), false)`;
  const rows = await tx.$queryRaw<
    {
      startup: boolean | null;
      template: boolean | null;
      lease: boolean | null;
      vm: boolean | null;
      credential: boolean | null;
    }[]
  >`SELECT bool_or(NOT ${startup}) AS startup, bool_or(${startup} AND NOT ${known}) AS template,
      bool_or(${startup} AND ${known} AND NOT ${lease}) AS lease,
      bool_or(${startup} AND ${known} AND ${lease} AND NOT ${perVm}) AS vm,
      bool_or(NOT ${credential}) AS credential
    ${sql.from} WHERE ${sql.where(["enabled", "compatible", "builder"])}`;
  const row = rows[0];
  return [
    ...(row?.startup ? (["template_startup"] as const) : []),
    ...(row?.template ? (["template_unavailable"] as const) : []),
    ...(row?.lease ? (["lease_policy"] as const) : []),
    ...(row?.vm ? (["vm_size"] as const) : []),
    ...(row?.credential ? (["credential_policy"] as const) : []),
  ];
}

/** Build refusal hints (§3.3) over visible, enabled, compatible hosts: some
 * host does not offer builds, is ruled out by the capture policy, or has a
 * lease too short. Booleans only, never counts (the `skippedReasons` rule). */
async function buildSkipped(
  tx: Prisma.TransactionClient,
  q: PlacementQuery,
): Promise<BuildSkipped> {
  const sql = placementSql({ ...q, selectedId: null, excludedHostIds: [] });
  if (!sql.builder) return { builder: false, capture_policy: false, lease: false };
  const offers = PrismaValue.sql`COALESCE((${sql.builder.offers}), false)`;
  const admits = PrismaValue.sql`COALESCE((${sql.builder.admits}), false)`;
  const lease = PrismaValue.sql`COALESCE((${sql.stages.lease}), false)`;
  const rows = await tx.$queryRaw<
    { builder: boolean | null; policy: boolean | null; lease: boolean | null }[]
  >`SELECT bool_or(NOT ${offers}) AS builder,
      bool_or(${offers} AND NOT ${admits}) AS policy,
      bool_or(${admits} AND NOT ${lease}) AS lease
    ${sql.from} WHERE ${sql.where(["enabled", "compatible"])}`;
  const row = rows[0];
  return {
    builder: row?.builder === true,
    capture_policy: row?.policy === true,
    lease: row?.lease === true,
  };
}

/** Could this request ever place in the pool (§4.1 waitable vs not)? */
async function staticallyFeasible(
  tx: Prisma.TransactionClient,
  q: PlacementQuery,
): Promise<boolean> {
  const sql = placementSql({ ...q, selectedId: null, excludedHostIds: [] });
  const rows = await tx.$queryRaw<{ ok: number }[]>`
    SELECT 1 AS ok ${sql.from} WHERE ${sql.where(STATIC_STAGES)} AND ${sql.fitsEmpty} LIMIT 1`;
  return rows.length > 0;
}

/** Hosts the caller sees that pass `include` (bounded by pool membership). */
export async function eligibleHostIds(
  tx: Prisma.TransactionClient,
  q: PlacementQuery,
  include: readonly PlacementStage[],
  extra: Prisma.Sql = PrismaValue.sql`TRUE`,
): Promise<string[]> {
  const sql = placementSql(q);
  const rows = await tx.$queryRaw<{ id: string }[]>`
    SELECT h.id ${sql.from} WHERE ${sql.where(include)} AND ${extra}
    ORDER BY h.id LIMIT ${MAX_ACTIVE_POOL_MEMBERSHIPS}`;
  return rows.map((row) => row.id);
}

/** Thrown for a waitable refusal when the gate held back the only fitting hosts. */
export function poolReserved(skipped: readonly SkippedReason[] = []) {
  // A fitting host exists and is held for an older head: retryable.
  return poolFull("reserved", true, skipped);
}

type PlacementInput = {
  sandboxHostId?: string;
  poolId?: string;
  template: string;
  /** CLI logins (§8): computed by the caller from rows read in this transaction. */
  credential?: CredentialPlacementContext | null;
} & VmSizeOverrides & {
    diskGiB?: number;
    expectedDisconnectGraceSeconds?: number;
    timeoutMs?: number;
    /** Requested egress mode (ranking only; the effective mode is resolved at materialization). */
    egressMode?: EgressMode;
    /** Preview tunnels: the create declares tunnel ports (the `tunnel` stage). */
    tunnel?: boolean;
  };

/** Pool context resolved under User → G, before any host is chosen. */
export type PoolPlacementContext = {
  poolId: string;
  pool: { userId: string; disconnectGraceSeconds: number };
  shareId: string | null;
  revision: Awaited<ReturnType<typeof resolveTemplateRevision>>;
  size: VmSize;
  added: { memoryMiB: bigint; vcpu: bigint; diskGiB: bigint };
  leaseRequest: LeaseRequest;
  sampledAt: Date;
};

/** The queue gate (§4.3), evaluated under G for this request. */
export type PlacementGate = (
  tx: Prisma.TransactionClient,
  context: PoolPlacementContext,
) => Promise<{
  excludedHostIds: readonly string[];
  /** Under H of the chosen host: charge bypasses or throw PlacementChanged. */
  accept(hostId: string): Promise<void>;
}>;

/** Last blocker recorded on a waiting entry (`lastBlocker`). */
export type CapacityBlocker =
  | "ram"
  | "vcpu"
  | "disk"
  | "storage"
  | "ceiling"
  | "reserved"
  | "member_quota"
  | "share_quota"
  | "unavailable"
  /** The image is gone everywhere and a rebuild of its recipe runs (§3.9). */
  | "image_rebuilding";

export type WaitablePlacement = {
  kind: "waitable";
  refusal: ORPCError<string, unknown>;
  blocker: CapacityBlocker;
  context: PoolPlacementContext;
};

/** The waitable classification of a pool refusal (§4.1), or null. */
export function waitableBlocker(error: unknown): CapacityBlocker | null {
  if (!(error instanceof ORPCError)) return null;
  const data = error.data as { code?: unknown; reason?: unknown } | undefined;
  switch (data?.code) {
    case "sandbox.pool_full":
      return (
        (["ram", "vcpu", "disk", "storage", "ceiling", "reserved"] as const).find(
          (reason) => reason === data.reason,
        ) ?? null
      );
    case "sandbox.member_quota":
      return "member_quota";
    case "sandbox.share_quota":
      return "share_quota";
    case "UNSUPPORTED_CAPABILITY":
      return isEgressGuardRefusal(error) ? "unavailable" : null;
    case "sandbox.pool_unavailable":
    case "sandbox.template_image_missing":
    case "lease_exceeds_policy":
    case "sandbox.vm_size_unsupported":
      return "unavailable";
    default:
      return null;
  }
}

/** The pool-level guard refusal (`egressRefused("egress_guard_unavailable")`). */
export function isEgressGuardRefusal(error: unknown): boolean {
  if (!(error instanceof ORPCError)) return false;
  const data = error.data as { code?: unknown; reason?: unknown } | undefined;
  return data?.code === "UNSUPPORTED_CAPABILITY" && data.reason === "egress_guard_unavailable";
}

/** Refusals a waiting request can never outwait (not waitable, or
 * statically infeasible): the queue ends the wait instead of retrying. */
const staticRefusals = new WeakSet<object>();
export function isStaticRefusal(error: unknown): boolean {
  return typeof error === "object" && error !== null && staticRefusals.has(error);
}

/** A share cap smaller than the request can never be satisfied by waiting. */
function exceedsShareCaps(
  share: { maxMemoryMiB: number | null; maxVcpu: number | null; maxDiskGiB: number | null } | null,
  added: PoolPlacementContext["added"],
) {
  return Boolean(
    share &&
      ((share.maxMemoryMiB !== null && added.memoryMiB > BigInt(share.maxMemoryMiB)) ||
        (share.maxVcpu !== null && added.vcpu > BigInt(share.maxVcpu)) ||
        (share.maxDiskGiB !== null && added.diskGiB > BigInt(share.maxDiskGiB))),
  );
}

export type PlacedResult = Awaited<ReturnType<typeof resolveDirectPlacement>> & {
  hostId: string;
  poolId: string | null;
  memberId: string | null;
  poolOwnerId: string | null;
  originShareId: string | null;
  acceptedGraceSeconds: number;
};

export async function resolvePlacement(
  tx: Prisma.TransactionClient,
  owner: Principal,
  input: PlacementInput,
  options?: { gate?: PlacementGate; allowWait?: false; buildId?: string | null },
): Promise<PlacedResult>;
/** `rebuildOnMiss` (a new waiting create only): a tag whose context-free
 * BUILD revision is gone everywhere starts or joins its rebuild and waits
 * with blocker `image_rebuilding` (template-builds §3.9). */
export async function resolvePlacement(
  tx: Prisma.TransactionClient,
  owner: Principal,
  input: PlacementInput,
  options: {
    gate?: PlacementGate;
    allowWait: true;
    buildId?: string | null;
    rebuildOnMiss?: boolean;
  },
): Promise<PlacedResult | WaitablePlacement>;
export async function resolvePlacement(
  tx: Prisma.TransactionClient,
  owner: Principal,
  input: PlacementInput,
  options: {
    gate?: PlacementGate;
    allowWait?: boolean;
    buildId?: string | null;
    rebuildOnMiss?: boolean;
  } = {},
): Promise<PlacedResult | WaitablePlacement> {
  if ((input.poolId === undefined) === (input.sandboxHostId === undefined))
    throw new ORPCError("BAD_REQUEST", { message: "Choose exactly one placement target." });
  const leaseRequest = leaseRequestOf(input.timeoutMs ?? LEASE_DEFAULT_MS);
  // The deployment layer needs no row: refuse before taking any lock.
  requireLeaseWithinPolicy(leaseRequest, deploymentPathLimit());
  if (input.sandboxHostId !== undefined) {
    const resolved = await resolveDirectPlacement(
      tx,
      owner,
      input.sandboxHostId,
      input.template,
      null,
      undefined,
      inputSizeOverrides(input),
      undefined,
      input.credential ?? null,
    );
    // A direct target is always an own host: only `image.build` matters.
    // Owner placement and H are held, so the build inputs and the host's
    // features cannot change before commit.
    if (options.buildId) {
      await requireBuildPlacement(tx, owner.ownerId, options.buildId);
      const host = await tx.sandboxHost.findFirst({
        where: { id: input.sandboxHostId, userId: owner.ownerId },
        select: { daemonFeatures: true },
      });
      if (hostImageFeatures(host?.daemonFeatures ?? null)?.build !== true)
        throw buildNoBuilder({ builder: true, capture_policy: false, lease: false });
    }
    // The `startup` stage on a direct target. H is held and the host's
    // admission is current (resolveDirectPlacement), so its features are
    // positive current-epoch evidence and cannot change before commit.
    if (await revisionNeedsStartup(tx, owner.ownerId, resolved.revision.id, options.buildId)) {
      const host = await tx.sandboxHost.findFirst({
        where: { id: input.sandboxHostId, userId: owner.ownerId },
        select: { daemonFeatures: true },
      });
      if (!hostAdmitsTemplateStartup(host?.daemonFeatures ?? null))
        throw unsupportedCapability("template_startup");
    }
    // Preview tunnels on a direct (own) target: a verified client.
    if (input.tunnel === true) {
      const host = await tx.sandboxHost.findFirst({
        where: { id: input.sandboxHostId, userId: owner.ownerId },
        select: { daemonTunnel: true, daemonTunnelPorts: true },
      });
      if (!host?.daemonTunnel || !host.daemonTunnelPorts)
        throw tunnelRefused("tunnel_host_unsupported");
    }
    // H is held (resolveDirectPlacement → lockAdmissionHost): the host
    // ceiling cannot change before commit. No pool path on a direct target.
    const limit = effectiveLeaseLimit({
      deployment: deploymentLeaseMaxMs(),
      host: resolved.hostMaxLeaseMs,
      pool: null,
      memberMaxLeaseMs: null,
      requesterId: owner.ownerId,
    });
    if (options.buildId) {
      try {
        requireLeaseWithinPolicy(leaseRequest, limit);
      } catch {
        throw buildNoBuilder({ builder: false, capture_policy: false, lease: true });
      }
    } else requireLeaseWithinPolicy(leaseRequest, limit);
    return {
      ...resolved,
      hostId: input.sandboxHostId,
      poolId: null,
      memberId: null,
      poolOwnerId: null,
      originShareId: null,
      acceptedGraceSeconds: 0,
    };
  }
  const poolId = input.poolId;
  if (!poolId) throw new ORPCError("BAD_REQUEST");
  await lockOwnerPlacement(tx, owner.ownerId);
  await lockPoolGraph(tx, [poolId]);
  const context = await requirePoolShareAcquisition(tx, owner, poolId, {
    memoryMiB: 0n,
    vcpu: 0n,
    diskGiB: 0n,
  });
  if (
    input.expectedDisconnectGraceSeconds !== undefined &&
    context.pool.disconnectGraceSeconds < input.expectedDisconnectGraceSeconds
  )
    throw new ORPCError("CONFLICT", {
      data: { code: "sandbox.pool_policy_changed" },
      message: "Pool grace decreased. Review the policy before retrying.",
    });
  const revision = await resolveTemplateRevision(tx, owner, input.template);
  const size = resolveVmSize(
    {
      cpuCount: revision.cpuCount,
      memoryMiB: revision.memoryMiB,
      diskGiB: revision.defaultDiskGiB,
    },
    inputSizeOverrides(input),
  );
  assertDiskFitsImage(revision, size.diskGiB);
  const added = {
    memoryMiB: BigInt(vmLiveMemoryChargeMiB(size.memoryMiB)),
    vcpu: BigInt(size.cpuCount),
    diskGiB: BigInt(vmRootChargeGiB(size.diskGiB)),
  };
  const sampledAt = await hostDatabaseNow(tx);
  const placementContext: PoolPlacementContext = {
    poolId,
    pool: context.pool,
    shareId: context.share?.id ?? null,
    revision,
    size,
    added,
    leaseRequest,
    sampledAt,
  };
  const query: PlacementQuery = {
    viewer: viewerOf(owner),
    poolId,
    revision,
    size,
    now: sampledAt,
    lease: leaseRequest,
    plan: await imageFetchPlan(tx, owner.ownerId, revision),
    // Read under owner placement (held since above), like every placement input.
    build: options.buildId ? await requireBuildPlacement(tx, owner.ownerId, options.buildId) : null,
    startup: await revisionNeedsStartup(tx, owner.ownerId, revision.id, options.buildId),
    credential: input.credential ?? null,
    egressMode: input.egressMode,
    tunnel: input.tunnel === true,
  };
  let feasible: Promise<boolean> | undefined;
  /** Static feasibility (§4.1), read at most once per placement attempt. */
  const isFeasible = () => (feasible ??= staticallyFeasible(tx, query));
  /**
   * A refusal becomes a wait only when the request could ever place (§4.1).
   * The same classification is the public `retryable` flag of every
   * capacity/quota/pool refusal, waiting requested or not.
   */
  const refuse = async (raw: unknown): Promise<WaitablePlacement> => {
    if (!(raw instanceof ORPCError)) throw raw;
    const code = (raw.data as { code?: unknown } | undefined)?.code;
    const classified = typeof code === "string" && isRetryableRefusalCode(code);
    if (!options.allowWait && !classified) throw raw;
    const blocker = waitableBlocker(raw);
    const permanent = !blocker || exceedsShareCaps(context.share, added) || !(await isFeasible());
    const error = classified ? withRetryable(raw, !permanent) : raw;
    if (!options.allowWait) throw error;
    if (permanent) {
      staticRefusals.add(error);
      throw error;
    }
    return { kind: "waitable", refusal: error, blocker, context: placementContext };
  };
  if (options.allowWait && options.rebuildOnMiss) {
    // Owner admission (the create's User lock) and owner placement are held.
    const rebuild = await rebuildOnMissLocked(tx, owner, input.template, revision, {
      retryFailed: true,
      now: sampledAt,
    });
    // The tag moved past a finished rebuild: resolve it again.
    if (rebuild.kind === "rebuilt") throw new PlacementChanged();
    if (rebuild.kind === "refused") throw rebuildRefusal(rebuild);
    if (rebuild.kind === "rebuilding")
      return {
        kind: "waitable",
        refusal: rebuildRefusal(rebuild),
        blocker: "image_rebuilding",
        context: placementContext,
      };
  }
  try {
    await requirePoolShareAcquisition(tx, owner, poolId, added);
  } catch (error) {
    return refuse(error);
  }
  const gate = options.gate ? await options.gate(tx, placementContext) : null;
  const excludedHostIds = gate?.excludedHostIds ?? [];
  const selected = await selectCandidate(tx, { ...query, excludedHostIds });
  if (!selected) {
    try {
      if (excludedHostIds.length > 0 && (await selectCandidate(tx, query)))
        throw poolReserved(await skippedReasons(tx, query));
      await placementCascade(tx, query, isFeasible);
    } catch (error) {
      return refuse(error);
    }
    throw new PlacementChanged();
  }
  requirePlacementPrincipals(tx, [owner.ownerId, context.pool.userId, selected.hostOwnerId]);
  // Owner was proven in the candidate JOIN, before taking exactly one H.
  const locked = await tx.$queryRaw<
    { id: string }[]
  >`SELECT id FROM sandbox_host WHERE id = ${selected.id} AND "userId" = ${selected.hostOwnerId} FOR UPDATE`;
  const observedAt = await hostDatabaseNow(tx);
  if (
    !locked[0] ||
    !(await candidateExists(
      tx,
      { ...query, now: observedAt, selectedId: selected.id, excludedHostIds },
      PLACEMENT_STAGES,
    ))
  )
    throw new PlacementChanged();
  await requirePoolMemberAcquisition(
    tx,
    {
      poolId,
      memberId: selected.memberId,
      hostId: selected.id,
      hostOwnerId: selected.hostOwnerId,
      newRoot: true,
    },
    added,
  );
  try {
    await gate?.accept(selected.id);
  } catch (error) {
    // The chosen host is reserved for an older head: a waitable refusal.
    if (waitableBlocker(error) === "reserved") return refuse(error);
    throw error;
  }
  // Reuse 3E's exact launch admission and parent locks, with pooled authority.
  const pinned = await poolHostRecheck(poolId, () =>
    resolveDirectPlacement(
      tx,
      owner,
      selected.id,
      `revision/${revision.id}`,
      poolId,
      observedAt,
      inputSizeOverrides(input),
      { revision, size },
      input.credential ?? null,
    ),
  );
  return {
    ...pinned,
    hostId: selected.id,
    poolId,
    memberId: selected.memberId,
    poolOwnerId: context.pool.userId,
    originShareId: context.share?.id ?? null,
    acceptedGraceSeconds: context.pool.disconnectGraceSeconds,
  };
}

/** Diagnose why no host passes every stage; always throws. Capacity refusals
 * carry the static `skipped` hints (§3), computed over visible hosts only. */
async function placementCascade(
  tx: Prisma.TransactionClient,
  query: PlacementQuery,
  feasible: () => Promise<boolean>,
) {
  const passes = (stage: PlacementStage | null) => candidateExists(tx, query, stagesThrough(stage));
  const skipped = () => skippedReasons(tx, query);
  if (!(await passes(null))) throw new ORPCError("FORBIDDEN");
  // Every visible member is disabled: configuration, never outwaited.
  if (!(await passes("enabled"))) throw poolUnavailable(false);
  if (!(await passes("compatible"))) throw poolNoCompatibleHost();
  if (!(await passes("builder"))) throw buildNoBuilder(await buildSkipped(tx, query));
  // No visible host runs start/ready commands: static, like `compatible`.
  if (!(await passes("startup"))) throw poolNoCompatibleHost();
  // No visible host runs tunnels for this owner: typed, never a wait.
  if (!(await passes("tunnel"))) throw tunnelRefused("tunnel_no_host");
  if (!(await passes("credentialOwner"))) throw credentialError("credential.host_forbidden");
  if (!(await passes("templateKnown"))) throw templateUnavailable();
  if (!(await passes("online"))) throw poolUnavailable(await feasible(), await skipped());
  // Online members exist but none holds an active egress guard lease. A
  // fresh create refuses (admitCapacityWait never queues it); a waiting
  // create keeps waiting (`unavailable`).
  if (!(await passes("guard"))) throw egressRefused("egress_guard_unavailable");
  // Waitable: a daemon upgrade can bring the capability.
  if (!(await passes("credentialCapability")))
    throw poolUnavailable(await feasible(), await skipped());
  if (!(await passes("templateCurrent"))) throw templateImageMissing();
  if (!(await passes("lease")))
    throw query.build
      ? buildNoBuilder(await buildSkipped(tx, query))
      : leaseExceedsPolicy(await maxPathLimit(tx, query, stagesThrough("templateCurrent")));
  if (!(await passes("perVm"))) throw vmSizeUnsupported();
  for (const [stage, reason] of [
    ["storagePresent", "storage"],
    ["ram", "ram"],
    ["ceiling", "ceiling"],
    ["vcpu", "vcpu"],
    ["disk", "disk"],
  ] as const)
    if (!(await passes(stage))) throw poolFull(reason, await feasible(), await skipped());
  for (const [stage, resource] of [
    ["memberMemory", "memory"],
    ["memberVcpu", "vcpu"],
  ] as const)
    if (!(await passes(stage))) throw memberQuota(resource, await feasible(), await skipped());
}

/** Final suffix, after outbox. G held through commit protects membership;
 * H protects availability. Recheck both predicates
 * rather than relying on SELECT FOR SHARE to re-evaluate a prior query (B-2). */
export async function lockPlacementSuffix(
  tx: Prisma.TransactionClient,
  owner: Principal,
  placement: PlacedResult,
) {
  const revision = placement.revision;
  if (placement.imageFetch) {
    // The placement relies on a fetch: lock the stored artifact (S3) or
    // re-check an owned current source (peer) at the availability position.
    if (
      !(await lockImageFetchSuffix(
        tx,
        owner.ownerId,
        placement.imageFetch,
        placement.hostId,
        await hostDatabaseNow(tx),
      ))
    )
      throw new PlacementChanged();
  }
  const availability = placement.imageFetch
    ? [{ id: "image-fetch" }]
    : await tx.$queryRaw<{ id: string }[]>`
    SELECT a.id FROM sandbox_template_availability a JOIN sandbox_host h ON h.id = a."hostId"
    WHERE a."revisionId" = ${revision.id} AND a."hostId" = ${placement.hostId}
      AND a."userId" = ${owner.ownerId} AND a."hostOwnerId" = ${placement.hostOwnerId} AND a.status = 'AVAILABLE'
      AND a."localFingerprint" = ${revision.incusFingerprint}
      AND a.architecture = ${revision.architecture} AND a."manifestDigest" = ${revision.manifestDigest}
      AND a."verifiedConnectionEpoch" = h."connectionEpoch"
      AND ${foreignCopyUsableSql(owner.ownerId, revision.incusFingerprint)} FOR SHARE OF a`;
  if (!availability[0]) throw new PlacementChanged();
  if (placement.memberId) {
    const member = await tx.$queryRaw<{ id: string }[]>`SELECT id FROM sandbox_pool_member
      WHERE id = ${placement.memberId} AND "userId" = ${placement.poolOwnerId}
        AND "hostOwnerId" = ${placement.hostOwnerId}
        AND "poolId" = ${placement.poolId} AND "sandboxHostId" = ${placement.hostId}
        AND enabled = true AND "removedAt" IS NULL FOR SHARE`;
    if (!member[0]) throw new PlacementChanged();
  }
}

function inputSizeOverrides(input: VmSizeOverrides & { diskGiB?: number }) {
  return { cpuCount: input.cpuCount, memoryMiB: input.memoryMiB, diskGiB: input.diskGiB };
}
