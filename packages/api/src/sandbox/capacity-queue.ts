import { randomUUID } from "node:crypto";
import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import { AccountDeletionConflictError } from "@wssp/db/account-deletion";
import { Prisma as PrismaValue } from "@wssp/db/client";
import {
  type CapacityWaitRequest,
  type CapacityWaitView,
  capacityReasonSchema,
  LEASE_UNLIMITED_DEADLINE_MS,
  type OperationErrorCode,
} from "@wssp/sandbox-contracts";
import { writeCreateAttachments } from "../credentials/launch";
import { sandboxCredentialPlacementContext } from "../credentials/placement";
import { claimCreateLeases } from "../credentials/resume";
import type { CredentialClaimRequest } from "../credentials/selection";
import { preflightCredentialSpec } from "../credentials/specs";
import {
  isOwnerCredentialPolicySatisfied,
  ownerCredentialPolicyUserSelect,
} from "../lib/owner-credential-policy";
import { authorizeServiceAction } from "../lib/sdk-key-access";
import { getForcedTwoFactorSettingsRecord } from "../lib/two-factor-policy";
import type { BuildRole } from "../template-builds/build-authority";
import { loadBuildPlacement } from "../template-builds/placement";
import { rebuildOnMissLocked } from "../template-builds/rebuild";
import { notifyTemplateBuildsChanged } from "../template-builds/wake";
import {
  CAPACITY_QUEUE_POOL_CEILING,
  deploymentQueuePerKey,
  deploymentQueuePerOwner,
  GATE_HEAD_MAX,
  HEAD_BYPASS_LIMIT,
  PASS_PLACEMENT_MAX,
  poolCapacityLimits,
  QUEUE_RECHECK_MS,
  QUEUE_SCAN_WINDOW,
  requireWaitWithinPolicy,
  waitDeadline,
} from "./capacity-limits";
import { type CapacityHint, noteCapacityChanged } from "./capacity-queue-wake";
import type { Principal } from "./contracts";
import { operationDigestContext } from "./digest-context";
import { lockOwnerPlacement } from "./direct-placement";
import type { OffloadPolicyColumns } from "./disk-offload/policy";
import { capacityQueueFull, sandboxStateConflict } from "./errors";
import { STORAGE_HEALTH_STALE_MS } from "./host-admission";
import { requestDigestMetadata } from "./idempotency";
import { imageFetchPlan } from "./image-placement";
import { defaultIncusInstanceName } from "./incus-name";
import { acceptedLaunchMode } from "./launch-mode";
import type { LeaseClock } from "./lease";
import { leaseRequestOf } from "./lease-policy";
import { sandboxOutboxTransaction } from "./outbox";
import {
  buildSandboxFields,
  type CreateIntent,
  materializePlacement,
} from "./placement-materialize";
import { lockPoolGraph, MAX_ACTIVE_POOL_MEMBERSHIPS } from "./pool-locks";
import {
  type CapacityBlocker,
  eligibleHostIds,
  isEgressGuardRefusal,
  isStaticRefusal,
  PlacementChanged,
  type PlacementGate,
  type PlacementQuery,
  type PlacementViewer,
  type PoolPlacementContext,
  placementSql,
  poolReserved,
  resolvePlacement,
  retryPlacement,
  revisionNeedsStartup,
  type WaitablePlacement,
  waitableBlocker,
} from "./pool-placement";
import { buildIdOf, isBrowserSession, recordedKeyIdOf, viewerOf } from "./principal-kinds";
import { hostDatabaseNow } from "./relay-fence";
import { resolveCreateSandboxName } from "./sandbox-names";
import { lockPlacementPrincipals } from "./sharing-authority";
import { resolveStoredPrincipal } from "./stored-principal";
import { resolveTemplateRevision } from "./template-resolution";

/**
 * Capacity queue (§4): pool creates that found no fitting host wait in a
 * per-pool FIFO by global `seq`, as a hostless WAITING_FOR_CAPACITY sandbox, a
 * QUEUED CREATE operation and a SandboxCapacityWait row. The placer runs one
 * placement per transaction under User → K → owner placement → G → H → S → O,
 * re-authorizing the creator at placement time. Every FAILED exit sets
 * `Sandbox.lastErrorCode`; a cancel leaves it NULL.
 */

/** Blockers that make an entry a protected head (pool resources only).
 * `unavailable` (offline/draining) and self-blocked `share_quota` never do. */
const HEAD_BLOCKERS = ["ram", "vcpu", "disk", "storage", "ceiling", "member_quota"] as const;

export type CapacityEntryPlan = PoolPlacementContext & {
  request: CapacityWaitRequest;
  blocker: CapacityBlocker;
  poolOwnerId: string;
};

type StoredIntent = CreateIntent & { expectedDisconnectGraceSeconds?: number };

/**
 * Entry limits, checked under the owner placement lock (owner and key
 * counts) and G (pool count), which `resolvePlacement` already holds, so two
 * concurrent enqueues can never both slip under a limit.
 */
/**
 * A NEW create's `waitForCapacityMs` against the effective (deployment and
 * pool) limit, whether it then waits or places at once: the same request is
 * never accepted or refused depending on momentary capacity, and the refusal
 * always quotes the effective max. Call only after `resolvePlacement` made
 * the pool visible and usable (under G), never for an already-waiting entry.
 */
export async function requireEntryWaitWithinPolicy(
  tx: Prisma.TransactionClient,
  poolId: string,
  request: CapacityWaitRequest,
) {
  const pool = await tx.sandboxPool.findUniqueOrThrow({
    where: { id: poolId },
    select: {
      userId: true,
      capacityWaitMaxMs: true,
      capacityQueuePerKeyMax: true,
      capacityQueuePerOwnerMax: true,
    },
  });
  requireWaitWithinPolicy(request, poolCapacityLimits(pool).maxWaitMs);
  return pool;
}

export async function admitCapacityWait(
  tx: Prisma.TransactionClient,
  owner: Principal,
  request: CapacityWaitRequest,
  waitable: WaitablePlacement,
): Promise<CapacityEntryPlan> {
  // Queue admission (§1.3, M11): online members exist but none holds an
  // active egress guard lease. Refuse instead of accepting a WAITING row.
  if (isEgressGuardRefusal(waitable.refusal)) throw waitable.refusal;
  const context = waitable.context;
  const pool = await requireEntryWaitWithinPolicy(tx, context.poolId, request);
  const keyId = recordedKeyIdOf(owner);
  const waiting = { state: "WAITING" as const };
  const [poolTotal, ownerAll, ownerPool, keyAll, keyPool] = await Promise.all([
    tx.sandboxCapacityWait.count({ where: { ...waiting, poolId: context.poolId } }),
    tx.sandboxCapacityWait.count({ where: { ...waiting, userId: owner.ownerId } }),
    tx.sandboxCapacityWait.count({
      where: { ...waiting, userId: owner.ownerId, poolId: context.poolId },
    }),
    keyId !== null
      ? tx.sandboxCapacityWait.count({ where: { ...waiting, authorizingKeyId: keyId } })
      : 0,
    keyId !== null
      ? tx.sandboxCapacityWait.count({
          where: { ...waiting, authorizingKeyId: keyId, poolId: context.poolId },
        })
      : 0,
  ]);
  const over = (count: number, limit: number | null) => limit !== null && count >= limit;
  const ownerLimits: [number, number | null][] = [
    [ownerAll, deploymentQueuePerOwner()],
    [ownerPool, pool.capacityQueuePerOwnerMax],
  ];
  const keyLimits: [number, number | null][] =
    keyId === null
      ? []
      : [
          [keyAll, deploymentQueuePerKey()],
          [keyPool, pool.capacityQueuePerKeyMax],
        ];
  // Retryable while waiting entries can drain. A layer limit of 0 never
  // admits a wait, whichever limit is reported first.
  const retryable = ![...ownerLimits, ...keyLimits].some(([, limit]) => limit === 0);
  if (poolTotal >= CAPACITY_QUEUE_POOL_CEILING) throw capacityQueueFull("pool", retryable);
  if (ownerLimits.some(([count, limit]) => over(count, limit)))
    throw capacityQueueFull("owner", retryable);
  if (keyLimits.some(([count, limit]) => over(count, limit)))
    throw capacityQueueFull("key", retryable);
  return { ...context, request, blocker: waitable.blocker, poolOwnerId: pool.userId };
}

/** Insert the waiting sandbox, its QUEUED CREATE operation and the wait row.
 * No execution config, placement, outbox row, hold or lease exists yet. */
export async function enqueueCapacityWait(
  tx: Prisma.TransactionClient,
  owner: Principal,
  plan: CapacityEntryPlan,
  intent: CreateIntent,
  ids: {
    idempotencyKey: string;
    bodyHash: () => string;
    /** The caller's name, or undefined to generate one (never in `CreateIntent`). */
    name?: string;
    expectedDisconnectGraceSeconds?: number;
    /** The requested offload policy, written at entry (never in `CreateIntent`). */
    offloadPolicy?: OffloadPolicyColumns;
    /** CLI logins named by the create: attachment rows written at entry. */
    credentials?: readonly CredentialClaimRequest[];
    /** A build principal's create role; a verify VM never waits (T4). */
    buildRole?: BuildRole;
  },
): Promise<string> {
  if (ids.buildRole === "verify") throw sandboxStateConflict();
  const now = await hostDatabaseNow(tx);
  const sandboxId = randomUUID();
  const authorizingKeyId = recordedKeyIdOf(owner);
  // Under lock 31 (resolvePlacement) and after authorization; the queue head's
  // materialize keeps this name.
  const name = await resolveCreateSandboxName(tx, owner.ownerId, ids.name);
  const sandbox = await tx.sandbox.create({
    data: {
      id: sandboxId,
      userId: owner.ownerId,
      name,
      templateId: plan.revision.templateId,
      templateRevisionId: plan.revision.id,
      cpuCount: plan.size.cpuCount,
      memoryMiB: plan.size.memoryMiB,
      diskGiB: plan.size.diskGiB,
      originalSelector: intent.originalSelector,
      originPoolId: plan.poolId,
      state: "WAITING_FOR_CAPACITY",
      // The accepted expiry action (lifecycle.onTimeout) is known at entry;
      // the lease deadline itself starts at placement.
      leaseExpireAction: intent.onExpire === "stop" ? "STOP" : "DESTROY",
      metadata: intent.metadata as Prisma.InputJsonValue,
      // The effective policy is resolved only at placement; until then the
      // NULL policy reads as deny-all (fail-safe).
      egressRequest: intent.egress.request as Prisma.InputJsonValue,
      tunnelEnabled: intent.tunnelPorts !== undefined,
      tunnelPorts: intent.tunnelPorts ?? [],
      ...(ids.offloadPolicy ?? {}),
      incusName: defaultIncusInstanceName(sandboxId),
      ...buildSandboxFields(owner, buildIdOf(owner) === null ? null : "build"),
    },
    select: { generation: true },
  });
  // CLI logins (§8): the queue head rebuilds its placement context from these
  // rows; the spec is preflighted now so an oversized one never waits.
  if (ids.credentials && ids.credentials.length > 0) {
    await writeCreateAttachments(tx, {
      ownerId: owner.ownerId,
      principal: owner,
      sandboxId,
      requests: ids.credentials,
    });
    await preflightCredentialSpec(tx, {
      sandboxId,
      credentialIds: ids.credentials.map((request) => request.credentialId),
    });
  }
  const operation = await tx.sandboxOperation.create({
    data: {
      authorizingKeyId,
      userId: owner.ownerId,
      sandboxId,
      kind: "CREATE_SANDBOX",
      launchMode: acceptedLaunchMode("CREATE_SANDBOX"),
      state: "QUEUED",
      generation: sandbox.generation,
      idempotencyKey: ids.idempotencyKey,
      requestBodyHash: ids.bodyHash(),
      digestContext: operationDigestContext(tx),
      ...requestDigestMetadata(),
    },
    select: { id: true },
  });
  const stored: StoredIntent = {
    ...intent,
    ...(ids.expectedDisconnectGraceSeconds !== undefined
      ? { expectedDisconnectGraceSeconds: ids.expectedDisconnectGraceSeconds }
      : {}),
  };
  await tx.sandboxCapacityWait.create({
    data: {
      userId: owner.ownerId,
      sandboxId,
      operationId: operation.id,
      poolId: plan.poolId,
      poolOwnerId: plan.poolOwnerId,
      authorizingKeyId,
      templateRevisionId: plan.revision.id,
      cpuCount: plan.size.cpuCount,
      memoryMiB: plan.size.memoryMiB,
      diskGiB: plan.size.diskGiB,
      chargedMemoryMiB: Number(plan.added.memoryMiB),
      rootChargeGiB: Number(plan.added.diskGiB),
      leaseTimeoutMs: intent.timeoutMs,
      leaseExpireAction: intent.onExpire === "stop" ? "STOP" : "DESTROY",
      intent: stored as unknown as Prisma.InputJsonValue,
      enqueuedAt: now,
      deadlineAt: waitDeadline(plan.request, now),
      lastBlocker: plan.blocker,
      lastEvaluatedAt: now,
    },
  });
  return sandboxId;
}

const headSelect = {
  id: true,
  seq: true,
  poolId: true,
  userId: true,
  authorizingKeyId: true,
  templateRevisionId: true,
  cpuCount: true,
  memoryMiB: true,
  diskGiB: true,
  leaseTimeoutMs: true,
  deadlineAt: true,
  bypassCount: true,
  // Immutable: a build create's placement query is rebuilt from it (§4).
  Sandbox: { select: { buildId: true, verifyBuildId: true, tunnelEnabled: true } },
  sandboxId: true,
} satisfies Prisma.SandboxCapacityWaitSelect;
type Head = Prisma.SandboxCapacityWaitGetPayload<{ select: typeof headSelect }>;

/** The head of every pool in `poolScope`: its oldest WAITING entry blocked
 * by a pool resource, older than the request, deadline not passed. */
function headsSql(poolScope: Prisma.Sql, requestSeq: bigint | null) {
  return PrismaValue.sql`SELECT DISTINCT ON (w."poolId") w.id, w."bypassCount"
    FROM sandbox_capacity_wait w
    WHERE w.state = 'WAITING' AND w."lastBlocker" = ANY(${[...HEAD_BLOCKERS]}::text[])
      AND (${requestSeq}::bigint IS NULL OR w.seq < ${requestSeq}::bigint)
      AND (w."deadlineAt" IS NULL OR w."deadlineAt" > (clock_timestamp() AT TIME ZONE 'UTC'))
      AND w."poolId" IN (${poolScope})
    ORDER BY w."poolId", w.seq`;
}

async function loadHeads(tx: Prisma.TransactionClient, ids: string[]): Promise<Head[]> {
  if (ids.length === 0) return [];
  return tx.sandboxCapacityWait.findMany({
    where: { id: { in: ids }, state: "WAITING" },
    select: headSelect,
    orderBy: { seq: "asc" },
    take: ids.length,
  });
}

/** Strict heads (bypasses spent) of every pool sharing a member host with
 * `poolId` (review M6), bounded by GATE_HEAD_MAX; any beyond are caught by
 * the per-host check in `accept`, which denies conservatively. */
async function strictHeadsNear(
  tx: Prisma.TransactionClient,
  poolId: string,
  requestSeq: bigint | null,
): Promise<Head[]> {
  const scope = PrismaValue.sql`SELECT other."poolId" FROM sandbox_pool_member mine
        JOIN sandbox_pool_member other ON other."sandboxHostId" = mine."sandboxHostId"
          AND other."removedAt" IS NULL
        WHERE mine."poolId" = ${poolId} AND mine."removedAt" IS NULL`;
  const rows = await tx.$queryRaw<{ id: string }[]>`
    SELECT heads.id FROM (${headsSql(scope, requestSeq)}) heads
    WHERE heads."bypassCount" >= ${HEAD_BYPASS_LIMIT} LIMIT ${GATE_HEAD_MAX}`;
  return loadHeads(
    tx,
    rows.map((row) => row.id),
  );
}

/** Every head of every pool that has the host as an active member. A host
 * holds at most MAX_ACTIVE_POOL_MEMBERSHIPS memberships, so this is complete
 * and bounded (review finding 4: never truncated by pool id). */
async function hostHeads(
  tx: Prisma.TransactionClient,
  hostId: string,
  requestSeq: bigint | null,
): Promise<Head[]> {
  const scope = PrismaValue.sql`SELECT m."poolId" FROM sandbox_pool_member m
        WHERE m."sandboxHostId" = ${hostId} AND m."removedAt" IS NULL`;
  const rows = await tx.$queryRaw<{ id: string }[]>`
    SELECT heads.id FROM (${headsSql(scope, requestSeq)}) heads
    LIMIT ${MAX_ACTIVE_POOL_MEMBERSHIPS + 1}`;
  return loadHeads(
    tx,
    rows.map((row) => row.id),
  );
}

/** The head's own visibility (its creator and key host filter), or null
 * when its credential is no longer active (it will fail on its own turn). */
async function headViewer(
  tx: Prisma.TransactionClient,
  head: Head,
): Promise<PlacementViewer | null> {
  const principal = await resolveStoredPrincipal(tx, {
    userId: head.userId,
    authorizingKeyId: head.authorizingKeyId,
    sandboxBuildId: head.Sandbox.buildId,
    sandboxVerifyBuildId: head.Sandbox.verifyBuildId,
  });
  return principal ? viewerOf(principal) : null;
}

/**
 * E(head): hosts the head could CURRENTLY use (review M4): visible to its
 * creator, enabled, compatible, template verified on the current connection,
 * online, lease and per-VM fit, healthy storage, empty-host fit within member
 * caps, and not held solely by leases that outlive the head's deadline
 * (unlimited leases for an unlimited head).
 */
async function headEligibleHosts(
  tx: Prisma.TransactionClient,
  head: Head,
  onlyHost: string | null,
): Promise<string[]> {
  const viewer = await headViewer(tx, head);
  if (!viewer) return [];
  const revision = await tx.sandboxTemplateRevision.findFirst({
    where: { id: head.templateRevisionId, userId: head.userId },
    select: {
      id: true,
      templateId: true,
      incusFingerprint: true,
      architecture: true,
      manifestDigest: true,
      sourceKind: true,
    },
  });
  if (!revision) return [];
  // A build head reserves builder hosts only (r2 N11); a vanished build places nowhere.
  const buildId = head.Sandbox.buildId;
  const build = buildId ? await loadBuildPlacement(tx, head.userId, buildId) : null;
  if (buildId && !build) return [];
  const query: PlacementQuery = {
    viewer,
    poolId: head.poolId,
    revision,
    size: { cpuCount: head.cpuCount, memoryMiB: head.memoryMiB, diskGiB: head.diskGiB },
    now: await hostDatabaseNow(tx),
    lease: leaseRequestOf(head.leaseTimeoutMs),
    selectedId: onlyHost,
    // Fetchable hosts count, exactly as for a fresh create (image distribution).
    plan: await imageFetchPlan(tx, head.userId, revision),
    build,
    startup: await revisionNeedsStartup(tx, head.userId, revision.id, buildId),
    credential: await sandboxCredentialPlacementContext(tx, head.sandboxId),
    // Preview tunnels: a head with declared ports can use tunnel hosts only.
    tunnel: head.Sandbox.tunnelEnabled,
  };
  const sql = placementSql(query);
  const outlives = new Date((head.deadlineAt?.getTime() ?? LEASE_UNLIMITED_DEADLINE_MS) - 1);
  const pinned = PrismaValue.sql`(SELECT COALESCE(sum(p."chargedMemoryMiB"::bigint), 0)::bigint AS memory,
        COALESCE(sum(p."chargedVcpu"::bigint), 0)::bigint AS vcpu
      FROM sandbox_instance s JOIN sandbox_placement p
        ON p.id = s."currentPlacementId" AND p."sandboxId" = s.id AND p."userId" = s."userId"
      WHERE s."sandboxHostId" = h.id AND s."liveResourcesHeld"
        AND (s."leaseExpiresAt" IS NULL OR s."leaseExpiresAt" > ${outlives}))`;
  // The same deadline-aware pinning within THIS pool's membership, for the
  // contributed member's RAM/vCPU caps (owner-local members are exempt, as in
  // placement's member stages). Round-3 finding.
  const pinnedMember = PrismaValue.sql`(SELECT COALESCE(sum(p."chargedMemoryMiB"::bigint), 0)::bigint AS memory,
        COALESCE(sum(p."chargedVcpu"::bigint), 0)::bigint AS vcpu
      FROM sandbox_instance s JOIN sandbox_placement p
        ON p.id = s."currentPlacementId" AND p."sandboxId" = s.id AND p."userId" = s."userId"
      WHERE s."sandboxHostId" = h.id AND s."usagePoolId" = pool.id AND s."liveResourcesHeld"
        AND (s."leaseExpiresAt" IS NULL OR s."leaseExpiresAt" > ${outlives}))`;
  const memberFits = PrismaValue.sql`(h."userId" = pool."userId"
      OR ((m."memoryCapPercent" IS NULL
          OR (SELECT memory FROM ${pinnedMember} pm) + ${sql.charge}::bigint
            <= (h."daemonMemoryBudgetMiB"::bigint * m."memoryCapPercent" / 100))
        AND (m."vcpuCapPercent" IS NULL
          OR (SELECT vcpu FROM ${pinnedMember} pm) + ${query.size.cpuCount}::bigint
            <= (h."daemonVcpuBudget"::bigint * m."vcpuCapPercent" / 100))))`;
  // Only a fresh storage report counts, like placement's storage lateral.
  const storageOldest = new Date(query.now.getTime() - STORAGE_HEALTH_STALE_MS);
  // Retained roots never free on their own (stopped disks, STOP-on-expiry
  // leases, leases outliving the head): only a live DESTROY-on-expiry root
  // whose lease ends before the head's deadline will free (review finding 3).
  // NULL-safe: a NULL or far-future (unlimited) lease never frees, so it stays
  // charged (the 9999-12-31 sentinel always outlives `outlives`).
  const rootFits = PrismaValue.sql`EXISTS (SELECT 1 FROM sandbox_host_storage_pool sp
      WHERE sp."sandboxHostId" = h.id AND sp."userId" = h."userId"
        AND sp."connectionEpoch" = h."connectionEpoch" AND sp."newRootsAllowed"
        AND sp.health = 'healthy' AND NOT sp.draining
        AND sp."reportedAt" BETWEEN ${storageOldest} AND ${query.now}
        AND sp."capacityGiB"::bigint - COALESCE((SELECT sum(r."rootChargeGiB"::bigint)
          FROM sandbox_instance r WHERE r."storagePoolId" = sp.id AND r."diskReservationHeld"
            AND NOT COALESCE(r."liveResourcesHeld" AND r."leaseExpiresAt" IS NOT NULL
              AND r."leaseExpiresAt" <= ${outlives}
              AND r."leaseExpireAction" = 'DESTROY', false)), 0) >= ${sql.root}::bigint)`;
  return eligibleHostIds(
    tx,
    query,
    [
      "enabled",
      "compatible",
      "builder",
      "tunnel",
      "templateKnown",
      "online",
      "guard",
      "templateCurrent",
      "lease",
      "perVm",
      "storagePresent",
    ],
    PrismaValue.sql`${sql.fitsEmpty}
      AND (SELECT memory FROM ${pinned} pin) + ${sql.charge}::bigint <= h."daemonMemoryBudgetMiB"
      AND (SELECT vcpu FROM ${pinned} pin) + ${query.size.cpuCount}::bigint <= h."daemonVcpuBudget"
      AND ${memberFits}
      AND ${rootFits}`,
  );
}

/**
 * Head protection with bounded, interference-aware skip-ahead (§4.3), for a
 * request with `requestSeq` (null: a new arrival, the tail). Strict heads
 * (8 bypasses spent) reserve E(head) outright; the gate goes into the
 * candidate SQL so ranking falls through to unreserved hosts. Placing on a
 * host in a non-strict head's E(head) spends one bypass (CAS under H).
 */
export function capacityGate(requestSeq: bigint | null): PlacementGate {
  return async (tx, context) => {
    // Bounded pre-selection exclusion; on overflow the per-host check below
    // still denies every interfering placement.
    const excluded = await reservedHostIds(tx, context.poolId, requestSeq);
    return {
      excludedHostIds: excluded,
      async accept(hostId) {
        // Authoritative per chosen host: every head of every pool on it.
        // Decide first, write after: a refusal must never commit a bypass
        // charge for a placement that does not happen (round-2 finding 4).
        const interfering: Head[] = [];
        for (const head of await hostHeads(tx, hostId, requestSeq))
          if ((await headEligibleHosts(tx, head, hostId)).length > 0) interfering.push(head);
        // A strict head here is only possible when the strict scan overflowed
        // or E(head) grew since selection: deny conservatively.
        if (interfering.some((head) => head.bypassCount >= HEAD_BYPASS_LIMIT)) throw poolReserved();
        for (const head of interfering) {
          const charged = await tx.sandboxCapacityWait.updateMany({
            where: { id: head.id, state: "WAITING", bypassCount: { lt: HEAD_BYPASS_LIMIT } },
            data: { bypassCount: { increment: 1 } },
          });
          // The head placed, ended or went strict concurrently: reselect.
          if (charged.count !== 1) throw new PlacementChanged();
        }
      },
    };
  };
}

/**
 * Hosts reserved outright for strict heads (bypasses spent) of every pool
 * sharing a member host with `poolId`, as seen by a request with
 * `requestSeq` (null: a new arrival). The gate excludes exactly these before
 * selection; the capacity view uses the same set so "fits now" agrees with a
 * create. Host ids only: nothing about the heads leaves this function.
 */
export async function reservedHostIds(
  tx: Prisma.TransactionClient,
  poolId: string,
  requestSeq: bigint | null,
): Promise<string[]> {
  const excluded = new Set<string>();
  for (const head of await strictHeadsNear(tx, poolId, requestSeq))
    for (const id of await headEligibleHosts(tx, head, null)) excluded.add(id);
  return [...excluded];
}

/** Pure §4.3 decision table (the SQL gate implements it); unit-tested. */
export function headDecision(input: {
  isHead: boolean;
  headExists: boolean;
  hostInHeadSet: boolean;
  bypassCount: number;
}): "place" | "place_bypass" | "deny" {
  if (input.isHead || !input.headExists || !input.hostInHeadSet) return "place";
  return input.bypassCount < HEAD_BYPASS_LIMIT ? "place_bypass" : "deny";
}

const waitSelect = {
  id: true,
  seq: true,
  state: true,
  userId: true,
  sandboxId: true,
  operationId: true,
  poolId: true,
  poolOwnerId: true,
  authorizingKeyId: true,
  templateRevisionId: true,
  cpuCount: true,
  memoryMiB: true,
  diskGiB: true,
  leaseTimeoutMs: true,
  deadlineAt: true,
  lastBlocker: true,
  // Immutable: checked before `authorizingKeyId` when rebuilding authority (§3.1.2).
  Sandbox: { select: { buildId: true, verifyBuildId: true } },
} satisfies Prisma.SandboxCapacityWaitSelect;
type Wait = Prisma.SandboxCapacityWaitGetPayload<{ select: typeof waitSelect }>;

type EndState = "TIMED_OUT" | "CANCELLED" | "FAILED";
type EndCode = Extract<
  OperationErrorCode,
  | "capacity_wait_timeout"
  | "access_denied"
  | "credential_inactive"
  | "placement_infeasible"
  | "lease_exceeds_policy"
  | "image_unavailable"
>;

/** The deadline passed while the placer waited for a lock: roll back. */
class DeadlinePassed extends Error {}

/** A wait the placer must end with this code (not a retryable refusal). */
class QueueEnd extends Error {
  constructor(readonly code: EndCode) {
    super(code);
  }
}

/**
 * End a WAITING entry; the caller holds G. Sandbox → DELETED (with
 * `lastErrorCode` on every FAILED/TIMED_OUT exit, NULL on cancel), CREATE
 * operation → FAILED/CANCELLED, intent scrubbed. Returns false when it was
 * no longer waiting.
 */
async function endWaitLocked(
  tx: Prisma.TransactionClient,
  wait: Pick<Wait, "id" | "userId" | "sandboxId" | "operationId" | "poolId" | "lastBlocker">,
  state: EndState,
  code: EndCode | null,
  now: Date,
): Promise<boolean> {
  const ended = await tx.sandboxCapacityWait.updateMany({
    where: { id: wait.id, state: "WAITING" },
    data: {
      state,
      intent: PrismaValue.DbNull,
      endedAt: now,
      endReason: code ?? "cancelled",
      lastEvaluatedAt: now,
    },
  });
  if (ended.count !== 1) return false;
  const deleted = await tx.sandbox.updateMany({
    where: { id: wait.sandboxId, userId: wait.userId, state: "WAITING_FOR_CAPACITY" },
    // credential-settlement: exempt — a create still waiting for capacity holds
    // no lease (claims happen at placement) and no residue (never booted).
    data: { state: "DELETED", lastErrorCode: code },
  });
  if (deleted.count !== 1) throw new PlacementChanged();
  const reason = capacityReasonSchema.safeParse(wait.lastBlocker);
  await tx.sandboxOperation.updateMany({
    where: { id: wait.operationId, userId: wait.userId, state: "QUEUED" },
    data: {
      state: code ? "FAILED" : "CANCELLED",
      errorCode: code ?? "cancelled",
      failure: {
        resource: "sandbox",
        effect: "none",
        ...(code === "capacity_wait_timeout" && reason.success ? { reason: reason.data } : {}),
      },
      completedAt: now,
    },
  });
  // The next entry may now be the head.
  noteCapacityChanged(tx, { poolIds: [wait.poolId] });
  return true;
}

/** Owner row (share; never refused for a deleting owner) → G, then end. */
async function endWait(id: string, state: EndState, code: EndCode | null): Promise<boolean> {
  return sandboxOutboxTransaction(async (tx) => {
    const wait = await tx.sandboxCapacityWait.findUnique({ where: { id }, select: waitSelect });
    if (wait?.state !== "WAITING") return false;
    await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${wait.userId} FOR SHARE`;
    await lockPoolGraph(tx, [wait.poolId]);
    const now = await hostDatabaseNow(tx);
    const current = await tx.sandboxCapacityWait.findUnique({ where: { id }, select: waitSelect });
    if (current?.state !== "WAITING") return false;
    if (state === "TIMED_OUT" && (!current.deadlineAt || current.deadlineAt > now)) return false;
    return endWaitLocked(tx, current, state, code, now);
  });
}

async function recordBlocker(id: string, blocker: CapacityBlocker) {
  await prisma.sandboxCapacityWait.updateMany({
    where: { id, state: "WAITING" },
    data: { lastBlocker: blocker, lastEvaluatedAt: new Date() },
  });
}

/** Rebuild the creator's CURRENT authority (§4.4 step 2): key revoked,
 * expired, owner 2FA/ban/deletion; a session needs the same owner policy. */
async function placementPrincipal(tx: Prisma.TransactionClient, wait: Wait): Promise<Principal> {
  const principal = await resolveStoredPrincipal(tx, {
    userId: wait.userId,
    authorizingKeyId: wait.authorizingKeyId,
    sandboxBuildId: wait.Sandbox.buildId,
    sandboxVerifyBuildId: wait.Sandbox.verifyBuildId,
  });
  if (!principal) throw new QueueEnd("credential_inactive");
  // A key's owner policy is part of its revalidation; a session's is checked here.
  if (!isBrowserSession(principal)) return principal;
  const user = await tx.user.findUnique({
    where: { id: wait.userId },
    select: ownerCredentialPolicyUserSelect,
  });
  const settings = await getForcedTwoFactorSettingsRecord(tx);
  if (!user || !(await isOwnerCredentialPolicySatisfied(user, new Date(), settings)))
    throw new QueueEnd("access_denied");
  return principal;
}

/** Read-only discovery before User/K/G/H: creator, pool owner and every
 * member host owner (the existing discovery short-circuits on the key). */
async function discoverQueuedPlacementPrincipals(tx: Prisma.TransactionClient, wait: Wait) {
  const ids = new Set([wait.userId, wait.poolOwnerId]);
  const members = await tx.sandboxPoolMember.findMany({
    where: { poolId: wait.poolId, removedAt: null },
    select: { hostOwnerId: true },
    take: 251,
  });
  for (const member of members) if (member.hostOwnerId) ids.add(member.hostOwnerId);
  return [...ids].sort();
}

function parseIntent(value: Prisma.JsonValue | null): StoredIntent {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new QueueEnd("placement_infeasible");
  const intent = value as unknown as StoredIntent;
  if (typeof intent.guestSudo !== "boolean") throw new QueueEnd("placement_infeasible");
  return intent;
}

type PlaceOutcome = "placed" | "waiting" | "ended" | "gone";

/** Post-commit effects of one placement attempt. */
type PlaceEffects = { wakeBuilds: boolean };

/**
 * Rebuild on miss for a waiting entry (template-builds §3.9), under the
 * placer's locks (User, owner placement, G). Its revision's image is gone
 * everywhere: wait on the rebuild (started now when none ran yet), follow the
 * tag once the rebuild succeeded, or end `image_unavailable` when it failed,
 * was refused (quota) or the recipe needs its context again. A failed rebuild
 * is never retried from here: only a new create retries.
 */
async function followRebuild(
  tx: Prisma.TransactionClient,
  principal: Principal,
  wait: Wait,
  now: Date,
  effects: PlaceEffects,
): Promise<PlaceOutcome | { revisionId: string }> {
  const revision = await tx.sandboxTemplateRevision.findFirst({
    where: { id: wait.templateRevisionId, userId: wait.userId },
    select: { id: true, templateId: true, sourceKind: true, incusFingerprint: true },
  });
  if (revision?.sourceKind !== "BUILD") return { revisionId: wait.templateRevisionId };
  const sandbox = await tx.sandbox.findFirst({
    where: { id: wait.sandboxId, userId: wait.userId },
    select: { originalSelector: true },
  });
  if (!sandbox) return "gone";
  const rebuild = await rebuildOnMissLocked(tx, principal, sandbox.originalSelector, revision, {
    retryFailed: false,
    now,
  });
  if (rebuild.kind === "none") return { revisionId: wait.templateRevisionId };
  if (rebuild.kind === "rebuilding") {
    if (rebuild.started) effects.wakeBuilds = true;
    await tx.sandboxCapacityWait.updateMany({
      where: { id: wait.id, state: "WAITING" },
      data: { lastBlocker: "image_rebuilding", lastEvaluatedAt: now },
    });
    return "waiting";
  }
  if (rebuild.kind === "refused")
    return (await endWaitLocked(tx, wait, "FAILED", "image_unavailable", now)) ? "ended" : "gone";
  // Rebuilt: re-resolve the creator's selector (its own allowlists) and
  // follow it. A refusal here ends the wait through `endCodeFor`.
  const next = await resolveTemplateRevision(tx, principal, sandbox.originalSelector);
  if (next.id === wait.templateRevisionId) return { revisionId: next.id };
  const moved = await tx.sandbox.updateMany({
    where: { id: wait.sandboxId, userId: wait.userId, state: "WAITING_FOR_CAPACITY" },
    data: { templateId: next.templateId, templateRevisionId: next.id },
  });
  if (moved.count !== 1) return "gone";
  await tx.sandboxCapacityWait.update({
    where: { id: wait.id },
    data: { templateRevisionId: next.id },
  });
  return { revisionId: next.id };
}

/** One placement attempt in one transaction (§4.4). */
async function placeLocked(
  tx: Prisma.TransactionClient,
  discovered: Wait,
  clock: LeaseClock,
  effects: PlaceEffects,
): Promise<PlaceOutcome> {
  const operation = await tx.sandboxOperation.findFirst({
    where: { id: discovered.operationId, userId: discovered.userId },
    select: { idempotencyKey: true },
  });
  if (!operation) return "gone";
  await lockPlacementPrincipals(tx, await discoverQueuedPlacementPrincipals(tx, discovered));
  await tx.$queryRaw`SELECT 1 AS locked FROM pg_advisory_xact_lock(hashtextextended(${JSON.stringify([discovered.userId, operation.idempotencyKey])}, 0))`;
  const principal = await placementPrincipal(tx, discovered);
  await lockOwnerPlacement(tx, discovered.userId);
  await lockPoolGraph(tx, [discovered.poolId]);
  const now = await hostDatabaseNow(tx);
  const wait = await tx.sandboxCapacityWait.findUnique({
    where: { id: discovered.id },
    select: { ...waitSelect, intent: true },
  });
  if (wait?.state !== "WAITING") return "gone";
  // DB clock under G: a placement after the deadline is impossible.
  if (wait.deadlineAt && wait.deadlineAt <= now)
    return (await endWaitLocked(tx, wait, "TIMED_OUT", "capacity_wait_timeout", now))
      ? "ended"
      : "gone";
  const intent = parseIntent(wait.intent);
  const followed = await followRebuild(tx, principal, wait, now, effects);
  if (typeof followed === "string") return followed;
  const outcome = await resolvePlacement(
    tx,
    principal,
    {
      poolId: wait.poolId,
      template: `revision/${followed.revisionId}`,
      cpuCount: wait.cpuCount,
      memoryMiB: wait.memoryMiB,
      diskGiB: wait.diskGiB,
      timeoutMs: wait.leaseTimeoutMs,
      expectedDisconnectGraceSeconds: intent.expectedDisconnectGraceSeconds,
      // CLI logins (§8): rebuilt from the attachment rows and current opt-ins.
      credential: await sandboxCredentialPlacementContext(tx, wait.sandboxId),
      egressMode: intent.egress.request.mode,
      tunnel: intent.tunnelPorts !== undefined,
    },
    { gate: capacityGate(wait.seq), allowWait: true, buildId: wait.Sandbox.buildId },
  );
  if ("kind" in outcome) {
    await tx.sandboxCapacityWait.updateMany({
      where: { id: wait.id, state: "WAITING" },
      data: { lastBlocker: outcome.blocker, lastEvaluatedAt: now },
    });
    return "waiting";
  }
  // Review M3: the complete create authorization against the chosen host
  // (scopes, host/revision/pool allowlists, foreign-pool exemption, fence).
  await authorizeServiceAction(
    principal,
    "sandboxes.create",
    {
      sandboxHostId: outcome.hostId,
      templateRevisionId: outcome.revision.id,
      originPoolId: outcome.poolId,
    },
    tx,
  );
  const sandbox = await tx.sandbox.findFirst({
    where: { id: wait.sandboxId, userId: wait.userId },
    select: { generation: true, state: true },
  });
  if (sandbox?.state !== "WAITING_FOR_CAPACITY") return "gone";
  // S, then the DB clock again: every blocking placement lock (G, H, the key
  // row, S) is now held, so the deadline cannot pass before commit unseen.
  // Expired while waiting for a lock: roll the placement back and time out
  // (review finding 2).
  await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${wait.sandboxId} AND "userId" = ${wait.userId} FOR NO KEY UPDATE`;
  const [current] = await tx.$queryRaw<{ deadlineAt: Date | null; state: string }[]>`
    SELECT "deadlineAt", state::text AS state FROM sandbox_capacity_wait WHERE id = ${wait.id} FOR UPDATE`;
  const placedAt = await hostDatabaseNow(tx);
  if (current?.state !== "WAITING") return "gone";
  if (current.deadlineAt && current.deadlineAt <= placedAt) throw new DeadlinePassed();
  // CLI logins (§7.2, §6.1): spec preflight before any claim, then claim at
  // placement, after S (none free → in_use).
  await preflightCredentialSpec(tx, {
    sandboxId: wait.sandboxId,
    credentialIds: (
      await tx.sandboxCredential.findMany({
        where: { sandboxId: wait.sandboxId, detachedAt: null },
        select: { credentialId: true },
        orderBy: { credentialId: "asc" },
        take: 8,
      })
    ).map((row) => row.credentialId),
  });
  await claimCreateLeases(tx, {
    principal,
    ownerId: wait.userId,
    sandboxId: wait.sandboxId,
    operationId: wait.operationId,
    hostId: outcome.hostId,
  });
  await materializePlacement(
    tx,
    principal,
    outcome,
    intent,
    {
      idempotencyKey: operation.idempotencyKey,
      queued: {
        sandboxId: wait.sandboxId,
        operationId: wait.operationId,
        generation: sandbox.generation,
      },
    },
    clock,
  );
  await tx.sandboxCapacityWait.update({
    where: { id: wait.id },
    data: {
      state: "PLACED",
      intent: PrismaValue.DbNull,
      endedAt: now,
      endReason: "placed",
      lastEvaluatedAt: now,
    },
  });
  noteCapacityChanged(tx, { poolIds: [wait.poolId] });
  return "placed";
}

/** How a refused placement ends (null: keep waiting). */
async function endCodeFor(wait: Wait, error: unknown): Promise<EndCode | null> {
  if (error instanceof QueueEnd) return error.code;
  if (error instanceof AccountDeletionConflictError) {
    const user = await prisma.user.findUnique({
      where: { id: wait.userId },
      select: { deletionRequestedAt: true },
    });
    return !user || user.deletionRequestedAt ? "access_denied" : null;
  }
  if (!(error instanceof ORPCError)) return null;
  const code = (error.data as { code?: unknown } | undefined)?.code;
  if (isStaticRefusal(error)) {
    if (code === "lease_exceeds_policy") return "lease_exceeds_policy";
    if (error.code === "FORBIDDEN") return "access_denied";
    return "placement_infeasible";
  }
  if (code === "sandbox.pool_policy_changed") return "placement_infeasible";
  if (code === "sandbox.template_not_found") {
    const revision = await prisma.sandboxTemplateRevision.findFirst({
      where: { id: wait.templateRevisionId, userId: wait.userId },
      select: { retiredAt: true },
    });
    return revision && !revision.retiredAt ? "access_denied" : "placement_infeasible";
  }
  if (code === "sandbox.pool_not_found" || error.code === "FORBIDDEN" || error.code === "NOT_FOUND")
    return "access_denied";
  return null;
}

/** Evaluate one waiting entry. Any unknown error keeps it waiting
 * (`unavailable`); it never aborts the pass. */
export async function placeCapacityWait(id: string, clock: LeaseClock): Promise<PlaceOutcome> {
  const discovered = await prisma.sandboxCapacityWait.findUnique({
    where: { id },
    select: waitSelect,
  });
  if (discovered?.state !== "WAITING") return "gone";
  const effects: PlaceEffects = { wakeBuilds: false };
  try {
    const outcome = await retryPlacement(() =>
      sandboxOutboxTransaction((tx) => {
        effects.wakeBuilds = false;
        return placeLocked(tx, discovered, clock, effects);
      }),
    );
    if (effects.wakeBuilds) notifyTemplateBuildsChanged();
    return outcome;
  } catch (error) {
    try {
      if (error instanceof DeadlinePassed) {
        await endWait(id, "TIMED_OUT", "capacity_wait_timeout");
        return "ended";
      }
      const code = await endCodeFor(discovered, error);
      if (code) {
        await endWait(id, "FAILED", code);
        return "ended";
      }
      await recordBlocker(id, waitableBlocker(error) ?? "unavailable");
    } catch {
      console.error("[capacity-queue] entry settlement failed; periodic retry pending");
    }
    return "waiting";
  }
}

/** Timeout sweep (DB clock): User → G → S, bounded per call. */
export async function expireCapacityWaits(shouldStop: () => boolean = () => false) {
  let expired = 0;
  for (;;) {
    const due = await prisma.$queryRaw<{ id: string }[]>`
      SELECT id FROM sandbox_capacity_wait
      WHERE state = 'WAITING' AND "deadlineAt" <= (clock_timestamp() AT TIME ZONE 'UTC')
      ORDER BY "deadlineAt", seq LIMIT ${QUEUE_SCAN_WINDOW}`;
    for (const row of due) {
      if (shouldStop()) return expired;
      try {
        if (await endWait(row.id, "TIMED_OUT", "capacity_wait_timeout")) expired++;
      } catch {
        console.error("[capacity-queue] expiry failed; periodic retry pending");
      }
    }
    if (due.length < QUEUE_SCAN_WINDOW || shouldStop()) return expired;
  }
}

/**
 * Cancel branch for destroy/stop/operation cancel (§4.4). The caller holds
 * User and K. The waiting row has no host, so H is never relied on: take G
 * from the wait row's pool, then re-read. Returns null when the sandbox is
 * not (or no longer) waiting, e.g. a racing placer placed it first: the
 * caller then runs its normal host-locked path (G → H is the global order).
 */
export async function cancelCapacityWaitIfWaiting(
  tx: Prisma.TransactionClient,
  ownerId: string,
  sandboxId: string,
): Promise<{ generation: number; poolId: string } | null> {
  const wait = await tx.sandboxCapacityWait.findFirst({
    where: { sandboxId, userId: ownerId },
    select: waitSelect,
  });
  if (wait?.state !== "WAITING") return null;
  await lockPoolGraph(tx, [wait.poolId]);
  const sandbox = await tx.sandbox.findFirst({
    where: { id: sandboxId, userId: ownerId },
    select: { state: true, generation: true },
  });
  if (sandbox?.state !== "WAITING_FOR_CAPACITY") return null;
  const now = await hostDatabaseNow(tx);
  if (!(await endWaitLocked(tx, wait, "CANCELLED", null, now))) return null;
  return { generation: sandbox.generation, poolId: wait.poolId };
}

/** Pools with waiting entries for this hint, oldest head first (bounded). */
/**
 * Scan cursors (review finding 1). A pass evaluates a bounded window, but a
 * fixed prefix could stay blocked forever (e.g. self-blocked share caps) and
 * starve later entries. So each window is the oldest entries (FIFO
 * preference) plus a rotating part that resumes after the last entry it
 * evaluated, up to a high-water mark fixed when the rotation began, then
 * starts over: new arrivals can never postpone the wrap, so every entry
 * present at a rotation's start is evaluated within ceil(n / 48) passes. Process-local (single replica, like the wakes);
 * losing it only restarts the rotation. The same holds for pool discovery.
 */
const FRONT_ENTRIES = 16;
const FRONT_POOLS = 128;
const POOL_WINDOW = 256;
/** Per pool: where the rotation is and its fixed high-water mark (max seq
 * when the rotation began), so new arrivals can never postpone the wrap. */
const rotations = new Map<string, { cursor: bigint; hwm: bigint }>();
let poolCursor = "";

/** Pools with waiting entries for this hint: the oldest heads first, then a
 * rotating window by pool id that wraps, so no waiting pool is starved. */
async function hintedPools(hint: CapacityHint | undefined): Promise<string[]> {
  const all = hint === undefined || hint === "all";
  const poolIds = all ? [] : [...(hint.poolIds ?? [])];
  const hostIds = all ? [] : [...(hint.hostIds ?? [])];
  const scope = PrismaValue.sql`w.state = 'WAITING' AND (${all} OR w."poolId" = ANY(${poolIds}::text[]) OR EXISTS (
      SELECT 1 FROM sandbox_pool_member m WHERE m."poolId" = w."poolId" AND m."removedAt" IS NULL
        AND m."sandboxHostId" = ANY(${hostIds}::text[])))`;
  const front = (
    await prisma.$queryRaw<{ poolId: string }[]>`
      SELECT w."poolId" FROM sandbox_capacity_wait w WHERE ${scope}
      GROUP BY w."poolId" ORDER BY min(w.seq) LIMIT ${FRONT_POOLS}`
  ).map((row) => row.poolId);
  const rotating = async (after: boolean, limit: number) =>
    limit <= 0
      ? []
      : (
          await prisma.$queryRaw<{ poolId: string }[]>`
            SELECT DISTINCT w."poolId" FROM sandbox_capacity_wait w WHERE ${scope}
              AND NOT (w."poolId" = ANY(${front}::text[]))
              AND (CASE WHEN ${after} THEN w."poolId" > ${poolCursor} ELSE w."poolId" <= ${poolCursor} END)
            ORDER BY w."poolId" LIMIT ${limit}`
        ).map((row) => row.poolId);
  const later = await rotating(true, POOL_WINDOW - front.length);
  const wrapped = await rotating(false, POOL_WINDOW - front.length - later.length);
  const rest = [...later, ...wrapped];
  if (all && rest.length > 0) poolCursor = rest[rest.length - 1] ?? "";
  return [...front, ...rest];
}

/** Entries to evaluate in one pool this pass: the protected head first, the
 * oldest entries, then a rotating window resuming after the last one. */
async function scanWindow(poolId: string): Promise<string[]> {
  const select = { id: true, seq: true } as const;
  const head = await prisma.sandboxCapacityWait.findFirst({
    where: { poolId, state: "WAITING", lastBlocker: { in: [...HEAD_BLOCKERS] } },
    orderBy: { seq: "asc" },
    select,
  });
  const front = await prisma.sandboxCapacityWait.findMany({
    where: { poolId, state: "WAITING" },
    orderBy: { seq: "asc" },
    take: FRONT_ENTRIES,
    select,
  });
  const frontEnd = front.at(-1)?.seq ?? -1n;
  const budget = QUEUE_SCAN_WINDOW - front.length;
  const highWater = async () =>
    (
      await prisma.sandboxCapacityWait.findFirst({
        where: { poolId, state: "WAITING" },
        orderBy: { seq: "desc" },
        select: { seq: true },
      })
    )?.seq ?? frontEnd;
  const window = (after: bigint, hwm: bigint) =>
    prisma.sandboxCapacityWait.findMany({
      where: { poolId, state: "WAITING", seq: { gt: after, lte: hwm } },
      orderBy: { seq: "asc" },
      take: budget,
      select,
    });
  let rotation = rotations.get(poolId) ?? { cursor: frontEnd, hwm: await highWater() };
  let rotating = await window(
    // biome-ignore lint/complexity/useMathMinMax: queue sequence cursors are bigint; Math.max accepts only numbers.
    rotation.cursor > frontEnd ? rotation.cursor : frontEnd,
    rotation.hwm,
  );
  // The rotation reached its high-water mark: start the next one now, from
  // just after the oldest entries, up to a fresh mark (round-2 finding 1).
  if (rotating.length === 0 && rotation.cursor > frontEnd) {
    rotation = { cursor: frontEnd, hwm: await highWater() };
    rotating = await window(frontEnd, rotation.hwm);
  }
  const last = rotating.at(-1);
  if (last && rotating.length === budget)
    rotations.set(poolId, { cursor: last.seq, hwm: rotation.hwm });
  else rotations.delete(poolId);
  const ids = [...(head ? [head.id] : []), ...front.map((e) => e.id), ...rotating.map((e) => e.id)];
  return [...new Set(ids)];
}

/**
 * One queue pass: expire due entries, then, per hinted pool (oldest heads
 * first, then a rotating window), evaluate the head, the oldest entries and a
 * rotating window (one placement per transaction, at most 64 placements per
 * pool). Per-pool FIFO is the guarantee; cross-pool order is approximate.
 * Returns ms until the next deadline (≤ 15 s) or null.
 */
export async function runCapacityQueuePass(
  clock: LeaseClock,
  shouldStop: () => boolean = () => false,
  hint?: CapacityHint,
): Promise<number | null> {
  await expireCapacityWaits(shouldStop);
  for (const poolId of await hintedPools(hint)) {
    if (shouldStop()) break;
    let placed = 0;
    for (const id of await scanWindow(poolId)) {
      if (shouldStop()) break;
      if ((await placeCapacityWait(id, clock)) === "placed" && ++placed >= PASS_PLACEMENT_MAX)
        break;
    }
  }
  const next = await prisma.sandboxCapacityWait.findFirst({
    where: { state: "WAITING", deadlineAt: { not: null } },
    orderBy: { deadlineAt: "asc" },
    select: { deadlineAt: true },
  });
  if (!next?.deadlineAt) return null;
  return Math.max(0, Math.min(QUEUE_RECHECK_MS, next.deadlineAt.getTime() - Date.now()));
}

/**
 * Coalescing scheduler (the `SharingAccessScheduler` pattern): pool/host
 * hints with an "all" overflow, a 15 s unref interval, one drain loop, plus a
 * deadline timer armed at the next `deadlineAt` (≤ 15 s) so timeouts fire
 * promptly.
 */
export class CapacityQueueScheduler {
  private stopped = false;
  private pending = false;
  private all = false;
  private pools = new Set<string>();
  private hosts = new Set<string>();
  private running: Promise<void> | null = null;
  private deadline: ReturnType<typeof setTimeout> | null = null;
  private readonly timer: ReturnType<typeof setInterval>;

  constructor(
    private readonly pass: (
      shouldStop: () => boolean,
      hint: CapacityHint,
    ) => Promise<number | null>,
  ) {
    this.timer = setInterval(() => this.wake(), QUEUE_RECHECK_MS);
    this.timer.unref?.();
    this.wake();
  }

  wake(hint: CapacityHint = "all") {
    if (this.stopped) return;
    this.pending = true;
    if (hint === "all") this.all = true;
    else if (!this.all) {
      for (const id of hint.poolIds ?? []) this.pools.add(id);
      for (const id of hint.hostIds ?? []) this.hosts.add(id);
      if (this.pools.size + this.hosts.size > 250) {
        this.all = true;
        this.pools.clear();
        this.hosts.clear();
      }
    }
    if (!this.running) this.running = this.drain();
  }

  private async drain() {
    try {
      while (this.pending && !this.stopped) {
        this.pending = false;
        const hint: CapacityHint = this.all
          ? "all"
          : { poolIds: [...this.pools], hostIds: [...this.hosts] };
        this.all = false;
        this.pools.clear();
        this.hosts.clear();
        try {
          const next = await this.pass(() => this.stopped, hint);
          this.arm(next);
        } catch {
          console.error("[capacity-queue] pass failed; periodic retry pending");
        }
      }
    } finally {
      this.running = null;
    }
  }

  private arm(ms: number | null) {
    if (this.deadline) clearTimeout(this.deadline);
    this.deadline = null;
    if (ms === null || this.stopped) return;
    this.deadline = setTimeout(() => this.wake(), ms + 50);
    this.deadline.unref?.();
  }

  async stop() {
    this.stopped = true;
    clearInterval(this.timer);
    if (this.deadline) clearTimeout(this.deadline);
    this.pools.clear();
    this.hosts.clear();
    await this.running;
  }
}

/** Long-poll: a waiting create answers at once (it holds no waiter slot). */
export async function isCapacityWaitingOperation(ownerId: string, operationId: string) {
  return (
    (await prisma.sandboxCapacityWait.findFirst({
      where: { operationId, userId: ownerId, state: "WAITING" },
      select: { id: true },
    })) != null
  );
}

/** The public blocker of a stored one (the stored values are the public enum). */
export function publicCapacityBlocker(value: string | null): CapacityWaitView["blocker"] {
  return value as CapacityWaitView["blocker"];
}

/** Creator-visible queue view per waiting sandbox (no intent, bounded by the
 * caller's page). Position = this pool's waiting entries up to this one. */
export async function capacityWaitViews(
  client: Prisma.TransactionClient,
  ownerId: string,
  sandboxIds: readonly string[],
): Promise<Map<string, CapacityWaitView>> {
  const views = new Map<string, CapacityWaitView>();
  if (sandboxIds.length === 0) return views;
  const rows = await client.$queryRaw<
    {
      sandboxId: string;
      poolId: string;
      enqueuedAt: Date;
      deadlineAt: Date | null;
      lastBlocker: string | null;
      position: number;
    }[]
  >`SELECT w."sandboxId", w."poolId", w."enqueuedAt", w."deadlineAt", w."lastBlocker",
      (SELECT count(*) FROM sandbox_capacity_wait o
        WHERE o."poolId" = w."poolId" AND o.state = 'WAITING' AND o.seq <= w.seq)::int AS position
    FROM sandbox_capacity_wait w
    WHERE w."userId" = ${ownerId} AND w.state = 'WAITING' AND w."sandboxId" = ANY(${[...sandboxIds]}::text[])`;
  for (const row of rows)
    views.set(row.sandboxId, {
      state: "waiting",
      poolId: row.poolId,
      enqueuedAt: row.enqueuedAt.toISOString(),
      deadlineAt: row.deadlineAt ? row.deadlineAt.toISOString() : null,
      position: Math.max(1, row.position),
      blocker: publicCapacityBlocker(row.lastBlocker),
    });
  return views;
}

/** The KILL/STOP receipt of a cancelled waiting create, completed server-side
 * as SUCCEEDED (no host was ever bound; the CREATE operation is CANCELLED).
 * Also the receipt of a KILL of an already-DELETED sandbox (nothing to send).
 * Runs inside the caller's `operationTransaction` (owner/key boundary). */
export async function recordWaitingTeardown(
  tx: Prisma.TransactionClient,
  owner: Principal,
  sandboxId: string,
  idempotencyKey: string,
  bodyHash: () => string,
  spec: { kind: "KILL_SANDBOX" | "STOP_SANDBOX"; generation: number },
) {
  return tx.sandboxOperation.create({
    data: {
      authorizingKeyId: recordedKeyIdOf(owner),
      userId: owner.ownerId,
      sandboxId,
      kind: spec.kind,
      state: "SUCCEEDED",
      generation: spec.generation,
      idempotencyKey,
      requestBodyHash: bodyHash(),
      digestContext: operationDigestContext(tx),
      ...requestDigestMetadata(spec.kind),
      completedAt: await hostDatabaseNow(tx),
    },
    select: { id: true, state: true },
  });
}
