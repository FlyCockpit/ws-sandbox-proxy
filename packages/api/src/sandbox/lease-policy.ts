import type { Prisma } from "@wssp/db";
import { Prisma as PrismaValue } from "@wssp/db/client";
import { env } from "@wssp/env/server";
import { leaseExceedsPolicy } from "./errors";
import { LEASE_FINITE_MAX_MS, LEASE_MAX_MS, LEASE_UNLIMITED_DEADLINE_MS } from "./lease-limits";
import type { PlacementViewer } from "./principal-kinds";

/**
 * Layered sandbox lease policy, the single source for every check:
 * effective maximum = min(deployment, host ceiling, pool max, membership max).
 * A `null` layer adds no limit. `timeoutMs: 0` requests no lease timer and is
 * allowed only when every layer is unlimited and, on a pool path, the requester
 * owns the pool or the pool allows unlimited leases for shares.
 */
export type LeaseRequest = { kind: "none" } | { kind: "deadline"; ms: number };
export type PathLimit = { finiteMaxMs: number; unlimited: boolean };
export type PoolLeaseLayer = {
  maxLeaseMs: number | null;
  ownerId: string;
  unlimitedForShares: boolean;
};

export function leaseRequestOf(timeoutMs: number): LeaseRequest {
  return timeoutMs === 0 ? { kind: "none" } : { kind: "deadline", ms: timeoutMs };
}

/** Deployment layer: `null` means the operator set `unlimited`. A test env
 * that omits the variable gets the schema default. */
export function deploymentLeaseMaxMs(): number | null {
  const configured: number | null | undefined = env.SANDBOX_MAX_TIMEOUT_MS;
  return configured === undefined ? LEASE_MAX_MS : configured;
}

/** Largest finite timeout the deployment allows (capabilities `sandboxTimeoutMaxMs`). */
export function deploymentFiniteMaxMs(): number {
  return deploymentLeaseMaxMs() ?? LEASE_FINITE_MAX_MS;
}

export function effectiveLeaseLimit(layers: {
  deployment: number | null;
  host: number | null;
  pool: PoolLeaseLayer | null;
  memberMaxLeaseMs: number | null;
  requesterId: string;
}): PathLimit {
  const finite = [
    layers.deployment,
    layers.host,
    layers.pool?.maxLeaseMs ?? null,
    layers.memberMaxLeaseMs,
  ].filter((value): value is number => value !== null);
  const permitted =
    layers.pool === null ||
    layers.pool.ownerId === layers.requesterId ||
    layers.pool.unlimitedForShares;
  return {
    finiteMaxMs: Math.min(LEASE_FINITE_MAX_MS, ...finite),
    unlimited: finite.length === 0 && permitted,
  };
}

/** Deployment-only limit: the deployment layer checked before any lock. */
export function deploymentPathLimit(): PathLimit {
  const deployment = deploymentLeaseMaxMs();
  return {
    finiteMaxMs: deployment ?? LEASE_FINITE_MAX_MS,
    unlimited: deployment === null,
  };
}

export function leaseWithinPolicy(request: LeaseRequest, limit: PathLimit): boolean {
  return request.kind === "none" ? limit.unlimited : request.ms <= limit.finiteMaxMs;
}

export function requireLeaseWithinPolicy(request: LeaseRequest, limit: PathLimit): void {
  if (!leaseWithinPolicy(request, limit)) throw leaseExceedsPolicy(limit.finiteMaxMs);
}

export function leaseDeadline(request: LeaseRequest, now: Date | number): Date {
  if (request.kind === "none") return new Date(LEASE_UNLIMITED_DEADLINE_MS);
  return new Date((typeof now === "number" ? now : now.getTime()) + request.ms);
}

/**
 * Lease path (§3.1). Own host (`hostOwnerId === userId`): the ORIGIN pool and
 * that host's membership row, for the sandbox's whole life; sharing's
 * own-host clearing of `usagePoolId` does not matter. Foreign host: the usage
 * path. The pool layers apply only while the pool is not deleted and the
 * membership is not removed, belongs to the pool and names the sandbox's
 * host. A disabled membership still applies (`enabled` only gates new holds).
 */
export type LeasePathSandbox = {
  userId: string;
  hostOwnerId: string | null;
  sandboxHostId: string | null;
  originPoolId: string | null;
  usagePoolId: string | null;
  usageMemberId: string | null;
};
export type LeasePath =
  | { kind: "none" }
  | { kind: "own"; poolId: string; hostId: string }
  | { kind: "foreign"; poolId: string; memberId: string; hostId: string };

export function leasePathOf(s: LeasePathSandbox): LeasePath {
  if (!s.sandboxHostId || !s.hostOwnerId) return { kind: "none" };
  if (s.hostOwnerId === s.userId)
    return s.originPoolId
      ? { kind: "own", poolId: s.originPoolId, hostId: s.sandboxHostId }
      : { kind: "none" };
  return s.usagePoolId && s.usageMemberId
    ? {
        kind: "foreign",
        poolId: s.usagePoolId,
        memberId: s.usageMemberId,
        hostId: s.sandboxHostId,
      }
    : { kind: "none" };
}

export function sameLeasePath(a: LeasePathSandbox, b: LeasePathSandbox): boolean {
  return (
    a.hostOwnerId === b.hostOwnerId &&
    JSON.stringify(leasePathOf(a)) === JSON.stringify(leasePathOf(b))
  );
}

/** Pools to lock (G) before H for a policy read of this sandbox's path. */
export function leasePathPools(s: LeasePathSandbox): string[] {
  const path = leasePathOf(s);
  return path.kind === "none" ? [] : [path.poolId];
}

const F = LEASE_FINITE_MAX_MS;

/**
 * Lease path join over `sandbox_instance s` and `sandbox_host h` (LEFT JOIN on
 * the sandbox's host). Exposes `pool` and `m`, both NULL unless the §3.1
 * conditions hold, matching the placement aliases.
 */
export const leasePathJoinSql: Prisma.Sql = PrismaValue.sql`
  LEFT JOIN (sandbox_pool pool JOIN sandbox_pool_member m
      ON m."poolId" = pool.id AND m."userId" = pool."userId"
      AND m."removedAt" IS NULL AND pool."deletedAt" IS NULL)
    ON pool.id = (CASE WHEN s."hostOwnerId" = s."userId" THEN s."originPoolId" ELSE s."usagePoolId" END)
    AND m."sandboxHostId" = s."sandboxHostId" AND m."hostOwnerId" = s."hostOwnerId"
    AND (s."hostOwnerId" = s."userId" OR m.id = s."usageMemberId")`;

/** The later of the requested and host-acknowledged deadlines. */
export const pullInDeadlineSql: Prisma.Sql = PrismaValue.sql`GREATEST(s."leaseExpiresAt", COALESCE(s."leaseExpiresAtEffective", s."leaseExpiresAt"))`;

/** Host layer; a missing host row counts as the 24h default, never unlimited. */
const hostLayerSql = PrismaValue.sql`(CASE WHEN h.id IS NULL THEN ${LEASE_MAX_MS}::int ELSE h."daemonMaxLeaseMs" END)`;

/** Finite path maximum including the deployment layer (aliases h, pool, m). */
export function pathLimitSql(deployment: number | null): Prisma.Sql {
  return PrismaValue.sql`LEAST(COALESCE(${deployment}::int, ${F}::int), COALESCE(${hostLayerSql}, ${F}::int),
    COALESCE(pool."maxLeaseMs", ${F}::int), COALESCE(m."maxLeaseMs", ${F}::int))`;
}

/** Whether `requester` may hold no lease timer on this path (aliases h, pool, m). */
export function pathUnlimitedSql(deployment: number | null, requester: Prisma.Sql): Prisma.Sql {
  return PrismaValue.sql`(${deployment}::int IS NULL AND ${hostLayerSql} IS NULL
    AND pool."maxLeaseMs" IS NULL AND m."maxLeaseMs" IS NULL
    AND (pool.id IS NULL OR pool."userId" = ${requester} OR pool."unlimitedLeaseForShares"))`;
}

/** Placement stage predicate: does `request` fit this candidate path? */
export function leaseFitsSql(
  request: LeaseRequest,
  requesterId: string,
  deployment: number | null,
): Prisma.Sql {
  return request.kind === "none"
    ? pathUnlimitedSql(deployment, PrismaValue.sql`${requesterId}`)
    : PrismaValue.sql`(${request.ms}::int <= ${pathLimitSql(deployment)})`;
}

type PathLayerRow = {
  userId: string;
  hostFound: boolean;
  hostMaxLeaseMs: number | null;
  poolId: string | null;
  poolOwnerId: string | null;
  poolMaxLeaseMs: number | null;
  unlimitedLeaseForShares: boolean | null;
  memberMaxLeaseMs: number | null;
};

/** Raw layers of a sandbox's current lease path (§3.1), read from the row. */
export async function readPathLayers(tx: Prisma.TransactionClient, sandboxId: string) {
  const rows = await tx.$queryRaw<PathLayerRow[]>`
    SELECT s."userId", (h.id IS NOT NULL) AS "hostFound", h."daemonMaxLeaseMs" AS "hostMaxLeaseMs",
      pool.id AS "poolId", pool."userId" AS "poolOwnerId", pool."maxLeaseMs" AS "poolMaxLeaseMs",
      pool."unlimitedLeaseForShares", m."maxLeaseMs" AS "memberMaxLeaseMs"
    FROM sandbox_instance s
    LEFT JOIN sandbox_host h ON h.id = s."sandboxHostId" AND h."userId" = s."hostOwnerId"
    ${leasePathJoinSql}
    WHERE s.id = ${sandboxId}`;
  const row = rows[0];
  if (!row) return null;
  return {
    deployment: deploymentLeaseMaxMs(),
    host: row.hostFound ? row.hostMaxLeaseMs : LEASE_MAX_MS,
    pool:
      row.poolId && row.poolOwnerId
        ? {
            maxLeaseMs: row.poolMaxLeaseMs,
            ownerId: row.poolOwnerId,
            unlimitedForShares: row.unlimitedLeaseForShares === true,
          }
        : null,
    memberMaxLeaseMs: row.poolId ? row.memberMaxLeaseMs : null,
    requesterId: row.userId,
  };
}

/**
 * Effective limit of a sandbox's lease path. The caller holds G (the path
 * pool, `leasePathPools`) and H, then S; every policy writer serializes on
 * one of them, so the value cannot change before commit.
 */
export async function readLockedPathLimit(
  tx: Prisma.TransactionClient,
  s: { id: string },
): Promise<PathLimit> {
  const layers = await readPathLayers(tx, s.id);
  if (!layers)
    return { finiteMaxMs: Math.min(deploymentFiniteMaxMs(), LEASE_MAX_MS), unlimited: false };
  return effectiveLeaseLimit(layers);
}

export type PoolLeaseView = { maxTimeoutMs: number; timeoutZero: boolean };

/**
 * Discovery (§6): per pool, the best available lease path for `caller` — the
 * largest finite maximum and whether some path allows no lease timer. One
 * grouped query over the page's pool ids, with placement's visibility
 * predicates and the SDK key's host filter, so a key never sees a maximum it
 * cannot use. Offline hosts still count: actual placement may offer less.
 */
export async function poolLeaseViews(
  tx: Prisma.TransactionClient,
  caller: Pick<PlacementViewer, "ownerId" | "allowedHostIds">,
  pools: readonly { id: string; maxLeaseMs: number | null }[],
  now: Date = new Date(),
): Promise<Map<string, PoolLeaseView>> {
  const views = new Map<string, PoolLeaseView>();
  if (pools.length === 0) return views;
  const deployment = deploymentLeaseMaxMs();
  const allHosts = caller.allowedHostIds === "allOwned";
  const hostIds = caller.allowedHostIds === "allOwned" ? [] : [...caller.allowedHostIds];
  const rows = await tx.$queryRaw<{ poolId: string; max: number | null; zero: boolean | null }[]>`
    SELECT pool.id AS "poolId", max(${pathLimitSql(deployment)}) AS max,
      bool_or(${pathUnlimitedSql(deployment, PrismaValue.sql`${caller.ownerId}`)}) AS zero
    FROM sandbox_pool pool
    JOIN sandbox_pool_member m ON m."poolId" = pool.id AND m."userId" = pool."userId"
      AND m."removedAt" IS NULL AND m.enabled = true
      AND (m."hostOwnerId" = pool."userId" OR (m."contributeWitness" IS TRUE AND m."ownHostsOnlyWitness" IS FALSE))
    JOIN sandbox_host h ON h.id = m."sandboxHostId" AND h."userId" = m."hostOwnerId"
      AND h."deletionRequestedAt" IS NULL
    JOIN "user" host_owner ON host_owner.id = h."userId"
      AND host_owner."deletionRequestedAt" IS NULL
      AND (host_owner.banned IS NOT TRUE OR host_owner."banExpires" <= ${now})
    WHERE pool.id = ANY(${pools.map((pool) => pool.id)}::text[]) AND pool."deletedAt" IS NULL
      AND (${allHosts} OR h.id = ANY(${hostIds}::text[]) OR h."userId" <> ${caller.ownerId})
    GROUP BY pool.id`;
  for (const pool of pools) {
    const row = rows.find((candidate) => candidate.poolId === pool.id);
    views.set(
      pool.id,
      row?.max != null
        ? { maxTimeoutMs: Number(row.max), timeoutZero: row.zero === true }
        : {
            // No usable path: the pool and deployment layers still bound it.
            maxTimeoutMs: Math.min(deploymentFiniteMaxMs(), pool.maxLeaseMs ?? LEASE_FINITE_MAX_MS),
            timeoutZero: false,
          },
    );
  }
  return views;
}

/** SANDBOX_CREATE_PROVISION_MAX_MS: a READY-based lease's reclaim backstop (M7). */
export function provisionMaxMs(): number {
  return env.SANDBOX_CREATE_PROVISION_MAX_MS ?? 7_200_000;
}
