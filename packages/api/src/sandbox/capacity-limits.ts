import { env } from "@wssp/env/server";
import { CAPACITY_WAIT_MAX_MS, type CapacityWaitRequest } from "@wssp/sandbox-contracts";
import { capacityWaitExceedsPolicy } from "./errors";

/**
 * Capacity-queue limits, layered like the lease policy (`lease-policy.ts`):
 * effective = min(deployment env, pool column), where `null` means "no limit
 * at that layer". A request over the effective limit is refused, never
 * clamped. Built-in bounds keep scans bounded even with "unlimited".
 */

/** Waiting entries per pool, so scans stay bounded even with "unlimited". */
export const CAPACITY_QUEUE_POOL_CEILING = 4096;
/** Interfering placements a head absorbs before strict mode (§4.3). */
export const HEAD_BYPASS_LIMIT = 8;
/** Entries one pass evaluates per pool, in seq order. */
export const QUEUE_SCAN_WINDOW = 64;
/** Placements one pass makes per pool (one per transaction). */
export const PASS_PLACEMENT_MAX = 64;
/** Fallback wake period; a missed wake costs at most this. */
export const QUEUE_RECHECK_MS = 15_000;
/** Strict heads read before selection (pools sharing a member host); over
 * this the per-host check at acceptance denies conservatively. */
export const GATE_HEAD_MAX = 256;

type Limit = number | null;

function configured(value: Limit | undefined, fallback: number): Limit {
  // A test env that omits the variable gets the schema default.
  return value === undefined ? fallback : value;
}

export function deploymentWaitMaxMs(): Limit {
  return configured(env.SANDBOX_CAPACITY_WAIT_MAX_MS, 3_600_000);
}
export function deploymentQueuePerKey(): Limit {
  return configured(env.SANDBOX_CAPACITY_QUEUE_MAX_PER_KEY, 16);
}
export function deploymentQueuePerOwner(): Limit {
  return configured(env.SANDBOX_CAPACITY_QUEUE_MAX_PER_OWNER, 64);
}

export function minLimit(a: Limit, b: Limit): Limit {
  if (a === null) return b;
  if (b === null) return a;
  return Math.min(a, b);
}

export type PoolQueueLayer = {
  capacityWaitMaxMs: number | null;
  capacityQueuePerKeyMax: number | null;
  capacityQueuePerOwnerMax: number | null;
};

/** Effective limits for one pool (`null` = unlimited; wait 0 = disabled). */
export function poolCapacityLimits(pool: PoolQueueLayer) {
  return {
    maxWaitMs: minLimit(deploymentWaitMaxMs(), pool.capacityWaitMaxMs),
    perKey: minLimit(deploymentQueuePerKey(), pool.capacityQueuePerKeyMax),
    perOwner: minLimit(deploymentQueuePerOwner(), pool.capacityQueuePerOwnerMax),
  };
}

export function waitWithinPolicy(request: CapacityWaitRequest, maxWaitMs: Limit): boolean {
  if (maxWaitMs === null) return true;
  return request !== "unlimited" && request <= maxWaitMs;
}

/** Refuse (never clamp). "unlimited" passes only when every layer is null. */
export function requireWaitWithinPolicy(request: CapacityWaitRequest, maxWaitMs: Limit): void {
  if (!waitWithinPolicy(request, maxWaitMs))
    throw capacityWaitExceedsPolicy(
      Math.min(maxWaitMs ?? CAPACITY_WAIT_MAX_MS, CAPACITY_WAIT_MAX_MS),
    );
}

/** Deadline of a wait that starts at `now` (DB clock); null waits forever. */
export function waitDeadline(request: CapacityWaitRequest, now: Date): Date | null {
  return request === "unlimited" ? null : new Date(now.getTime() + request);
}
