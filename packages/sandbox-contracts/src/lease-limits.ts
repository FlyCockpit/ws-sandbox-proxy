import limits from "./lease-limits.json";

/**
 * Lease policy bounds shared with the Rust relay contract
 * (`crates/sandbox-protocol/src/lease.rs` reads the same JSON).
 *
 * - `LEASE_LIMIT_MIN_MS`: the smallest finite value any policy layer may hold.
 * - `LEASE_FINITE_MAX_MS`: the largest finite lease (24 days; the operation
 *   row stores `leaseTimeoutMs` as a 32-bit integer). Longer means unlimited.
 * - `LEASE_UNLIMITED_DEADLINE_MS`: 9999-12-31T23:59:59.999Z, the stored and
 *   wire deadline of a sandbox with no lease timer (`timeoutMs: 0`).
 */
export const LEASE_LIMIT_MIN_MS: number = limits.limitMinMs;
export const LEASE_FINITE_MAX_MS: number = limits.finiteMaxMs;
export const LEASE_UNLIMITED_DEADLINE_MS: number = limits.unlimitedDeadlineMs;

/** True when a lease end is the far-future "no time limit" sentinel. */
export function isUnlimitedLeaseEnd(value: Date | string | number | null | undefined): boolean {
  if (value === null || value === undefined) return false;
  const ms =
    typeof value === "number"
      ? value
      : typeof value === "string"
        ? Date.parse(value)
        : value.getTime();
  return Number.isFinite(ms) && ms >= LEASE_UNLIMITED_DEADLINE_MS;
}
