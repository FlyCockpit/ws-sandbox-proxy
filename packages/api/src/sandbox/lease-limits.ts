/**
 * Lease bounds (PLAN shared decisions): five minutes by default; the default
 * deployment maximum is 24 hours. Pure constants so the browser form validates
 * with the server's own numbers; `lease-policy.ts` enforces the layered policy.
 */
export {
  isUnlimitedLeaseEnd,
  LEASE_FINITE_MAX_MS,
  LEASE_LIMIT_MIN_MS,
  LEASE_UNLIMITED_DEADLINE_MS,
} from "@wssp/sandbox-contracts";
export const LEASE_DEFAULT_MS = 300_000;
export const LEASE_MAX_MS = 24 * 60 * 60 * 1000;
