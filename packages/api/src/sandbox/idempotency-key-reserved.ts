/** Reserved owner-wide idempotency namespaces for internal relay cleanup only. */
export const INTERNAL_IDEMPOTENCY_KEY_PREFIXES = [
  "lease-expire:",
  "readiness-failed:",
  "inventory-observed:",
  "access-expire:",
  "lease-policy:",
  /** Template-build orchestrator keys (`tb:<buildId>:…`). */
  "tb:",
  /** System retries of a failed stop/kill (`queueFailedTeardownRetry`). */
  "teardown-retry:",
] as const;

export function isReservedInternalIdempotencyKey(key: string): boolean {
  return INTERNAL_IDEMPOTENCY_KEY_PREFIXES.some((prefix) => key.startsWith(prefix));
}

export function leaseExpiryIdempotencyKey(
  sandboxId: string,
  generation: number,
  leaseRevision: number,
  action: import("@wssp/db").SandboxLeaseExpireAction,
): string {
  return `${INTERNAL_IDEMPOTENCY_KEY_PREFIXES[0]}${sandboxId}:${generation}:${leaseRevision}:${action}`;
}

export function readinessFailureIdempotencyKey(sandboxId: string, generation: number): string {
  return `${INTERNAL_IDEMPOTENCY_KEY_PREFIXES[1]}${sandboxId}:${generation}`;
}

export function inventoryObservationIdempotencyKey(sandboxId: string, generation: number): string {
  return `${INTERNAL_IDEMPOTENCY_KEY_PREFIXES[2]}${sandboxId}:${generation}`;
}

export function accessExpiryIdempotencyKey(
  sandboxId: string,
  generation: number,
  action: "STOP" | "DESTROY",
  deadline: Date | null,
): string {
  return `access-expire:${sandboxId}:${generation}:${action}:${deadline?.getTime() ?? "ban"}`;
}

/** Prefix of every system lease pull-in key (`leasePolicyIdempotencyKey`). */
export const LEASE_POLICY_KEY_PREFIX = INTERNAL_IDEMPOTENCY_KEY_PREFIXES[4];

/** System lease pull-in (§3.4): unique per attempt because the revision advances. */
export function leasePolicyIdempotencyKey(
  sandboxId: string,
  generation: number,
  leaseRevision: number,
): string {
  return `${LEASE_POLICY_KEY_PREFIX}${sandboxId}:${generation}:${leaseRevision}`;
}

/** The `retry`-th (1-based) system retry of a failed stop/kill, queued at
 * `generation`. */
export function teardownRetryIdempotencyKey(
  sandboxId: string,
  generation: number,
  retry: number,
): string {
  return `${INTERNAL_IDEMPOTENCY_KEY_PREFIXES[6]}${sandboxId}:${generation}:${retry}`;
}

/** Which system retry a teardown's key names: 0 for any other teardown. */
export function teardownRetryIndex(key: string): number {
  if (!key.startsWith(INTERNAL_IDEMPOTENCY_KEY_PREFIXES[6])) return 0;
  const retry = Number(key.slice(key.lastIndexOf(":") + 1));
  return Number.isSafeInteger(retry) && retry > 0 ? retry : 0;
}

export function isLeasePolicyIdempotencyKey(key: unknown): boolean {
  return typeof key === "string" && key.startsWith(INTERNAL_IDEMPOTENCY_KEY_PREFIXES[4]);
}
