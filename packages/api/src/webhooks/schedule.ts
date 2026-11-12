/**
 * Delivery retry policy. Postgres owns the schedule; BullMQ only fires the
 * delayed job. Attempt n (1-based) runs `RETRY_DELAYS_MS[n - 1]` after the
 * previous failure, ±20% jitter: immediate, 30 s, 2 m, 5 m, 15 m, 30 m, 1 h,
 * 2 h, 4 h, 6 h, 8 h. Eleven attempts, the last about 21.9 h in, inside the 24 h
 * delivery window.
 */
export const RETRY_DELAYS_MS: readonly number[] = [
  0, 30_000, 120_000, 300_000, 900_000, 1_800_000, 3_600_000, 7_200_000, 14_400_000, 21_600_000,
  28_800_000,
];
export const WEBHOOK_MAX_ATTEMPTS = RETRY_DELAYS_MS.length;
export const WEBHOOK_TEST_MAX_ATTEMPTS = 1;
export const WEBHOOK_DELIVERY_WINDOW_MS = 24 * 3_600_000;
export const JITTER_RATIO = 0.2;
/** Retry-After is honored up to this cap, and never sooner than the schedule. */
export const RETRY_AFTER_CAP_MS = 3_600_000;

/** Disable after BOTH: failing for at least 72 h AND at least 20 consecutive failures. */
export const DISABLE_AFTER_FAILING_MS = 72 * 3_600_000;
export const DISABLE_AFTER_CONSECUTIVE_FAILURES = 20;

/** Lease on an IN_FLIGHT claim; an expired lease returns the delivery to PENDING. */
export const DELIVERY_LEASE_MS = 60_000;
/** Per-endpoint concurrent attempts, enforced in Postgres (all workers together). */
export const ENDPOINT_IN_FLIGHT_CAP = 2;
/** Pending deliveries per endpoint beyond which fan-out records CANCELLED rows. */
export const ENDPOINT_BACKLOG_CAP = 10_000;
/** Events are pruned after this long; deliveries and attempts cascade. */
export const WEBHOOK_LOG_RETENTION_DAYS = 7;
/** Redeliver refuses events this close to pruning, so a retry window always fits. */
export const REDELIVER_MAX_EVENT_AGE_MS =
  WEBHOOK_LOG_RETENTION_DAYS * 86_400_000 - WEBHOOK_DELIVERY_WINDOW_MS;

/** Delay before attempt `attempt` (2..max), jittered; `random` is in [0, 1). */
export function retryDelayMs(attempt: number, random: number = Math.random()): number {
  const base = RETRY_DELAYS_MS[Math.min(Math.max(attempt, 1), RETRY_DELAYS_MS.length) - 1] ?? 0;
  const factor = 1 - JITTER_RATIO + 2 * JITTER_RATIO * Math.min(Math.max(random, 0), 1);
  return Math.round(base * factor);
}

/**
 * When the next attempt runs after attempt `completed` failed, or null when the
 * delivery is exhausted (attempts used up, or the next time is past expiry).
 */
export function nextAttemptAt(input: {
  completed: number;
  maxAttempts: number;
  now: Date;
  expiresAt: Date;
  retryAfterSeconds?: number | null;
  random?: number;
}): Date | null {
  if (input.completed >= input.maxAttempts) return null;
  let delay = retryDelayMs(input.completed + 1, input.random);
  if (input.retryAfterSeconds != null && input.retryAfterSeconds > 0)
    delay = Math.max(delay, Math.min(input.retryAfterSeconds * 1000, RETRY_AFTER_CAP_MS));
  const at = new Date(input.now.getTime() + delay);
  return at.getTime() > input.expiresAt.getTime() ? null : at;
}

export function shouldDisableEndpoint(input: {
  failingSince: Date | null;
  consecutiveFailures: number;
  now: Date;
}): boolean {
  return (
    input.failingSince !== null &&
    input.now.getTime() - input.failingSince.getTime() >= DISABLE_AFTER_FAILING_MS &&
    input.consecutiveFailures >= DISABLE_AFTER_CONSECUTIVE_FAILURES
  );
}
