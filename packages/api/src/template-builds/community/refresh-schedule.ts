import { randomUUID } from "node:crypto";
import { redisConnection } from "@wssp/queue";
import { runCommunityRefreshScan } from "./service";

/**
 * The daily community refresh (S10), run by the server, never the worker.
 * A refresh writes a new upstream revision whose private defaults row is
 * MACed with `SANDBOX_REQUEST_HMAC_SECRET` and bound to `BETTER_AUTH_URL`,
 * and it accepts a build under the server's template-build policy. An
 * external worker has neither (it validates only `@wssp/env/shared`), so the
 * scan runs beside the build orchestrator, in both worker topologies.
 *
 * Once per UTC day, from 05:23 UTC: every server checks every few minutes.
 * A day is done once its completion marker exists; the marker is written only
 * after a scan finished. To scan, a server takes the day's short lease (a
 * random token, LEASE_TTL_SECONDS) and renews it while it scans; a server
 * that loses its lease, or cannot confirm a renewal before the lease could
 * have expired, stops scanning. A scan that fails or stops early
 * releases the lease; a crashed server, or a lease SET whose reply was lost,
 * holds it only until it expires, so another check retries the same day. A
 * repeat is safe (unchanged pins and active builds are skipped).
 */

/** Minutes after 00:00 UTC from which the day's scan is due (05:23 UTC). */
const COMMUNITY_REFRESH_UTC_MINUTE = 5 * 60 + 23;
const CHECK_INTERVAL_MS = 5 * 60_000;
/** A crashed scanner blocks the day's retry for at most this long. */
const LEASE_TTL_SECONDS = 10 * 60;
const LEASE_RENEW_MS = 60_000;
/** Outlives its day, so a finished day is never scanned again. */
const DONE_TTL_SECONDS = 2 * 86_400;
const KEY_PREFIX = "wssp:community-refresh:v1:";

/** The UTC day whose scan is due at `now`, or null before 05:23 UTC. */
export function communityRefreshDueDay(now: Date): string | null {
  const minute = now.getUTCHours() * 60 + now.getUTCMinutes();
  return minute >= COMMUNITY_REFRESH_UTC_MINUTE ? now.toISOString().slice(0, 10) : null;
}

/** The day's lease and completion marker (Redis in production). */
export type CommunityRefreshClaims = {
  isDone(day: string): Promise<boolean>;
  markDone(day: string): Promise<void>;
  /** Take the day's lease for `token` if nobody holds it. */
  acquire(day: string, token: string): Promise<boolean>;
  /** Extend the lease only while `token` still holds it. */
  renew(day: string, token: string): Promise<boolean>;
  /** Drop the lease only if `token` still holds it. */
  release(day: string, token: string): Promise<void>;
};

const RENEW_IF_OWNER =
  'if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("expire", KEYS[1], ARGV[2]) else return 0 end';
const RELEASE_IF_OWNER =
  'if redis.call("get", KEYS[1]) == ARGV[1] then return redis.call("del", KEYS[1]) else return 0 end';

/** The Redis commands the claims need; satisfied by `redisConnection`. */
type ClaimRedis = {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ex: "EX", seconds: number, nx?: "NX"): Promise<unknown>;
  eval(script: string, numKeys: number, ...args: (string | number)[]): Promise<unknown>;
};

export function redisCommunityRefreshClaims(redis: ClaimRedis): CommunityRefreshClaims {
  const lease = (day: string) => `${KEY_PREFIX}lease:${day}`;
  const done = (day: string) => `${KEY_PREFIX}done:${day}`;
  return {
    isDone: async (day) => (await redis.get(done(day))) !== null,
    markDone: async (day) => {
      await redis.set(done(day), "1", "EX", DONE_TTL_SECONDS);
    },
    acquire: async (day, token) =>
      (await redis.set(lease(day), token, "EX", LEASE_TTL_SECONDS, "NX")) === "OK",
    renew: async (day, token) =>
      Number(await redis.eval(RENEW_IF_OWNER, 1, lease(day), token, LEASE_TTL_SECONDS)) === 1,
    release: async (day, token) => {
      await redis.eval(RELEASE_IF_OWNER, 1, lease(day), token);
    },
  };
}

export function startCommunityRefreshSchedule(
  options: {
    claims?: CommunityRefreshClaims;
    scan?: (shouldStop: () => boolean) => Promise<{ stopped: boolean }>;
    clock?: () => Date;
    intervalMs?: number;
    renewMs?: number;
    /** Milliseconds for the local lease deadline (monotonic in production). */
    now?: () => number;
  } = {},
): { check: () => Promise<void>; stop: () => Promise<void> } {
  const claims = options.claims ?? redisCommunityRefreshClaims(redisConnection);
  const scan =
    options.scan ?? ((shouldStop) => runCommunityRefreshScan(new Date(), undefined, shouldStop));
  const clock = options.clock ?? (() => new Date());
  const now = options.now ?? (() => performance.now());
  const renewMs = options.renewMs ?? LEASE_RENEW_MS;
  // The lease is only trusted up to its TTL after the last confirmed SET or
  // renewal, minus one renewal interval of margin: if Redis stays unreachable,
  // the scan stops before another server can take the expired lease.
  const leaseValidMs = Math.max(LEASE_TTL_SECONDS * 1000 - renewMs, renewMs);
  let stopped = false;
  let running: Promise<void> | null = null;

  const runOnce = async () => {
    const day = communityRefreshDueDay(clock());
    if (!day || (await claims.isDone(day))) return;
    const token = randomUUID();
    let leaseUntil = now() + leaseValidMs;
    if (!(await claims.acquire(day, token))) return;
    let leaseLost = false;
    const renewal = setInterval(() => {
      const asked = now();
      claims
        .renew(day, token)
        .then((held) => {
          if (!held) leaseLost = true;
          else leaseUntil = asked + leaseValidMs;
        })
        .catch(() => {
          // Redis unreachable: the local deadline below stops the scan before
          // the lease can expire under it.
        });
    }, renewMs);
    renewal.unref?.();
    try {
      const result = await scan(() => stopped || leaseLost || now() >= leaseUntil);
      if (!result.stopped) await claims.markDone(day);
    } finally {
      clearInterval(renewal);
      await claims.release(day, token).catch(() => {});
    }
  };
  const check = (): Promise<void> => {
    if (stopped) return Promise.resolve();
    running ??= runOnce()
      .catch((error: unknown) => {
        console.error(
          "[community] Daily refresh scan failed; a later check retries:",
          error instanceof Error ? error.name : "error",
        );
      })
      .finally(() => {
        running = null;
      });
    return running;
  };
  const timer = setInterval(() => void check(), options.intervalMs ?? CHECK_INTERVAL_MS);
  timer.unref?.();
  void check();
  return {
    check,
    /** Idempotent. Resolves once no scan is running; never rejects. */
    stop: async () => {
      stopped = true;
      clearInterval(timer);
      await running;
    },
  };
}
