import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("./service", () => ({ runCommunityRefreshScan: vi.fn() }));

const { communityRefreshDueDay, redisCommunityRefreshClaims, startCommunityRefreshSchedule } =
  await import("./refresh-schedule");

/** In-memory Redis with the commands the claims use, TTLs on a manual clock. */
function memoryRedis() {
  let now = 0;
  const keys = new Map<string, { value: string; expiresAt: number }>();
  const live = (key: string) => {
    const entry = keys.get(key);
    if (entry && entry.expiresAt <= now) keys.delete(key);
    return keys.get(key);
  };
  const redis = {
    keys,
    advance: (seconds: number) => {
      now += seconds;
    },
    /** When set, the next SET applies but its reply is lost (rejects). */
    loseNextSetReply: false,
    get: vi.fn(async (key: string) => live(key)?.value ?? null),
    set: vi.fn(async (key: string, value: string, _ex: "EX", seconds: number, nx?: "NX") => {
      if (nx && live(key)) return null;
      keys.set(key, { value, expiresAt: now + seconds });
      if (redis.loseNextSetReply) {
        redis.loseNextSetReply = false;
        throw new Error("connection reset");
      }
      return "OK";
    }),
    eval: vi.fn(async (script: string, _n: number, key: string, token: string, ttl?: number) => {
      const entry = live(key);
      if (entry?.value !== token) return 0;
      if (script.includes('"expire"')) entry.expiresAt = now + Number(ttl);
      else keys.delete(key);
      return 1;
    }),
  };
  return redis;
}

const at = (iso: string) => () => new Date(iso);
const schedules: { stop: () => Promise<void> }[] = [];
function start(options: Parameters<typeof startCommunityRefreshSchedule>[0]) {
  const schedule = startCommunityRefreshSchedule({ intervalMs: 3_600_000, ...options });
  schedules.push(schedule);
  return schedule;
}
afterEach(async () => {
  await Promise.all(schedules.splice(0).map((schedule) => schedule.stop()));
  vi.restoreAllMocks();
});

describe("communityRefreshDueDay", () => {
  it("is due from 05:23 UTC, for that UTC day", () => {
    expect(communityRefreshDueDay(new Date("2026-11-15T05:22:59Z"))).toBeNull();
    expect(communityRefreshDueDay(new Date("2026-11-15T05:23:00Z"))).toBe("2026-11-15");
    expect(communityRefreshDueDay(new Date("2026-11-15T23:59:00Z"))).toBe("2026-11-15");
  });
});

describe("startCommunityRefreshSchedule", () => {
  it("runs one scan per UTC day across checks and servers", async () => {
    const redis = memoryRedis();
    const claims = redisCommunityRefreshClaims(redis);
    const scan = vi.fn(async () => ({ stopped: false }));
    const first = start({ claims, scan, clock: at("2026-11-15T06:00:00Z") });
    await first.check();
    await first.check();
    // A second server sharing Redis.
    await start({ claims, scan, clock: at("2026-11-15T07:00:00Z") }).check();
    expect(scan).toHaveBeenCalledTimes(1);
    // Done marker for the day, lease released.
    expect([...redis.keys.keys()]).toEqual(["wssp:community-refresh:v1:done:2026-11-15"]);
    await start({ claims, scan, clock: at("2026-11-16T05:30:00Z") }).check();
    expect(scan).toHaveBeenCalledTimes(2);
  });

  it("claims nothing before the day's time", async () => {
    const redis = memoryRedis();
    const scan = vi.fn(async () => ({ stopped: false }));
    await start({
      claims: redisCommunityRefreshClaims(redis),
      scan,
      clock: at("2026-11-15T05:00:00Z"),
    }).check();
    expect(redis.set).not.toHaveBeenCalled();
    expect(scan).not.toHaveBeenCalled();
  });

  it("a failed or stopped scan releases the lease and marks nothing done", async () => {
    const redis = memoryRedis();
    const claims = redisCommunityRefreshClaims(redis);
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    const failing = vi.fn(async () => {
      throw new Error("database down");
    });
    await start({ claims, scan: failing, clock: at("2026-11-15T06:00:00Z") }).check();
    expect(redis.keys.size).toBe(0);
    expect(error).toHaveBeenCalled();
    const stopped = vi.fn(async () => ({ stopped: true }));
    await start({ claims, scan: stopped, clock: at("2026-11-15T06:00:00Z") }).check();
    expect(redis.keys.size).toBe(0);
    const complete = vi.fn(async () => ({ stopped: false }));
    await start({ claims, scan: complete, clock: at("2026-11-15T06:00:00Z") }).check();
    expect(complete).toHaveBeenCalledTimes(1);
    expect([...redis.keys.keys()]).toEqual(["wssp:community-refresh:v1:done:2026-11-15"]);
  });

  it("a crashed scanner or a lost lease reply blocks the day only until the lease expires", async () => {
    const redis = memoryRedis();
    const claims = redisCommunityRefreshClaims(redis);
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    const scan = vi.fn(async () => ({ stopped: false }));
    // The lease SET applied but its reply was lost: this server never scans.
    redis.loseNextSetReply = true;
    await start({ claims, scan, clock: at("2026-11-15T06:00:00Z") }).check();
    expect(scan).not.toHaveBeenCalled();
    expect(error).toHaveBeenCalled();
    // Another server checks while the orphaned lease is live: skips.
    await start({ claims, scan, clock: at("2026-11-15T06:05:00Z") }).check();
    expect(scan).not.toHaveBeenCalled();
    // The lease expires (10 min); a later check the same day runs the scan.
    redis.advance(10 * 60);
    await start({ claims, scan, clock: at("2026-11-15T06:15:00Z") }).check();
    expect(scan).toHaveBeenCalledTimes(1);
    expect([...redis.keys.keys()]).toEqual(["wssp:community-refresh:v1:done:2026-11-15"]);
  });

  it("renews the lease while scanning and stops when it was lost", async () => {
    const redis = memoryRedis();
    const claims = redisCommunityRefreshClaims(redis);
    let shouldStop: () => boolean = () => false;
    let finish: () => void = () => {};
    const scan = vi.fn(
      (stop: () => boolean) =>
        new Promise<{ stopped: boolean }>((resolve) => {
          shouldStop = stop;
          finish = () => resolve({ stopped: stop() });
        }),
    );
    start({ claims, scan, clock: at("2026-11-15T06:00:00Z"), renewMs: 10 });
    await vi.waitFor(() => expect(scan).toHaveBeenCalledTimes(1));
    // Renewals keep a long scan's lease alive past its first TTL.
    await vi.waitFor(() => expect(redis.eval).toHaveBeenCalled());
    redis.advance(9 * 60);
    await vi.waitFor(() => expect(redis.eval.mock.calls.length).toBeGreaterThan(3));
    redis.advance(9 * 60);
    expect(redis.keys.has("wssp:community-refresh:v1:lease:2026-11-15")).toBe(true);
    expect(shouldStop()).toBe(false);
    // Someone else holds it now (e.g. it lapsed during a Redis outage).
    redis.keys.set("wssp:community-refresh:v1:lease:2026-11-15", {
      value: "other",
      expiresAt: Number.POSITIVE_INFINITY,
    });
    await vi.waitFor(() => expect(shouldStop()).toBe(true));
    finish();
    // The release (compare-and-delete) runs once the scan returns.
    await vi.waitFor(() =>
      expect(redis.eval).toHaveBeenCalledWith(
        expect.stringContaining('"del"'),
        1,
        "wssp:community-refresh:v1:lease:2026-11-15",
        expect.any(String),
      ),
    );
    expect(redis.keys.has("wssp:community-refresh:v1:done:2026-11-15")).toBe(false);
    // Its release never deletes the other holder's lease.
    expect(redis.keys.get("wssp:community-refresh:v1:lease:2026-11-15")?.value).toBe("other");
  });

  it("stops a scan whose renewals fail before the lease could expire", async () => {
    const redis = memoryRedis();
    const claims = redisCommunityRefreshClaims(redis);
    let ms = 0;
    let shouldStop: () => boolean = () => false;
    let finish: () => void = () => {};
    const scan = vi.fn(
      (stop: () => boolean) =>
        new Promise<{ stopped: boolean }>((resolve) => {
          shouldStop = stop;
          finish = () => resolve({ stopped: stop() });
        }),
    );
    start({ claims, scan, clock: at("2026-11-15T06:00:00Z"), renewMs: 10, now: () => ms });
    await vi.waitFor(() => expect(scan).toHaveBeenCalledTimes(1));
    // Redis becomes unreachable: every renewal rejects.
    redis.eval.mockRejectedValue(new Error("connection refused"));
    ms = 9 * 60_000;
    expect(shouldStop()).toBe(false);
    // Within one renewal interval of the 10-minute TTL: stop.
    ms = 10 * 60_000 - 10;
    expect(shouldStop()).toBe(true);
    finish();
    await vi.waitFor(() =>
      expect(redis.keys.has("wssp:community-refresh:v1:done:2026-11-15")).toBe(false),
    );
  });

  it("stop() signals the running scan and waits for it", async () => {
    const redis = memoryRedis();
    const claims = redisCommunityRefreshClaims(redis);
    let release: () => void = () => {};
    let shouldStop: () => boolean = () => false;
    const scan = vi.fn(
      (stop: () => boolean) =>
        new Promise<{ stopped: boolean }>((resolve) => {
          shouldStop = stop;
          release = () => resolve({ stopped: stop() });
        }),
    );
    const schedule = start({ claims, scan, clock: at("2026-11-15T06:00:00Z") });
    await vi.waitFor(() => expect(scan).toHaveBeenCalledTimes(1));
    // Single flight: a check while scanning does not start a second scan.
    void schedule.check();
    let stopped = false;
    const stopping = schedule.stop().then(() => {
      stopped = true;
    });
    await Promise.resolve();
    expect(shouldStop()).toBe(true);
    expect(stopped).toBe(false);
    release();
    await stopping;
    expect(scan).toHaveBeenCalledTimes(1);
    // Stopped early: the day is left for a later check.
    expect(redis.keys.size).toBe(0);
    await schedule.check();
    expect(scan).toHaveBeenCalledTimes(1);
  });
});
