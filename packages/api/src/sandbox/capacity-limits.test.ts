import { describe, expect, it, vi } from "vitest";

const env = vi.hoisted(() => ({
  SANDBOX_CAPACITY_WAIT_MAX_MS: 3_600_000 as number | null | undefined,
  SANDBOX_CAPACITY_QUEUE_MAX_PER_KEY: 16 as number | null | undefined,
  SANDBOX_CAPACITY_QUEUE_MAX_PER_OWNER: 64 as number | null | undefined,
}));
vi.mock("@wssp/env/server", () => ({ env }));

const { minLimit, poolCapacityLimits, requireWaitWithinPolicy, waitDeadline, waitWithinPolicy } =
  await import("./capacity-limits");

const pool = (wait: number | null, key: number | null = null, owner: number | null = null) => ({
  capacityWaitMaxMs: wait,
  capacityQueuePerKeyMax: key,
  capacityQueuePerOwnerMax: owner,
});

describe("capacity limits — unit (pure; enforcement under locks: capacity-queue.pg.test.ts)", () => {
  it.each([
    [null, null, null],
    [5, null, 5],
    [null, 7, 7],
    [5, 7, 5],
    [0, 7, 0],
  ] as const)("minLimit(%s, %s) = %s (null adds no limit)", (a, b, out) => {
    expect(minLimit(a, b)).toBe(out);
  });

  it("layers deployment and pool limits", () => {
    expect(poolCapacityLimits(pool(null))).toEqual({
      maxWaitMs: 3_600_000,
      perKey: 16,
      perOwner: 64,
    });
    expect(poolCapacityLimits(pool(60_000, 2, 3))).toEqual({
      maxWaitMs: 60_000,
      perKey: 2,
      perOwner: 3,
    });
    expect(poolCapacityLimits(pool(0))).toMatchObject({ maxWaitMs: 0 });
    env.SANDBOX_CAPACITY_WAIT_MAX_MS = null;
    env.SANDBOX_CAPACITY_QUEUE_MAX_PER_KEY = null;
    expect(poolCapacityLimits(pool(null))).toMatchObject({ maxWaitMs: null, perKey: null });
    env.SANDBOX_CAPACITY_WAIT_MAX_MS = undefined;
    expect(poolCapacityLimits(pool(null))).toMatchObject({ maxWaitMs: 3_600_000 });
    env.SANDBOX_CAPACITY_WAIT_MAX_MS = 3_600_000;
    env.SANDBOX_CAPACITY_QUEUE_MAX_PER_KEY = 16;
  });

  it('allows "unlimited" only when no layer limits the wait, and refuses (never clamps) over-limit waits', () => {
    expect(waitWithinPolicy("unlimited", null)).toBe(true);
    expect(waitWithinPolicy("unlimited", 3_600_000)).toBe(false);
    expect(waitWithinPolicy(3_600_000, 3_600_000)).toBe(true);
    expect(waitWithinPolicy(3_600_001, 3_600_000)).toBe(false);
    expect(waitWithinPolicy(1000, 0)).toBe(false);
    expect(() => requireWaitWithinPolicy(5_000, 1_000)).toThrow(
      expect.objectContaining({ data: { code: "capacity_wait_exceeds_policy", maxWaitMs: 1_000 } }),
    );
    expect(() => requireWaitWithinPolicy(1_000, 0)).toThrow(
      expect.objectContaining({ data: { code: "capacity_wait_exceeds_policy", maxWaitMs: 0 } }),
    );
    expect(() => requireWaitWithinPolicy("unlimited", null)).not.toThrow();
  });

  it("derives the deadline from the DB clock; unlimited has none", () => {
    const now = new Date("2026-11-02T00:00:00Z");
    expect(waitDeadline(30_000, now)?.toISOString()).toBe("2026-11-02T00:00:30.000Z");
    expect(waitDeadline("unlimited", now)).toBeNull();
  });
});
