import { beforeEach, expect, it, vi } from "vitest";
import { mockDeep } from "vitest-mock-extended";

vi.mock("@wssp/db", () => ({ default: mockDeep() }));
vi.mock("@wssp/env/server", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("rate-limiter-flexible", async (original) => {
  const actual = await original<typeof import("rate-limiter-flexible")>();
  return { ...actual, RateLimiterRedis: actual.RateLimiterMemory };
});

const { default: prisma } = await import("@wssp/db");
const { previewLeaseLowering } = await import("./pools");
const db = prisma as unknown as {
  sandboxPool: { findFirst: ReturnType<typeof vi.fn> };
  $queryRaw: ReturnType<typeof vi.fn>;
};

beforeEach(() => {
  db.sandboxPool.findFirst.mockResolvedValue({ id: "pool-1", userId: "owner" });
  db.$queryRaw.mockResolvedValue([]);
});

it("unit (mocked Prisma; real-DB counts: lease-enforcement.pg.test.ts) — the lowering preview spends an owner-scoped budget before querying, so one batched request cannot run it unbounded", async () => {
  const owner = { kind: "session" as const, ownerId: "owner" };
  const input = { scope: "pool" as const, poolId: "pool-1", maxLeaseMs: 3_600_000 };
  // One batch carrying more calls than the budget: the excess is refused.
  const outcomes = await Promise.allSettled(
    Array.from({ length: 31 }, () => previewLeaseLowering(owner, input)),
  );
  const refused = outcomes.filter((o) => o.status === "rejected");
  expect(outcomes.filter((o) => o.status === "fulfilled")).toHaveLength(30);
  expect(refused).toHaveLength(1);
  expect((refused[0] as PromiseRejectedResult).reason).toMatchObject({
    code: "TOO_MANY_REQUESTS",
  });
  // The refused call never reached the database.
  expect(db.sandboxPool.findFirst).toHaveBeenCalledTimes(30);
  // Another owner has an independent budget.
  await expect(
    previewLeaseLowering({ kind: "session", ownerId: "other" }, input),
  ).rejects.toMatchObject({ code: "NOT_FOUND" });
});

it("unit (mocked Prisma) — pool card summaries: owner-scoped aggregates per pool, in a constant number of queries", async () => {
  const { poolCardSummaries } = await import("./pools");
  const deep = prisma as unknown as {
    sandboxPoolMember: { groupBy: ReturnType<typeof vi.fn> };
    share: { groupBy: ReturnType<typeof vi.fn> };
  };
  deep.sandboxPoolMember.groupBy.mockResolvedValue([
    { poolId: "a", enabled: true, _count: { _all: 2 } },
    { poolId: "a", enabled: false, _count: { _all: 1 } },
  ]);
  deep.share.groupBy.mockResolvedValue([{ poolId: "a", _count: { _all: 3 } }]);
  db.$queryRaw.mockReset();
  db.$queryRaw.mockImplementation(async (strings: TemplateStringsArray) =>
    strings.join("?").includes("bool_or")
      ? [{ poolId: "a", max: 86_400_000, zero: false }]
      : [{ poolId: "a", memory: 98_304n, vcpu: 96n, connected: 1 }],
  );
  const owner = { kind: "session" as const, ownerId: "owner" };
  const summaries = await poolCardSummaries(owner, [
    { id: "a", maxLeaseMs: null },
    { id: "b", maxLeaseMs: 3_600_000 },
  ]);
  expect(summaries.get("a")).toEqual({
    hosts: { total: 3, enabled: 2, connected: 1 },
    people: 3,
    capacity: { memoryMiB: 98_304, vcpu: 96 },
    lease: { maxTimeoutMs: 86_400_000, timeoutZero: false },
  });
  // A pool with no usable host still answers, bounded by its own limit.
  expect(summaries.get("b")).toMatchObject({
    hosts: { total: 0, enabled: 0, connected: 0 },
    people: 0,
    capacity: { memoryMiB: 0, vcpu: 0 },
    lease: { maxTimeoutMs: 3_600_000 },
  });
  expect(deep.sandboxPoolMember.groupBy).toHaveBeenCalledWith(
    expect.objectContaining({
      where: { poolId: { in: ["a", "b"] }, userId: "owner", removedAt: null },
    }),
  );
  expect(deep.share.groupBy).toHaveBeenCalledWith(
    expect.objectContaining({ where: { poolId: { in: ["a", "b"] }, ownerUserId: "owner" } }),
  );
  expect(db.$queryRaw).toHaveBeenCalledTimes(2);
  expect(await poolCardSummaries(owner, [])).toEqual(new Map());
});
