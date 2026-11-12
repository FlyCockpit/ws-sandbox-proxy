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
