vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "placement-freshness-fixture",
  },
}));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
// A report lands right after pool placement samples its clock
// (pool-placement.ts `sampledAt`) and before its candidate statement: the
// test's hook runs between the two, on its own connection, and commits.
const race = vi.hoisted(() => ({
  after: undefined as undefined | ((sampled: Date) => Promise<void>),
}));
vi.mock("./relay-fence", async (importOriginal) => {
  const real = await importOriginal<typeof import("./relay-fence")>();
  return {
    ...real,
    hostDatabaseNow: async (...args: Parameters<typeof real.hostDatabaseNow>) => {
      const now = await real.hostDatabaseNow(...args);
      const after = race.after;
      if (after && /pool-placement\.ts/.test(new Error().stack ?? "")) {
        race.after = undefined;
        await after(now);
      }
      return now;
    },
  };
});

import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, afterEach, expect, it, vi } from "vitest";
import { createSandbox } from "./services/sandboxes";
import { poolFixture } from "./testing/pool-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());
afterEach(() => {
  race.after = undefined;
});

const stamp = {
  // The daemon's storage report (inventory-reconcile.ts) and heartbeat, on
  // the database clock, committed before the hook returns; the new stamps.
  storage: (userId: string) => db.inspect.$queryRaw<{ at: Date }[]>`UPDATE sandbox_host_storage_pool
    SET "reportedAt" = clock_timestamp() AT TIME ZONE 'UTC' WHERE "userId" = ${userId}
    RETURNING "reportedAt" AS at`,
  heartbeat: (userId: string) => db.inspect.$queryRaw<{ at: Date }[]>`UPDATE sandbox_host
    SET "lastHeartbeatAt" = clock_timestamp() AT TIME ZONE 'UTC' WHERE "userId" = ${userId}
    RETURNING "lastHeartbeatAt" AS at`,
};

for (const kind of ["storage", "heartbeat"] as const)
  it(`a ${kind} report committed after placement sampled its clock still counts as fresh`, async () => {
    const f = await poolFixture(db);
    // Compared with the earlier sample the new stamps look future-dated, which
    // used to drop both hosts (`pool_full` reason `storage`, or the host
    // offline: `pool_unavailable`).
    race.after = async (sampled) => {
      // Strictly after the sample on every candidate, so the old inclusive
      // upper bound (`<= sampled`) would have refused them.
      await db.inspect.$executeRaw`SELECT pg_sleep(0.005)`;
      const stamps = await stamp[kind](f.id);
      expect(stamps).toHaveLength(2);
      for (const { at } of stamps) expect(at.getTime()).toBeGreaterThan(sampled.getTime());
    };
    const created = await createSandbox(f.owner, f.input);
    expect(race.after).toBeUndefined();
    expect([f.host.id, f.other.id]).toContain(created.sandboxHostId);
  });

it("a storage report dated in the future (a clock stepped back) is still refused", async () => {
  const f = await poolFixture(db);
  await db.inspect.$executeRaw`UPDATE sandbox_host_storage_pool
    SET "reportedAt" = (clock_timestamp() AT TIME ZONE 'UTC') + interval '60 seconds'
    WHERE "userId" = ${f.id}`;
  await expect(createSandbox(f.owner, f.input)).rejects.toMatchObject({
    data: { code: "sandbox.pool_full", reason: "storage" },
  });
});
