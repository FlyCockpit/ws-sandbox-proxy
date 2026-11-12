import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "capacity-view-fixture",
  },
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("./sharing-budgets", () => ({ consumePoolCapacityRead: async () => {} }));

import { poolCapacityView } from "./capacity-view";
import { poolFixture } from "./testing/pool-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());

it("excludes hosts with fresh heartbeats but expired egress guard leases from capacity and fits", async () => {
  const f = await poolFixture(db);
  const input = {
    id: f.pool.id,
    cpuCount: 1,
    memoryMiB: 512,
    diskGiB: 1,
  };
  const healthy = await poolCapacityView(f.owner, input);
  expect(healthy.fits).toBeGreaterThan(0);
  expect(healthy.aggregate.free.memoryMiB).toBeGreaterThan(0);
  expect(healthy.hosts).toHaveLength(2);
  expect(healthy.hosts.every((host) => host.schedulable)).toBe(true);

  const now = new Date();
  await db.inspect.sandboxHost.updateMany({
    where: { id: { in: [f.host.id, f.other.id] } },
    data: {
      lastHeartbeatAt: now,
      daemonEgressGuardOk: true,
      daemonEgressGuardLeaseUntil: new Date(now.getTime() - 1000),
    },
  });
  const expired = await poolCapacityView(f.owner, input);
  expect(expired.fits).toBe(0);
  expect(expired.aggregate).toEqual({
    free: { memoryMiB: 0, vcpu: 0, diskGiB: 0 },
    budget: { memoryMiB: 0, vcpu: 0, diskGiB: 0 },
  });
  expect(expired.hosts.every((host) => host.status === "CONNECTED" && !host.schedulable)).toBe(
    true,
  );
});
