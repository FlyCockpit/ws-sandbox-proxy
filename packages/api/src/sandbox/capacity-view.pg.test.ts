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
  // The largest single sandbox is bounded by what one host has free.
  expect(healthy.largest?.cpuCount).toBeGreaterThan(0);
  expect(healthy.largest?.memoryMiB).toBeGreaterThan(0);
  expect(healthy.largest?.cpuCount).toBeLessThanOrEqual(
    Math.max(...healthy.hosts.map((host) => host.vcpu.budget - host.vcpu.reserved)),
  );

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
  expect(expired.largest).toBeNull();
  expect(expired.aggregate).toEqual({
    free: { memoryMiB: 0, vcpu: 0, diskGiB: 0 },
    budget: { memoryMiB: 0, vcpu: 0, diskGiB: 0 },
  });
  expect(expired.hosts.every((host) => host.status === "CONNECTED" && !host.schedulable)).toBe(
    true,
  );
});

it("a template's disk defaults to its revision's default, and a disk below its minimum is refused like the create", async () => {
  const f = await poolFixture(db);
  await db.inspect.sandboxTemplateRevision.update({
    where: { id: f.revision.id },
    data: { minDiskGiB: 8, defaultDiskGiB: 32 },
  });
  await expect(
    poolCapacityView(f.owner, { id: f.pool.id, template: "base", diskGiB: 4 }),
  ).rejects.toMatchObject({ data: { code: "sandbox.disk_below_image" } });
  await expect(
    poolCapacityView(f.owner, { id: f.pool.id, template: "base", diskGiB: 8 }),
  ).resolves.toBeDefined();
  await expect(
    poolCapacityView(f.owner, { id: f.pool.id, template: "base" }),
  ).resolves.toBeDefined();
});
