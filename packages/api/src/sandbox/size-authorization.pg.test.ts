vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "capacity".repeat(10),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "pool-management-fixture",
  },
}));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";
import { createSandbox } from "./services/sandboxes";
import { allOwnedPoolKey, poolFixture, poolKey } from "./testing/pool-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());

async function counts(ownerId: string) {
  return {
    sandboxes: await db.inspect.sandbox.count({ where: { userId: ownerId } }),
    hosts: await db.inspect.sandboxHost.findMany({
      where: { userId: ownerId },
      select: { memoryReservedMiB: true, liveCount: true },
      orderBy: { id: "asc" },
      take: 10,
    }),
  };
}

it.each(["oversized", "no-report"] as const)(
  "B5 direct-grant 403 never reads capacity (%s)",
  async (mode) => {
    const f = await poolFixture(db);
    const key = await poolKey(db, f, [f.pool.id], [f.host.id]);
    await db.inspect.sandboxHost.update({
      where: { id: f.other.id },
      data:
        mode === "oversized"
          ? { daemonMaxCpuCount: 1, daemonMemoryBudgetMiB: 512 }
          : { daemonMaxCpuCount: null, daemonMemoryBudgetMiB: null },
    });
    const before = await counts(f.id);
    await expect(
      createSandbox(key.principal, {
        diskGiB: 32,
        template: `revision/${f.revision.id}`,
        sandboxHostId: f.other.id,
        cpuCount: 32,
        memoryMiB: 65536,
        idempotencyKey: randomUUID(),
      }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(await counts(f.id)).toEqual(before);
  },
);

it("B5 foreign/absent host under ALL_OWNED 404 never reads capacity", async () => {
  const f = await poolFixture(db);
  const foreign = await poolFixture(db);
  await db.inspect.sandboxHost.update({
    where: { id: foreign.host.id },
    data: { daemonMaxCpuCount: 1, daemonMemoryBudgetMiB: 512 },
  });
  const key = await allOwnedPoolKey(f);
  for (const hostId of [foreign.host.id, "absent-host"])
    await expect(
      createSandbox(key.principal, {
        diskGiB: 32,
        template: "base",
        sandboxHostId: hostId,
        cpuCount: 32,
        memoryMiB: 65536,
        idempotencyKey: randomUUID(),
      }),
    ).rejects.toMatchObject({ code: "NOT_FOUND", data: { code: "sandbox.host_not_found" } });
});

it.each(["hidden-fits", "hidden-too-small"] as const)(
  "B5 hidden pool member does not affect size diagnostic (%s)",
  async (mode) => {
    const f = await poolFixture(db);
    const key = await poolKey(db, f, [f.pool.id], [f.host.id]);
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { daemonMaxCpuCount: 1 },
    });
    await db.inspect.sandboxHost.update({
      where: { id: f.other.id },
      data: { daemonMaxCpuCount: mode === "hidden-fits" ? 32 : 1 },
    });
    await expect(
      createSandbox(key.principal, { ...f.input, cpuCount: 2, idempotencyKey: randomUUID() }),
    ).rejects.toMatchObject({ data: { code: "sandbox.vm_size_unsupported" } });
    // Visible host fits: hidden member's inability is irrelevant.
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { daemonMaxCpuCount: 4 },
    });
    await expect(
      createSandbox(key.principal, { ...f.input, cpuCount: 2, idempotencyKey: randomUUID() }),
    ).resolves.toMatchObject({ sandboxHostId: f.host.id, cpuCount: 2 });
  },
);

it("E1-A-04 a captured revision refuses a disk smaller than its image, direct and pooled", async () => {
  const f = await poolFixture(db);
  const key = await allOwnedPoolKey(f);
  // A captured image is the source VM's whole 32 GiB root.
  await db.inspect.sandboxTemplateRevision.update({
    where: { id: f.revision.id },
    data: { sourceKind: "CAPTURE", diskGiB: 32 },
  });
  const before = await counts(f.id);
  for (const target of [{ sandboxHostId: f.host.id }, { poolId: f.pool.id }])
    await expect(
      createSandbox(key.principal, {
        template: `revision/${f.revision.id}`,
        ...target,
        diskGiB: 16,
        idempotencyKey: randomUUID(),
      }),
    ).rejects.toMatchObject({ code: "BAD_REQUEST", data: { code: "sandbox.disk_below_image" } });
  expect(await counts(f.id)).toEqual(before);
  // The image's own size (and the default) still places.
  await expect(
    createSandbox(key.principal, {
      template: `revision/${f.revision.id}`,
      sandboxHostId: f.host.id,
      diskGiB: 32,
      idempotencyKey: randomUUID(),
    }),
  ).resolves.toMatchObject({ sandboxHostId: f.host.id, diskGiB: 32 });
  // A base (MANUAL) revision's diskGiB is only a default.
  await db.inspect.sandboxTemplateRevision.update({
    where: { id: f.revision.id },
    data: { sourceKind: "MANUAL" },
  });
  await expect(
    createSandbox(key.principal, {
      template: `revision/${f.revision.id}`,
      sandboxHostId: f.host.id,
      diskGiB: 16,
      idempotencyKey: randomUUID(),
    }),
  ).resolves.toMatchObject({ sandboxHostId: f.host.id, diskGiB: 16 });
});
