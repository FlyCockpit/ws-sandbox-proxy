vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "capacity".repeat(10),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "capacity-test-credential-digest",
  },
}));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { VM_SIZE_LIMITS, vmLiveMemoryChargeMiB } from "@wssp/sandbox-contracts";
import { afterAll, expect, it, vi } from "vitest";
import { releaseLiveResourcesOnInventoryProof } from "./host-admission";
import { lockHostByEpoch } from "./relay-fence";
import { listHosts } from "./services/hosts";
import { createSandbox, reconnectSandbox } from "./services/sandboxes";
import { poolFixture, poolKey } from "./testing/pool-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());
type Fixture = Awaited<ReturnType<typeof poolFixture>>;
const direct = (f: Fixture) => ({
  ...f.input,
  poolId: undefined,
  sandboxHostId: f.host.id,
  idempotencyKey: randomUUID(),
});
const pooled = (f: Fixture) => ({ ...f.input, idempotencyKey: randomUUID() });
async function single() {
  const f = await poolFixture(db);
  await db.inspect.sandboxPoolMember.updateMany({
    where: { sandboxHostId: f.other.id },
    data: { enabled: false },
  });
  return f;
}
async function stop(f: Fixture, id: string) {
  await db.prisma.$transaction(async (tx) => {
    await lockOwnerForAdmission(tx, f.id);
    await lockHostByEpoch(tx, f.host.id, f.host.connectionEpoch, f.id);
    await releaseLiveResourcesOnInventoryProof(tx, {
      hostId: f.host.id,
      ownerId: f.id,
      sandboxId: id,
    });
    await tx.sandbox.update({ where: { id }, data: { state: "STOPPED" } });
  });
}

it.each(["daemonVcpuBudget", "daemonMemoryBudgetMiB", "daemonMaxCpuCount"] as const)(
  "PG 3: missing %s refuses both direct and SQL readiness",
  async (field) => {
    const f = await single();
    await db.inspect.sandboxHost.update({ where: { id: f.host.id }, data: { [field]: null } });
    await expect(createSandbox(f.owner, direct(f))).rejects.toMatchObject({
      data: { code: "sandbox.host_unavailable" },
    });
    await expect(createSandbox(f.owner, pooled(f))).rejects.toMatchObject({
      data: { code: "sandbox.pool_unavailable" },
    });
    expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
  },
);

it.each(["storage", "ram", "ceiling", "vcpu", "disk"] as const)(
  "PG 3: selection/recheck return the same bounded %s reason",
  async (reason) => {
    const f = await single();
    const host = { id: f.host.id };
    if (reason === "storage")
      await db.inspect.sandboxHostStoragePool.updateMany({
        where: { sandboxHostId: f.host.id },
        data: { health: "unavailable" },
      });
    if (reason === "ram")
      await db.inspect.sandboxHost.update({
        where: host,
        data: { daemonMemoryBudgetMiB: 1536, memoryReservedMiB: 512 },
      });
    if (reason === "ceiling")
      await db.inspect.sandboxHost.update({ where: host, data: { rootCount: 250 } });
    if (reason === "vcpu")
      await db.inspect.sandboxHost.update({
        where: host,
        data: { daemonVcpuBudget: 1, vcpuReserved: 1 },
      });
    if (reason === "disk")
      await db.inspect.sandboxHostStoragePool.updateMany({
        where: { sandboxHostId: f.host.id },
        data: { diskReservedGiB: 8192 },
      });
    // Current reservations or storage state block it: retryable on both paths.
    await expect(createSandbox(f.owner, direct(f))).rejects.toMatchObject({
      data: { code: "sandbox.host_capacity", reason, retryable: true },
    });
    await expect(createSandbox(f.owner, pooled(f))).rejects.toMatchObject({
      data: { code: "sandbox.pool_full", reason, retryable: true },
    });
  },
);

it("a request larger than the host's total vCPU budget is a permanent refusal on both paths", async () => {
  const f = await single();
  // Per-VM maximum allows 2 vCPU; the whole host budget is 1, even when empty.
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { daemonVcpuBudget: 1, vcpuReserved: 0, daemonMaxCpuCount: 4 },
  });
  await expect(createSandbox(f.owner, { ...direct(f), cpuCount: 2 })).rejects.toMatchObject({
    data: { code: "sandbox.host_capacity", reason: "vcpu", retryable: false },
  });
  await expect(createSandbox(f.owner, { ...pooled(f), cpuCount: 2 })).rejects.toMatchObject({
    data: { code: "sandbox.pool_full", reason: "vcpu", retryable: false },
  });
  // Offline members with otherwise feasible requests stay retryable.
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { status: "DISCONNECTED", daemonVcpuBudget: 4 },
  });
  await expect(createSandbox(f.owner, pooled(f))).rejects.toMatchObject({
    data: { code: "sandbox.pool_unavailable", retryable: true },
  });
  expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
});

it("PG 3: joint fit and visible-only diagnostics; RAM on one member and vCPU on another do not combine", async () => {
  const f = await poolFixture(db);
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { daemonMemoryBudgetMiB: 1536, memoryReservedMiB: 512 },
  });
  await db.inspect.sandboxHost.update({
    where: { id: f.other.id },
    data: { daemonVcpuBudget: 1, vcpuReserved: 1 },
  });
  await expect(createSandbox(f.owner, pooled(f))).rejects.toMatchObject({
    data: { code: "sandbox.pool_full", reason: "vcpu" },
  });
  const key = await poolKey(db, f, [f.pool.id], [f.host.id]);
  await expect(createSandbox(key.principal, pooled(f))).rejects.toMatchObject({
    data: { code: "sandbox.pool_full", reason: "ram" },
  });
});

it("PG 2/3/10: deterministic joint ranking, original allocation replay, source availability stays per host", async () => {
  const f = await poolFixture(db);
  await db.inspect.sandboxHost.updateMany({
    where: { userId: f.id },
    data: { daemonMemoryBudgetMiB: 4096 },
  });
  // Joint (dominant-share) ranking: one vCPU of a 2-vCPU budget dominates
  // `host`; `other` stays memory-dominant at a lower share.
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { daemonVcpuBudget: 2 },
  });
  const input = pooled(f);
  const accepted = await createSandbox(f.owner, input);
  expect(accepted.sandboxHostId).toBe(f.other.id);
  const s = await db.inspect.sandbox.findUniqueOrThrow({
    where: { id: accepted.id },
    include: { CurrentPlacement: true },
  });
  expect(s).toMatchObject({
    diskGiB: 32,
    rootChargeGiB: 33,
    liveResourcesHeld: true,
    diskReservationHeld: true,
    CurrentPlacement: {
      chargedMemoryMiB: vmLiveMemoryChargeMiB(1024),
      chargedVcpu: 1,
      diskGiB: 32,
      storagePoolId: s.storagePoolId,
    },
  });
  await db.inspect.sandboxHostStoragePool.updateMany({
    where: { sandboxHostId: f.other.id },
    data: { capacityGiB: 1, draining: true, health: "unavailable" },
  });
  await db.inspect.sandboxTemplateRevision.update({
    where: { id: f.revision.id },
    data: { diskGiB: 64, memoryMiB: 2048 },
  });
  expect((await createSandbox(f.owner, input)).id).toBe(accepted.id);
  expect(await db.inspect.sandboxTemplateAvailability.count({ where: { userId: f.id } })).toBe(2);
});

it("PG 2/12: direct and overlapping pool requests contend for the same host counters", async () => {
  const f = await single();
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { daemonMemoryBudgetMiB: 1536 },
  });
  const other = await db.inspect.sandboxPool.create({
    data: { userId: f.id, slug: "overlap", label: "Overlap" },
  });
  await db.inspect.sandboxPoolMember.create({
    data: {
      hostOwnerId: f.id,
      userId: f.id,
      poolId: other.id,
      sandboxHostId: f.host.id,
    },
  });
  // Pool selection's advisory prefix also serializes direct requests. Hold H
  // independently to prove the admission really waits for the durable host.
  const gate = db.pauseAt("holder", { after: /SELECT id FROM sandbox_host .*FOR UPDATE/ });
  const held = db.run("holder", () =>
    db.prisma.$transaction(async (tx) => {
      await lockHostByEpoch(tx, f.host.id, f.host.connectionEpoch, f.id);
    }),
  );
  await gate.waitReached();
  const first = db.run("direct", () => createSandbox(f.owner, direct(f)));
  await db.waitUntilBlocked("direct", { by: "holder" });
  const second = createSandbox(f.owner, { ...pooled(f), poolId: other.id }).then(
    () => null,
    (e: unknown) => e,
  );
  gate.release();
  await held;
  await first;
  expect(await second).toMatchObject({ data: { code: "sandbox.pool_full", reason: "ram" } });
  expect(
    await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
  ).toMatchObject({
    liveCount: 1,
    rootCount: 1,
    memoryReservedMiB: vmLiveMemoryChargeMiB(1024),
    vcpuReserved: 1,
  });
});

it.each(["capacity", "drain", "health"] as const)(
  "PG 4: %s report racing create is serialized under H and selection rechecks",
  async (field) => {
    const f = await single();
    const gate = db.pauseAt("report", { after: /SELECT id FROM sandbox_host .*FOR UPDATE/ });
    const report = db.run("report", () =>
      db.prisma.$transaction(async (tx) => {
        await lockHostByEpoch(tx, f.host.id, f.host.connectionEpoch, f.id);
        await tx.sandboxHostStoragePool.updateMany({
          where: { sandboxHostId: f.host.id },
          data:
            field === "capacity"
              ? { capacityGiB: 1 }
              : field === "drain"
                ? { draining: true }
                : { health: "unavailable" },
        });
      }),
    );
    await gate.waitReached();
    const work = db
      .run("create", () => createSandbox(f.owner, direct(f)))
      .then(
        () => null,
        (e: unknown) => e,
      );
    await db.waitUntilBlocked("create", { by: "report" });
    gate.release();
    await report;
    expect(await work).toMatchObject({
      data:
        field === "capacity"
          ? { code: "sandbox.vm_size_unsupported" }
          : { code: "sandbox.host_capacity", reason: "storage" },
    });
    expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
  },
);

it("PG 5: healthy zero implicit cap cold boot keeps root binding and pins a new live boot; warm renewal adds zero", async () => {
  const f = await single();
  const s = await createSandbox(f.owner, direct(f));
  await stop(f, s.id);
  await db.inspect.sandboxHostStoragePool.updateMany({
    where: { sandboxHostId: f.host.id },
    data: {
      capacityGiB: 0,
      capacitySource: "implicit",
      totalBasedCapacityGiB: 0,
      derivationTotalBytes: 1n,
      derivationFreeBytes: 0n,
      derivationCommittedBytes: 0n,
      derivationActualBytes: 0n,
      derivationHeadroomBytes: 0n,
      implicitCeilingGiB: 0,
      draining: false,
    },
  });
  await expect(createSandbox(f.owner, direct(f))).rejects.toMatchObject({
    data: { code: "sandbox.vm_size_unsupported" },
  });
  await db.inspect.sandboxHostStoragePool.updateMany({
    where: { sandboxHostId: f.host.id },
    data: { draining: true },
  });
  const reconnect = await reconnectSandbox(f.owner, {
    id: s.id,
    idempotencyKey: randomUUID(),
    timeoutMs: 60000,
  });
  expect(reconnect).toMatchObject({ state: "QUEUED" });
  expect(
    await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
  ).toMatchObject({ liveCount: 1, rootCount: 1 });
  const row = await db.inspect.sandbox.findUniqueOrThrow({
    where: { id: s.id },
    include: { CurrentPlacement: true },
  });
  expect(row.CurrentPlacement).toMatchObject({
    storagePoolId: row.storagePoolId,
    diskGiB: 32,
    chargedMemoryMiB: vmLiveMemoryChargeMiB(1024),
  });
  await db.inspect.sandbox.update({ where: { id: s.id }, data: { state: "READY" } });
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { daemonMemoryBudgetMiB: 512, daemonVcpuBudget: 1 },
  });
  await reconnectSandbox(f.owner, { id: s.id, mode: "warm", idempotencyKey: randomUUID() });
  expect(
    await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
  ).toMatchObject({
    liveCount: 1,
    rootCount: 1,
    memoryReservedMiB: vmLiveMemoryChargeMiB(1024),
    vcpuReserved: 1,
  });
});

it("PG 12: host list uses stored counts and a bounded query without per-host COUNT", async () => {
  const f = await single();
  await createSandbox(f.owner, direct(f));
  const page = await listHosts(f.owner, { limit: 10 });
  expect(page.items.find((h) => h.id === f.host.id)).toMatchObject({
    liveSandboxCount: 1,
    retainedRootCount: 1,
  });
});

it("PG 12/13: historical storage pages are bounded and require the explicit host grant", async () => {
  const f = await single();
  await db.inspect.sandboxHostStoragePool.createMany({
    data: Array.from({ length: 18 }, (_, i) => ({
      sandboxHostId: f.host.id,
      userId: f.id,
      name: `history-${i}`,
      marker: `history_${i}`,
      capacityGiB: 1,
      capacitySource: "explicit",
      health: "unavailable",
      healthReason: "missing",
      connectionEpoch: f.host.connectionEpoch,
      observationSequence: 0,
      reportedAt: new Date(),
    })),
  });
  const { listHostStoragePools } = await import("./services/hosts");
  const page = await listHostStoragePools(f.owner, { id: f.host.id, limit: 3 });
  expect(page.items).toHaveLength(3);
  expect(page.nextCursor).toBeTruthy();
  for (const pool of page.items) {
    expect(pool).not.toHaveProperty("userId");
    expect(pool).not.toHaveProperty("newRootsAllowed");
  }
  const hidden = await poolKey(db, f, [f.pool.id], [f.other.id]);
  await expect(
    listHostStoragePools(hidden.principal, { id: f.host.id, limit: 3 }),
  ).rejects.toMatchObject({ code: "FORBIDDEN" });
});

it("PG 3/6: a large pinned old RAM charge refuses identically without SQL integer overflow", async () => {
  const f = await single();
  const { seedSandboxInstance } = await import("./testing/resource-fixtures");
  const held = await seedSandboxInstance(db.inspect, {
    data: {
      userId: f.id,
      templateId: f.revision.id,
      sandboxHostId: f.host.id,
      originHostId: f.host.id,
      state: "READY",
      liveResourcesHeld: true,
    },
  });
  await db.inspect.sandboxPlacement.update({
    where: { id: held.currentPlacementId! },
    data: { chargedMemoryMiB: 2147483647 },
  });
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { memoryReservedMiB: 2147483647, liveCount: 1, vcpuReserved: 1 },
  });
  await expect(createSandbox(f.owner, direct(f))).rejects.toMatchObject({
    data: { code: "sandbox.host_capacity", reason: "ram" },
  });
  await expect(createSandbox(f.owner, pooled(f))).rejects.toMatchObject({
    data: { code: "sandbox.pool_full", reason: "ram" },
  });
});

it.each(["ram", "disk"] as const)(
  "qualification: impossible %s is non-retryable for direct and pooled creates",
  async (dimension) => {
    const f = await single();
    await db.inspect.sandboxHost.update({
      where: { id: f.host.id },
      data: { daemonMemoryBudgetMiB: 1280 },
    });
    await db.inspect.sandboxHostStoragePool.updateMany({
      where: { sandboxHostId: f.host.id },
      data: { capacityGiB: 155 },
    });
    for (const target of [direct(f), pooled(f)]) {
      for (const size of dimension === "ram"
        ? [{ memoryMiB: 1280 }, { memoryMiB: 1536 }]
        : [{ diskGiB: 155 }, { diskGiB: 200 }]) {
        await expect(createSandbox(f.owner, { ...target, ...size })).rejects.toMatchObject({
          data: { code: "sandbox.vm_size_unsupported" },
        });
      }
    }
    const hosts = await listHosts(f.owner, { limit: 10 });
    expect(hosts.items.find((h) => h.id === f.host.id)?.capacity.maxMemoryMiB).toBe(
      1280 - VM_SIZE_LIMITS.vmHostOverheadMiB,
    );
    expect(await db.inspect.sandbox.count({ where: { userId: f.id } })).toBe(0);
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
    ).toMatchObject({ liveCount: 0, rootCount: 0, memoryReservedMiB: 0 });
  },
);

it("qualification: fresh heartbeats never make stale storage health look healthy", async () => {
  const f = await single();
  await db.inspect.sandboxHostStoragePool.updateMany({
    where: { sandboxHostId: f.host.id },
    data: { health: "healthy", reportedAt: new Date(Date.now() - 60_000) },
  });
  const hosts = await listHosts(f.owner, { limit: 10 });
  expect(hosts.items.find((h) => h.id === f.host.id)?.storagePools).toEqual([
    expect.objectContaining({ health: "unavailable", reason: "incomplete" }),
  ]);
  await expect(createSandbox(f.owner, direct(f))).rejects.toMatchObject({
    data: { code: "sandbox.host_capacity", reason: "storage" },
  });
});
