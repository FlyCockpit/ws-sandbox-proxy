import { seedAcceptedOperation } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "capacity".repeat(10),
    BETTER_AUTH_URL: "http://localhost:3000",
  },
}));

import { randomUUID } from "node:crypto";
import { bindHostStaticCapacity, type HostStaticCapacity } from "@wssp/api/sandbox/host-admission";
import { lockHostByEpoch } from "@wssp/api/sandbox/relay-fence";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, expect, it, vi } from "vitest";
import { createSandbox } from "../../../../packages/api/src/sandbox/services/sandboxes";
import { poolFixture } from "../../../../packages/api/src/sandbox/testing/pool-fixtures";
import { seedSandboxInstance } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";
import {
  convergeInventoryEntry,
  recordHostAdmission,
  recordHostInventory,
} from "./inventory-reconcile";

const db = await pgTestDatabase();
afterAll(() => db.close());
async function fixture(healthy = true) {
  const f = await poolFixture(db);
  const pool = await db.inspect.sandboxHostStoragePool.findFirstOrThrow({
    where: { sandboxHostId: f.host.id },
  });
  const capacity: HostStaticCapacity = {
    vmCapacity: { memoryBudgetMiB: 4096, maxCpuCount: 4, vcpuBudget: 8 },
    storagePools: [
      {
        name: pool.name,
        marker: pool.marker,
        health: healthy ? "healthy" : "unavailable",
        reason: healthy ? null : "io",
        totalBytes: null,
        usedBytes: null,
        freeBytes: null,
        capacityGiB: 96,
        totalBasedCapacityGiB: null,
        capacitySource: "explicit",
        derivationTotalBytes: null,
        derivationFreeBytes: null,
        derivationCommittedBytes: null,
        derivationActualBytes: null,
        derivationHeadroomBytes: null,
        implicitCeilingGiB: null,
        draining: false,
      },
    ],
  };
  await db.prisma.$transaction(async (tx) => {
    await lockOwnerForAdmission(tx, f.id);
    await lockHostByEpoch(tx, f.host.id, f.host.connectionEpoch, f.id);
    await bindHostStaticCapacity(tx, {
      hostId: f.host.id,
      ownerId: f.id,
      epoch: f.host.connectionEpoch,
      capacity,
    });
  });
  const sender = { hostId: f.host.id, userId: f.id, connectionEpoch: f.host.connectionEpoch };
  const report = {
    type: "host.admission" as const,
    connectionEpoch: sender.connectionEpoch,
    journalId: "b".repeat(32),
    runtimeKind: "fake" as const,
    schedulable: true,
    egressPolicy: true,
    terminal: true,
    ...capacity,
  };
  const observation = (sequence: number, health: "healthy" | "unavailable" = "healthy") => ({
    type: "inventory.update" as const,
    id: randomUUID(),
    connectionEpoch: sender.connectionEpoch,
    observationSequence: sequence,
    inventory: { hostId: f.host.id, schedulable: true, sandboxCount: 0 },
    storagePools: [
      {
        name: pool.name,
        marker: pool.marker,
        health,
        reason: health === "healthy" ? null : ("io" as const),
        totalBytes: null,
        usedBytes: null,
        freeBytes: null,
      },
    ],
  });
  return { ...f, sender, report, observation, storage: pool, capacity };
}

it("PG 9: current sender/static tuple are required; stale owner/epoch and conflicting repeats cannot write", async () => {
  const f = await fixture();
  const state = {};
  expect(await recordHostAdmission(f.sender, f.report, new Date(), state)).toBe(true);
  expect(await recordHostAdmission(f.sender, f.report, new Date(), state)).toBe(true);
  const before = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } });
  for (const sender of [
    { ...f.sender, userId: randomUUID() },
    { ...f.sender, connectionEpoch: 99 },
    { ...f.sender, isCurrent: () => false },
  ])
    expect(await recordHostAdmission(sender, f.report, new Date(), {})).toBe(false);
  for (const report of [
    { ...f.report, vmCapacity: { ...f.report.vmCapacity, vcpuBudget: 1 } },
    { ...f.report, storagePools: [{ ...f.capacity.storagePools[0]!, capacityGiB: 1 }] },
  ])
    expect(await recordHostAdmission(f.sender, report, new Date(), {})).toBe(false);
  expect(await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).toEqual(
    before,
  );
});

it("PG 4/9: observation sequences serialize at H, conflicting/older duplicates cannot refresh health", async () => {
  const f = await fixture();
  const gate = db.pauseAt("first", { after: /SELECT id FROM sandbox_host .*FOR UPDATE/ });
  const first = db.run("first", () =>
    recordHostInventory(f.sender, true, f.observation(2, "unavailable")),
  );
  await gate.waitReached();
  const second = db.run("second", () => recordHostInventory(f.sender, true, f.observation(1)));
  await db.waitUntilBlocked("second", { by: "first" });
  gate.release();
  expect(await first).toBe(true);
  expect(await second).toBe(false);
  const before = await db.inspect.sandboxHostStoragePool.findUniqueOrThrow({
    where: { id: f.storage.id },
  });
  expect(await recordHostInventory(f.sender, true, f.observation(2))).toBe(false);
  expect(await recordHostInventory(f.sender, true, f.observation(2, "unavailable"))).toBe(true);
  expect(
    await db.inspect.sandboxHostStoragePool.findUniqueOrThrow({ where: { id: f.storage.id } }),
  ).toEqual(before);
  expect(
    await recordHostInventory({ ...f.sender, userId: randomUUID() }, true, f.observation(3)),
  ).toBe(false);
});

it("PG 4/8: initial unavailable tuple remains closed to new roots after health-only recovery", async () => {
  const f = await fixture(false);
  expect(await recordHostInventory(f.sender, true, f.observation(1))).toBe(true);
  expect(
    await db.inspect.sandboxHostStoragePool.findUniqueOrThrow({ where: { id: f.storage.id } }),
  ).toMatchObject({ health: "healthy", newRootsAllowed: false });
  await expect(
    createSandbox(f.owner, {
      template: "base",
      sandboxHostId: f.host.id,
      idempotencyKey: randomUUID(),
    }),
  ).rejects.toMatchObject({ data: { code: "sandbox.host_capacity", reason: "storage" } });
});

it("PG 8: unavailable/mid-census storage and VM absence with an orphan root preserve disk commitments", async () => {
  const f = await fixture();
  const s = await createSandbox(f.owner, {
    template: "base",
    sandboxHostId: f.host.id,
    idempotencyKey: randomUUID(),
  });
  await db.inspect.sandbox.update({ where: { id: s.id }, data: { state: "READY" } });
  // Settlement needs no unresolved allocation attempt, so finish the fixture boot.
  await db.inspect.sandboxOperation.updateMany({
    where: { sandboxId: s.id },
    data: { state: "SUCCEEDED" },
  });
  await recordHostInventory(f.sender, true, f.observation(1, "unavailable"));
  expect(
    await convergeInventoryEntry(f.sender, {
      sandboxOwnerId: f.sender.userId,
      root: null,
      sandboxId: s.id,
      state: "absent",
    }),
  ).toEqual({
    converged: false,
  });
  expect(
    await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
  ).toMatchObject({ liveCount: 1, rootCount: 1 });
  await recordHostInventory(f.sender, true, f.observation(2));
  await convergeInventoryEntry(f.sender, {
    sandboxOwnerId: f.sender.userId,
    sandboxId: s.id,
    state: "absent",
    root: {
      storagePoolName: f.storage.name,
      storageMarker: f.storage.marker,
      diskGiB: 32,
      state: "present",
      networkCleanupComplete: false,
      observationSequence: 3,
    },
  });
  expect(
    await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
  ).toMatchObject({ liveCount: 0, rootCount: 1 });
  expect(
    await db.inspect.sandboxHostStoragePool.findUniqueOrThrow({ where: { id: f.storage.id } }),
  ).toMatchObject({ diskReservedGiB: 33 });
});

it("PG 7/8: root-only destroy can finish after stop; wrong marker cannot detach or release", async () => {
  const f = await fixture();
  const s = await seedSandboxInstance(db.inspect, {
    data: {
      userId: f.id,
      templateId: f.revision.id,
      sandboxHostId: f.host.id,
      originHostId: f.host.id,
      state: "RECLAIMING",
    },
  });
  await seedAcceptedOperation(db.inspect, {
    data: {
      userId: f.id,
      sandboxId: s.id,
      kind: "KILL_SANDBOX",
      state: "DISPATCHED",
      generation: s.generation,
      idempotencyKey: randomUUID(),
      requestBodyHash: "a".repeat(64),
      dispatchAttempt: 1,
      dispatchedHostId: f.host.id,
      dispatchedConnectionEpoch: f.sender.connectionEpoch,
    },
  });
  const proof = {
    storagePoolName: f.storage.name,
    storageMarker: "wrong",
    diskGiB: 32,
    state: "absent" as const,
    networkCleanupComplete: true,
    observationSequence: 3,
  };
  await convergeInventoryEntry(f.sender, {
    sandboxOwnerId: f.sender.userId,
    sandboxId: s.id,
    state: "absent",
    root: proof,
  });
  expect((await db.inspect.sandbox.findUniqueOrThrow({ where: { id: s.id } })).sandboxHostId).toBe(
    f.host.id,
  );
  await recordHostInventory(f.sender, true, f.observation(1));
  await convergeInventoryEntry(f.sender, {
    sandboxOwnerId: f.sender.userId,
    sandboxId: s.id,
    state: "absent",
    root: { ...proof, storageMarker: f.storage.marker },
  });
  expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: s.id } })).toMatchObject({
    state: "DELETED",
    sandboxHostId: null,
    diskReservationHeld: false,
    storagePoolId: null,
    storageMarker: f.storage.marker,
  });
  expect(
    await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
  ).toMatchObject({ liveCount: 0, rootCount: 0 });
});

it("PG 8: census root evidence is judged against its own observation; staleness is reported, never converged", async () => {
  const f = await fixture();
  const ready = async () => {
    const s = await createSandbox(f.owner, {
      template: "base",
      sandboxHostId: f.host.id,
      idempotencyKey: randomUUID(),
    });
    await db.inspect.sandbox.update({ where: { id: s.id }, data: { state: "READY" } });
    await db.inspect.sandboxOperation.updateMany({
      where: { sandboxId: s.id },
      data: { state: "SUCCEEDED" },
    });
    return s;
  };
  const stoppedEvidence = (sandboxId: string, observationSequence: number) => ({
    sandboxOwnerId: f.sender.userId,
    sandboxId,
    state: "stopped" as const,
    root: {
      storagePoolName: f.storage.name,
      storageMarker: f.storage.marker,
      diskGiB: 32,
      state: "present" as const,
      networkCleanupComplete: false,
      observationSequence,
    },
  });
  const pool = () =>
    db.inspect.sandboxHostStoragePool.findUniqueOrThrow({ where: { id: f.storage.id } });
  const state = async (id: string) =>
    (await db.inspect.sandbox.findUniqueOrThrow({ where: { id } })).state;
  const older = await ready();
  expect(await recordHostInventory(f.sender, true, f.observation(5))).toBe(true);
  const renewed = await pool();
  // Evidence collected before the pool's current observation never counts
  // (that observation may be a newer negative one) and never refreshes it:
  // it is reported as stale storage so the host retries it.
  expect(await convergeInventoryEntry(f.sender, stoppedEvidence(older.id, 3))).toEqual({
    converged: false,
    staleStorage: true,
  });
  expect(await state(older.id)).toBe("READY");
  expect(await pool()).toEqual(renewed);
  // Retried under the current observation, it converges.
  expect(await convergeInventoryEntry(f.sender, stoppedEvidence(older.id, 5))).toEqual({
    converged: true,
  });
  expect(await state(older.id)).toBe("STOPPED");
  // Current-sequence evidence whose pool health aged out (a census page the
  // server reached late) is refused by the retained-storage gate as stale.
  const late = await ready();
  await db.inspect.sandboxHostStoragePool.update({
    where: { id: f.storage.id },
    data: { reportedAt: new Date(Date.now() - 20_000) },
  });
  expect(await convergeInventoryEntry(f.sender, stoppedEvidence(late.id, 5))).toEqual({
    converged: false,
    staleStorage: true,
  });
  expect(await state(late.id)).toBe("READY");
  // An unavailable observation is a verdict, not staleness.
  expect(await recordHostInventory(f.sender, true, f.observation(6, "unavailable"))).toBe(true);
  expect(await convergeInventoryEntry(f.sender, stoppedEvidence(late.id, 6))).toEqual({
    converged: false,
  });
  expect(await state(late.id)).toBe("READY");
  expect(await pool()).toMatchObject({ health: "unavailable", observationSequence: 6n });
});
