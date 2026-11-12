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
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { vmRootChargeGiB } from "@wssp/sandbox-contracts";
import { afterAll, expect, it, vi } from "vitest";
import {
  assertHostDeletable,
  hostDrainStatus,
  initializeHostMemoryReservation,
  releaseLiveResourcesIfHeld,
  releaseLiveResourcesOnInventoryProof,
  releaseRootResources,
  reserveLiveResources,
  reserveRootResources,
} from "./host-admission";
import { lockHostByEpoch } from "./relay-fence";
import { SandboxIntegrityError } from "./sensitive-errors";
import { poolFixture } from "./testing/pool-fixtures";
import { seedSandboxInstance } from "./testing/resource-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());
async function fixture() {
  const f = await poolFixture(db);
  const pool = await db.inspect.sandboxHostStoragePool.findFirstOrThrow({
    where: { sandboxHostId: f.host.id },
  });
  const sandboxes = [];
  for (let i = 0; i < 2; i++)
    sandboxes.push(
      await seedSandboxInstance(db.inspect, {
        data: {
          diskGiB: 32,
          userId: f.id,
          templateId: f.revision.id,
          sandboxHostId: f.host.id,
          originHostId: f.host.id,
          state: "STOPPED",
          cpuCount: 1,
          memoryMiB: 512,
          diskReservationHeld: false,
        },
      }),
    );
  return { ...f, storage: pool, sandboxes };
}
type Fixture = Awaited<ReturnType<typeof fixture>>;
type Tx = Parameters<Parameters<typeof db.prisma.$transaction>[0]>[0];
async function locked<T>(f: Fixture, work: (tx: Tx) => Promise<T>) {
  return db.prisma.$transaction(async (tx) => {
    await lockOwnerForAdmission(tx, f.id);
    await lockHostByEpoch(tx, f.host.id, f.host.connectionEpoch, f.id);
    return work(tx);
  });
}
const claim = (f: Fixture, i = 0) => ({
  hostId: f.host.id,
  ownerId: f.id,
  sandboxId: f.sandboxes[i]!.id,
});
async function reserve(f: Fixture, i = 0) {
  return locked(f, async (tx) => {
    await reserveLiveResources(tx, claim(f, i));
    await reserveRootResources(tx, claim(f, i));
  });
}
async function ledger(f: Fixture) {
  const host = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } });
  const rows = await db.inspect.sandbox.findMany({
    where: {
      sandboxHostId: host.id,
      OR: [{ liveResourcesHeld: true }, { diskReservationHeld: true }],
    },
    take: 250,
    include: { CurrentPlacement: true },
  });
  const live = rows.filter((s) => s.liveResourcesHeld);
  const roots = rows.filter((s) => s.diskReservationHeld);
  expect(host.liveCount).toBe(live.length);
  expect(host.memoryReservedMiB).toBe(
    live.reduce((sum, s) => sum + s.CurrentPlacement!.chargedMemoryMiB!, 0),
  );
  expect(host.vcpuReserved).toBe(
    live.reduce((sum, s) => sum + s.CurrentPlacement!.chargedVcpu!, 0),
  );
  expect(host.rootCount).toBe(roots.length);
  const pool = await db.inspect.sandboxHostStoragePool.findUniqueOrThrow({
    where: { id: f.storage.id },
  });
  expect(pool.diskReservedGiB).toBe(roots.reduce((sum, s) => sum + s.rootChargeGiB!, 0));
  return host;
}

it.each(["ram", "vcpu", "disk", "ceiling"] as const)(
  "PG 1/12: last %s claim serializes at H and exactly one commits",
  async (reason) => {
    const f = await fixture();
    if (reason === "ram")
      await db.inspect.sandboxHost.update({
        where: { id: f.host.id },
        data: { daemonMemoryBudgetMiB: 1024 },
      });
    if (reason === "vcpu")
      await db.inspect.sandboxHost.update({
        where: { id: f.host.id },
        data: { daemonVcpuBudget: 1 },
      });
    if (reason === "disk")
      await db.inspect.sandboxHostStoragePool.update({
        where: { id: f.storage.id },
        data: { capacityGiB: vmRootChargeGiB(32) },
      });
    if (reason === "ceiling") {
      await db.inspect.sandbox.createMany({
        data: Array.from({ length: 249 }, () => ({
          hostOwnerId: f.id,
          id: randomUUID(),
          userId: f.id,
          templateId: f.revision.templateId,
          templateRevisionId: f.revision.id,
          originalSelector: "base",
          originHostId: f.host.id,
          sandboxHostId: f.host.id,
          state: "STOPPED",
          storagePoolId: f.storage.id,
          storagePoolName: f.storage.name,
          storageMarker: f.storage.marker,
          rootChargeGiB: 33,
          diskReservationHeld: true,
        })),
      });
      await locked(f, (tx) => initializeHostMemoryReservation(tx, f.host.id, f.id));
      await db.inspect.sandboxHostStoragePool.update({
        where: { id: f.storage.id },
        data: { capacityGiB: 20000 },
      });
    }
    const pause = db.pauseAt("winner", { after: /SELECT id FROM sandbox_host .*FOR UPDATE/ });
    const first = db.run("winner", () => reserve(f));
    await pause.waitReached();
    const second = db
      .run("loser", () => reserve(f, 1))
      .then(
        () => null,
        (e: unknown) => e,
      );
    await db.waitUntilBlocked("loser", { by: "winner" });
    pause.release();
    await first;
    expect(await second).toMatchObject({ data: { code: "sandbox.host_capacity", reason } });
    const h = await ledger(f);
    expect(h.liveCount).toBe(1);
    expect(h.rootCount).toBe(reason === "ceiling" ? 250 : 1);
  },
);

it("PG 2: a failed suffix rolls back all live/root counters and ownership bits", async () => {
  const f = await fixture();
  const before = await ledger(f);
  await expect(
    locked(f, async (tx) => {
      await reserveLiveResources(tx, claim(f));
      await reserveRootResources(tx, claim(f));
      throw Error("suffix");
    }),
  ).rejects.toThrow("suffix");
  expect(await ledger(f)).toEqual(before);
});

it("PG 5/7/12: duplicate stop/destroy release distinct lifetimes; healthy zero cap permits retained cold boot", async () => {
  const f = await fixture();
  await reserve(f);
  const stop = () => locked(f, (tx) => releaseLiveResourcesOnInventoryProof(tx, claim(f)));
  expect(await stop()).toBe(true);
  expect(await stop()).toBe(false);
  expect(await ledger(f)).toMatchObject({ liveCount: 0, rootCount: 1 });
  await db.inspect.sandboxHostStoragePool.update({
    where: { id: f.storage.id },
    data: { capacityGiB: 1, draining: true },
  });
  await locked(f, (tx) => reserveLiveResources(tx, claim(f)));
  await locked(f, (tx) => reserveLiveResources(tx, claim(f)));
  expect(await ledger(f)).toMatchObject({ liveCount: 1, rootCount: 1 });
  await stop();
  const destroy = () => locked(f, (tx) => releaseRootResources(tx, claim(f)));
  expect(await destroy()).toBe(true);
  expect(await destroy()).toBe(false);
  expect(await ledger(f)).toMatchObject({
    liveCount: 0,
    rootCount: 0,
    vcpuReserved: 0,
    memoryReservedMiB: 0,
  });
});

it("PG 6: reconstruction waits for H, then reads fresh pinned live/root aggregates", async () => {
  const f = await fixture();
  // Historical calibration weight differs from today's guest+overhead helper.
  await db.inspect.sandboxPlacement.update({
    where: { id: f.sandboxes[0]!.currentPlacementId! },
    data: { chargedMemoryMiB: 1536 },
  });
  const pause = db.pauseAt("reserve", { after: /SELECT id FROM sandbox_host .*FOR UPDATE/ });
  const first = db.run("reserve", () => reserve(f));
  await pause.waitReached();
  const rebuilt = db.run("rebuild", () =>
    locked(f, (tx) => initializeHostMemoryReservation(tx, f.host.id, f.id)),
  );
  await db.waitUntilBlocked("rebuild", { by: "reserve" });
  pause.release();
  await first;
  await rebuilt;
  expect(await ledger(f)).toMatchObject({
    liveCount: 1,
    memoryReservedMiB: 1536,
    vcpuReserved: 1,
    rootCount: 1,
  });
  await locked(f, (tx) => releaseLiveResourcesOnInventoryProof(tx, claim(f)));
  expect(await ledger(f)).toMatchObject({ memoryReservedMiB: 0, vcpuReserved: 0, rootCount: 1 });
});

it.each(["memoryReservedMiB", "vcpuReserved", "liveCount"] as const)(
  "PG 6/11: %s underflow aborts loudly, without repairing/clamping",
  async (field) => {
    const f = await fixture();
    await reserve(f);
    await db.inspect.sandboxHost.update({ where: { id: f.host.id }, data: { [field]: 0 } });
    await expect(
      locked(f, (tx) => releaseLiveResourcesOnInventoryProof(tx, claim(f))),
    ).rejects.toBeInstanceOf(SandboxIntegrityError);
    expect(
      (await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandboxes[0]!.id } }))
        .liveResourcesHeld,
    ).toBe(true);
  },
);

it("PG 7/10: uncertain create keeps both holds; proven first-unsent create releases both", async () => {
  const f = await fixture();
  await reserve(f);
  const input = {
    ...claim(f),
    kind: "CREATE_SANDBOX" as const,
    operationId: randomUUID(),
    sandboxStateBeforeResult: "PROVISIONING" as const,
  };
  await locked(f, (tx) => releaseLiveResourcesIfHeld(tx, { ...input, opState: "UNKNOWN_OUTCOME" }));
  expect(await ledger(f)).toMatchObject({ liveCount: 1, rootCount: 1 });
  await locked(f, (tx) =>
    releaseLiveResourcesIfHeld(tx, { ...input, opState: "FAILED", neverIssued: true }),
  );
  expect(await ledger(f)).toMatchObject({ liveCount: 0, rootCount: 0 });
});

it("PG 11: zero-live witness cross-checks both weights; roots block deletion after drain", async () => {
  const f = await fixture();
  await reserve(f);
  await locked(f, (tx) => releaseLiveResourcesOnInventoryProof(tx, claim(f)));
  const h = await ledger(f);
  expect(hostDrainStatus({ ...h, draining: true })).toMatchObject({ drained: true, rootCount: 1 });
  await expect(locked(f, (tx) => assertHostDeletable(tx, f.host.id, f.id))).rejects.toMatchObject({
    data: { code: "sandbox.host_delete_conflict" },
  });
  await db.inspect.sandboxHost.update({ where: { id: f.host.id }, data: { vcpuReserved: 1 } });
  await expect(locked(f, (tx) => assertHostDeletable(tx, f.host.id, f.id))).rejects.toBeInstanceOf(
    SandboxIntegrityError,
  );
});
