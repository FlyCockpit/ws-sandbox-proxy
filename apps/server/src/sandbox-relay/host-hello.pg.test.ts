import { requestDigestMetadata } from "@wssp/api/sandbox/idempotency";
import { seedLaunchHost } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";
import { capacityFixture, helloFixture } from "./capacity-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, describe, expect, it, vi } from "vitest";
import {
  seedSandboxInstance,
  seedTemplateRevision,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

/** Hello keeps epoch/admission fences while count maxima cease to be inputs. */
vi.mock("@wssp/db", async () => {
  const { pgTestDatabase: database } = await import("@wssp/db/testing/pg");
  return { default: (await database()).prisma };
});
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
const wakes = vi.hoisted(() => ({ notify: vi.fn() }));
vi.mock("@wssp/api/sandbox/sharing-access", async (original) => ({
  ...(await original<typeof import("@wssp/api/sandbox/sharing-access")>()),
  notifySharingAccessChanged: wakes.notify,
}));

const db = await pgTestDatabase();
const { commitHostHello } = await import("./host-hello.js");
const { reserveLiveResources } = await import("@wssp/api/sandbox/host-admission");

afterAll(() => db.close());

const FP = `sha256:${"e".repeat(64)}`;
/** The reservation's host-row lock: the no-op epoch CAS (`lockHostByEpoch`). */
const RESERVATION_HOST_LOCK = /^sql:SELECT id FROM sandbox_host.*FOR UPDATE$/;

async function seed(_ownerCap: number, sandboxes: number) {
  const ownerId = `user-${randomUUID()}`;
  await db.inspect.user.create({
    data: { id: ownerId, name: "Owner", email: `${ownerId}@example.test` },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: ownerId,
      slug: "lab",
      label: "Lab",
      status: "CONNECTED",

      connectionEpoch: 1,
      egressEnforcement: true,
    },
  });
  const template = await seedTemplateRevision(db.inspect, {
    data: {
      userId: ownerId,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      imageRef: "images:ubuntu/24.04/cloud",
      incusFingerprint: FP,
    },
  });
  const sandboxIds: string[] = [];
  for (let index = 0; index < sandboxes; index++) {
    const sandbox = await seedSandboxInstance(db.inspect, {
      data: {
        userId: ownerId,
        sandboxHostId: host.id,
        originHostId: host.id,
        templateId: template.id,
      },
    });
    sandboxIds.push(sandbox.id);
  }
  return { ownerId, hostId: host.id, sandboxIds };
}

function hello(
  hostId: string,
  userId: string,
  _maximum: number,
  _versions = ["1.0"],
  _schedulable = true,
  appNow = new Date(),
  memoryBudgetMiB = 65536,
) {
  return commitHostHello({
    identity: { hostId, userId },
    now: appNow,
    message: (() => {
      const message = helloFixture(hostId, false);
      message.vmCapacity.memoryBudgetMiB = memoryBudgetMiB;
      return message;
    })(),
  });
}

const reserve = (fixture: { ownerId: string; hostId: string }, sandboxId: string) =>
  db.prisma.$transaction((tx) =>
    reserveLiveResources(tx, { hostId: fixture.hostId, ownerId: fixture.ownerId, sandboxId }),
  );

const hostRow = (hostId: string) =>
  db.inspect.sandboxHost.findUniqueOrThrow({
    where: { id: hostId },
    select: { liveCount: true },
  });

describe("B4 hello capacity lifecycle (real PostgreSQL)", () => {
  it("legacy wire maxima no longer impose a configurable count cap", async () => {
    const f = await seed(1, 5);
    await hello(f.hostId, f.ownerId, 1);
    for (const id of f.sandboxIds) await reserve(f, id);
    expect(await hostRow(f.hostId)).toMatchObject({ liveCount: 5 });
  });
  it("RAM budget includes per-VM overhead independently of legacy maximum", async () => {
    const f = await seed(99, 2);
    await db.inspect.sandboxHost.update({
      where: { id: f.hostId },
      data: { daemonMemoryBudgetMiB: 1536 },
    });
    await hello(f.hostId, f.ownerId, 999999999, ["1.0"], true, new Date(), 1536);
    await reserve(f, f.sandboxIds[0]!);
    await expect(reserve(f, f.sandboxIds[1]!)).rejects.toMatchObject({
      data: { code: "sandbox.host_capacity", reason: "ram" },
    });
  });
  it("PG 4: hello waits for H and preserves reservations while replacing the epoch", async () => {
    const f = await seed(4, 1);
    const gate = db.pauseAt("reserve", { after: RESERVATION_HOST_LOCK });
    const first = db.run("reserve", () => reserve(f, f.sandboxIds[0]!));
    await gate.waitReached();
    const second = db.run("hello", () => hello(f.hostId, f.ownerId, 1));
    await db.waitUntilBlocked("hello", { by: "reserve" });
    gate.release();
    await first;
    await second;
    expect(await hostRow(f.hostId)).toMatchObject({ liveCount: 1 });
  });
});

describe("2A hello observations remain inactive", () => {
  it("hello_epoch_clears_prior_admission_and_census_and_preserves_last_budget", async () => {
    const f = await seed(4, 1);
    const epoch = await hello(f.hostId, f.ownerId, 4, ["1.0"], false);
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } }),
    ).toMatchObject({
      admissionEpoch: null,
      daemonSchedulable: null,
      daemonFeatures: {},
      inventoryAcknowledgedEpoch: null,
      availabilityCensusComplete: false,
    });
    // Negative observation is stored, but mandatory new-launch admission is 3E.
    await reserve(f, f.sandboxIds[0]!);
    await db.inspect.sandboxHost.update({
      where: { id: f.hostId },
      data: {
        journalKeyVersion: 1,
        journalKeyId: "a".repeat(32),
        journalKeyAcknowledgedEpoch: epoch,
        inventoryAcknowledgedEpoch: epoch,
        availabilityEpoch: epoch,
        availabilityCensusComplete: true,
      },
    });
    await hello(f.hostId, f.ownerId, 4);
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } }),
    ).toMatchObject({
      journalKeyVersion: 1,
      journalKeyId: requestDigestMetadata().requestDigestKeyId,
      journalKeyAcknowledgedEpoch: null,
      admissionEpoch: null,
      daemonSchedulable: null,
      daemonFeatures: {},
      inventoryAcknowledgedEpoch: null,
      availabilityEpoch: null,
      availabilityCensusComplete: false,
    });
  });
});

it("hello_replacement_fences_a_paused_old_epoch_key_ack", async () => {
  const { acknowledgeJournalKey } = await import("./journal-key-ack.js");
  const { requestDigestMetadata } = await import("@wssp/api/sandbox/idempotency");
  const f = await seed(4, 1);
  const epoch = await hello(f.hostId, f.ownerId, 4, ["1.0"]);
  const gate = db.pauseAt("old-key-ack", {
    before: /^sql:SELECT id FROM sandbox_host.*FOR UPDATE$/,
  });
  const pending = db.run("old-key-ack", () =>
    acknowledgeJournalKey(
      { userId: f.ownerId, hostId: f.hostId, connectionEpoch: epoch },
      {
        type: "journal.key.ack",
        connectionEpoch: epoch,
        keyVersion: 1,
        keyId: requestDigestMetadata().requestDigestKeyId,
      },
    ),
  );
  await gate.waitReached();
  const replacement = await hello(f.hostId, f.ownerId, 4, ["1.0"]);
  gate.release();
  expect(await pending).toBe(false);
  expect(await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } })).toMatchObject(
    {
      connectionEpoch: replacement,
      journalKeyVersion: 1,
      journalKeyId: requestDigestMetadata().requestDigestKeyId,
      journalKeyAcknowledgedEpoch: null,
    },
  );
});

describe("3A host writer owner admission barriers", () => {
  const writers = [
    "hello",
    "heartbeat",
    "disconnect",
    "admission",
    "inventory",
    "census",
    "availability",
    "result",
    "receipt",
    "delete",
    "edit",
  ] as const;
  for (const writer of writers) {
    it(`${writer}: valid host writers wait for owner; unknown workload replies refuse before H`, async () => {
      const f = await seed(4, 0);
      const sender = { userId: f.ownerId, hostId: f.hostId, connectionEpoch: 1 };
      const rootGate = db.pauseAt("root", { before: "$transaction.commit" });
      const root = db.run("root", () =>
        db.prisma.$transaction(async (tx) => {
          await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${f.ownerId} FOR UPDATE`;
        }),
      );
      await rootGate.waitReached();
      const run = async () => {
        const { recordHostHeartbeat, recordHostAdmission, recordHostInventory, InventoryCensus } =
          await import("./inventory-reconcile.js");
        switch (writer) {
          case "hello":
            return hello(f.hostId, f.ownerId, 4);
          case "heartbeat":
            return recordHostHeartbeat(sender, undefined, new Date(0));
          case "disconnect":
            return (await import("./journal-key-ack.js")).disconnectJournalKey(
              sender,
              new Date(0),
              false,
            );
          case "admission":
            return recordHostAdmission(
              sender,
              {
                vmCapacity: { memoryBudgetMiB: 65536, maxCpuCount: 32, vcpuBudget: 64 },
                storagePools: capacityFixture(sender.hostId).storagePools,
                journalId: "1234567890abcdef1234567890abcdef",
                type: "host.admission",
                connectionEpoch: 1,
                runtimeKind: "fake",
                schedulable: true,
                egressPolicy: true,
                terminal: false,
              },
              new Date(0),
              {},
            );
          case "inventory":
            return recordHostInventory(sender, true);
          case "census":
            return new InventoryCensus(sender).acceptPage({
              type: "sandbox.inventory",
              page: 0,
              complete: true,
              entries: [],
            });
          case "availability": {
            // No revisions means next() reaches the durable completion write.
            await db.inspect.sandboxTemplateAvailability.deleteMany({
              where: { hostId: f.hostId },
            });
            return new (await import("./availability-census.js")).AvailabilityCensus(
              sender,
              () => undefined,
            ).next();
          }
          case "result":
            return (await import("./operation-handlers.js")).applyOperationResult({
              sender,
              operationId: randomUUID(),
              sandboxId: randomUUID(),
              generation: 1,
              attempt: 1,
              state: "failed",
              error: { code: "internal", message: "test" },
            });
          case "receipt":
            return (await import("./operation-handlers.js")).confirmOperationReceipt({
              sender,
              operationId: randomUUID(),
              sandboxId: randomUUID(),
              generation: 1,
              attempt: 1,
              state: "failed",
              written: true,
            });
          case "edit":
            return (await import("../../../../packages/api/src/sandbox/services/hosts")).updateHost(
              { kind: "session", ownerId: f.ownerId },
              { id: f.hostId, label: "Edited" },
            );
          case "delete":
            return (await import("../../../../packages/api/src/sandbox/services/hosts")).deleteHost(
              { kind: "session", ownerId: f.ownerId },
              { id: f.hostId },
            );
        }
      };
      const pending = db.run("writer", run);
      try {
        if (writer === "result" || writer === "receipt") {
          expect(await pending).toEqual(writer === "result" ? { written: false } : null);
        } else {
          const blocked = await db.waitUntilBlocked("writer", { by: "root" });
          expect(blocked.query).toMatch(/FROM "user".*FOR SHARE/);
        }
        // H is still free while this writer waits for its earlier owner rank.
        await db.inspect.$transaction(async (tx) => {
          await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${f.hostId} FOR UPDATE NOWAIT`;
        });
      } finally {
        rootGate.release();
      }
      await root;
      await pending;
    });
  }
});

it("3A after-H receipt clock ignores opposing app clocks and reversed BEGIN order", async () => {
  const { recordHostHeartbeat } = await import("./inventory-reconcile.js");
  const { isHostHeartbeatFresh, HOST_HEARTBEAT_STALE_AFTER_MS } = await import(
    "@wssp/config/host-status"
  );
  const f = await seed(4, 0);
  // First transaction begins early, but has not acquired H.
  const earlyGate = db.pauseAt("early", {
    before: /^sql:SELECT id FROM sandbox_host.*FOR UPDATE$/,
  });
  const early = db.run("early", () => hello(f.hostId, f.ownerId, 4, ["1.0"], true, new Date(0)));
  await earlyGate.waitReached();
  const sender = { userId: f.ownerId, hostId: f.hostId, connectionEpoch: 1 };
  expect(await recordHostHeartbeat(sender, undefined, new Date("2099-01-01"))).toBe(true);
  const before = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } });
  earlyGate.release();
  await early;
  const after = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } });
  expect(after.lastHeartbeatAt!.getTime()).toBeGreaterThanOrEqual(
    before.lastHeartbeatAt!.getTime(),
  );
  expect(after.lastConnectedAt).toEqual(after.lastHeartbeatAt);
  expect(Math.abs(after.lastHeartbeatAt!.getTime() - Date.now())).toBeLessThan(10_000);
  const current = { ...sender, connectionEpoch: after.connectionEpoch };
  // Queue a heartbeat behind H, and commit a later DB timestamp while it waits.
  const held = db.pauseAt("holder", { before: "$transaction.commit" });
  const holder = db.run("holder", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${f.hostId} FOR UPDATE`;
      await tx.$executeRaw`UPDATE sandbox_host SET "lastHeartbeatAt" = clock_timestamp() WHERE id = ${f.hostId}`;
    }),
  );
  await held.waitReached();
  const waiting = db.run("waiting", () => recordHostHeartbeat(current, undefined, new Date(0)));
  try {
    expect((await db.waitUntilBlocked("waiting", { by: "holder" })).query).toContain(
      "sandbox_host",
    );
  } finally {
    held.release();
  }
  await holder;
  expect(await waiting).toBe(true);
  const final = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } });
  expect(final.lastHeartbeatAt!.getTime()).toBeGreaterThanOrEqual(after.lastHeartbeatAt!.getTime());
  const now = final.lastHeartbeatAt!;
  expect(isHostHeartbeatFresh(null, now)).toBe(false);
  expect(isHostHeartbeatFresh(new Date(now.getTime() + 1), now)).toBe(false);
  expect(isHostHeartbeatFresh(new Date(now.getTime() - HOST_HEARTBEAT_STALE_AFTER_MS), now)).toBe(
    true,
  );
  expect(
    isHostHeartbeatFresh(new Date(now.getTime() - HOST_HEARTBEAT_STALE_AFTER_MS - 1), now),
  ).toBe(false);
  // Persist actual DB-relative future, stale, null and exact-boundary receipts.
  for (const age of [null, -60_000, 30_000, 30_001]) {
    await db.inspect.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${f.hostId} FOR UPDATE`;
      const samples = await tx.$queryRaw<
        { sampledAt: Date }[]
      >`SELECT clock_timestamp() AS "sampledAt"`;
      expect(samples).toHaveLength(1);
      const sampledAt = samples[0]!.sampledAt;
      await tx.sandboxHost.update({
        where: { id: f.hostId },
        data: { lastHeartbeatAt: age === null ? null : new Date(sampledAt!.getTime() - age) },
      });
      const stored = await tx.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } });
      expect(isHostHeartbeatFresh(stored.lastHeartbeatAt, sampledAt!)).toBe(age === 30_000);
    });
  }
  expect(await recordHostHeartbeat(sender, undefined, new Date())).toBe(false);
});

describe("host lease ceiling on hello (real PostgreSQL)", () => {
  it.each([
    ["explicit null → unlimited", null, null],
    ["finite → stored", 21_600_000, 21_600_000],
  ] as const)("%s, then wakes the pull-in sweep after commit", async (_label, reported, stored) => {
    const { ownerId, hostId } = await seed(1, 0);
    // The previous session negotiated the opposite: every hello rewrites it.
    await db.inspect.sandboxHost.update({
      where: { id: hostId },
      data: { daemonMaxLeaseMs: 3_600_000, daemonLeasePolicy: reported === undefined },
    });
    wakes.notify.mockClear();
    const message = helloFixture(hostId, false);
    message.daemon.capabilities.maxLeaseMs = reported;
    await commitHostHello({ identity: { hostId, userId: ownerId }, now: new Date(), message });
    const host = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: hostId } });
    expect(host.daemonMaxLeaseMs).toBe(stored);
    // Pull-in negotiation: only a daemon that reports the field gets them.
    expect(host.daemonLeasePolicy).toBe(reported !== undefined);
    expect(wakes.notify).toHaveBeenCalledTimes(1);
  });
});

describe("disk offload capability on hello (real PostgreSQL)", () => {
  it("records daemonDiskOffload per epoch: set when advertised, cleared by a hello without it", async () => {
    const { ownerId, hostId } = await seed(1, 0);
    const advertised = helloFixture(hostId, false);
    advertised.daemon.capabilities.image = {
      fetch: true,
      serve: false,
      publish: false,
      capture: false,
      acceptForeign: false,
      leaseFromReady: false,
      formats: ["unified"],
    };
    advertised.daemon.capabilities.diskOffload = true;
    await commitHostHello({
      identity: { hostId, userId: ownerId },
      now: new Date(),
      message: advertised,
    });
    const row = () =>
      db.inspect.sandboxHost.findUniqueOrThrow({
        where: { id: hostId },
        select: { daemonDiskOffload: true, connectionEpoch: true },
      });
    const first = await row();
    expect(first.daemonDiskOffload).toBe(true);
    await commitHostHello({
      identity: { hostId, userId: ownerId },
      now: new Date(),
      message: helloFixture(hostId, false),
    });
    const second = await row();
    expect(second.daemonDiskOffload).toBe(false);
    expect(second.connectionEpoch).toBe(first.connectionEpoch + 1);
  });
});
