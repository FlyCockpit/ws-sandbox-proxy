import {
  acknowledgeFixtureExecutionConfigs,
  seedAcceptedOperation,
  seedLaunchHost,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";
import { capacityFixture } from "./capacity-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, describe, expect, it, vi } from "vitest";
import { seedTemplateRevision } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

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
vi.mock("./session-manager.js", () => ({
  sandboxRelaySessionManager: {
    isHostConnected: vi.fn().mockReturnValue(true),
    dispatchOperation: vi.fn().mockReturnValue("sent"),
  },
}));

const db = await pgTestDatabase();
const { createSandboxInput } = await import("@wssp/api/sandbox/contracts");
const { createSandbox, killSandbox, reconnectSandbox, stopSandbox } = await import(
  "../../../../packages/api/src/sandbox/services/sandboxes"
);
const { applyOperationResult } = await import("./operation-handlers.js");
const { processSandboxOutboxBatch: processOutboxWithInstalledConfig } = await import(
  "./outbox-processor.js"
);
async function processSandboxOutboxBatch(
  ...args: Parameters<typeof processOutboxWithInstalledConfig>
) {
  await acknowledgeFixtureExecutionConfigs(db.inspect);
  return processOutboxWithInstalledConfig(...args);
}

const { InventoryCensus, convergeInventoryEntry } = await import("./inventory-reconcile.js");

afterAll(() => db.close());

const FP = `sha256:${"d".repeat(64)}`;
const clock = () => new Date();
type Seed = Awaited<ReturnType<typeof seedHost>>;

async function seedHost() {
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
  await db.inspect.sandboxHost.update({
    where: { id: host.id },
    data: { capacityReport: JSON.stringify(capacityFixture(host.id)) },
  });
  return { owner: { kind: "session" as const, ownerId }, hostId: host.id, templateId: template.id };
}

/** A host outage: the server restarts, the host reconnects under a new epoch. */
async function reconnectHost(seed: Seed) {
  const host = await db.inspect.sandboxHost.update({
    where: { id: seed.hostId },
    data: {
      connectionEpoch: { increment: 1 },
      journalKeyAcknowledgedEpoch: { increment: 1 },
      // The reconnected daemon renews its egress guard lease on the new epoch.
      daemonEgressGuardEpoch: { increment: 1 },
    },
  });
  await db.inspect.sandboxHostStoragePool.updateMany({
    where: { sandboxHostId: seed.hostId },
    data: { connectionEpoch: host.connectionEpoch, reportedAt: new Date() },
  });
  return { userId: seed.owner.ownerId, hostId: seed.hostId, connectionEpoch: host.connectionEpoch };
}

async function reportSucceeded(operationId: string, state: "ready" | "stopped", epoch: number) {
  const op = await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: operationId } });
  const event = await db.inspect.outboxEvent.findFirstOrThrow({
    where: { aggregateId: op.sandboxId, payload: { path: ["operationId"], equals: op.id } },
  });
  const payload = event.payload as Record<string, unknown>;
  return applyOperationResult(
    {
      sender: { userId: op.userId, hostId: op.dispatchedHostId!, connectionEpoch: epoch },
      operationId: op.id,
      sandboxId: op.sandboxId,
      generation: op.generation,
      attempt: op.dispatchAttempt,
      state: "succeeded",
      result: { state, ...(payload.lease ? { lease: payload.lease } : {}) },
    },
    clock,
  );
}

async function hostLeaseOf(sandboxId: string, expired: boolean, generation?: number) {
  const row = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
  return {
    generation: generation ?? row.generation,
    lease: {
      revision: row.leaseRevisionEffective!,
      deadlineUnixMs: row.leaseExpiresAtEffective!.getTime(),
      action:
        row.leaseExpireActionEffective === "DESTROY" ? ("destroy" as const) : ("stop" as const),
      expiryPolicy: "retry-force-60s" as const,
    },
    expired,
    expiryComplete: expired,
    timerExpired: expired,
  };
}

async function census(
  sender: Awaited<ReturnType<typeof reconnectHost>>,
  entries: {
    sandboxId: string;
    sandboxOwnerId?: string;
    state: "ready" | "stopped" | "absent";
    lease?: unknown;
  }[],
  options?: { pendingAbsentMax?: number },
) {
  const accepted = await new InventoryCensus(sender, clock, options).acceptPage({
    type: "sandbox.inventory",
    page: 0,
    complete: true,
    entries: (await Promise.all(
      entries.map(async (entry) => {
        const s = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: entry.sandboxId } });
        return {
          ...entry,
          sandboxOwnerId: s.userId,
          root:
            s.storagePoolName && s.storageMarker
              ? {
                  storagePoolName: s.storagePoolName,
                  storageMarker: s.storageMarker,
                  diskGiB: s.diskGiB,
                  state: entry.state === "absent" ? "absent" : "present",
                  networkCleanupComplete: entry.state === "absent",
                  observationSequence: 100,
                }
              : undefined,
        };
      }),
    )) as never,
  });
  expect(accepted).toEqual({ ok: true });
}

async function readySandbox(seed: Seed, onExpire: "stop" | "destroy" = "stop") {
  const sandbox = await createSandbox(
    seed.owner,
    createSandboxInput.parse({
      template: "revision/" + seed.templateId,
      sandboxHostId: seed.hostId,
      idempotencyKey: `create-${randomUUID()}`,
      lifecycle: { onTimeout: onExpire === "stop" ? "stop" : "kill" },
    }),
  );
  await processSandboxOutboxBatch(clock);
  const create = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: sandbox.id, kind: "CREATE_SANDBOX" },
  });
  expect(await reportSucceeded(create.id, "ready", 1)).toEqual({ written: true });
  return sandbox.id;
}

/**
 * census rule (R2, N2), §8.10 item 1 and M2 against real
 * PostgreSQL, through the real create/stop/census paths: a cached STOPPED
 * copy whose disk is STORED is never ERROR or DELETED; with the census
 * root-absence proof it detaches to OFFLOADED (root released), without one
 * the hold moves to a SandboxDiskCopy(STALE); a host-reported expiry DESTROY
 * is no DELETED cause; a copy row on its host is discard input, never a
 * remnant; reconnect is refused while an eviction is granted; a settled
 * SYSTEM_DETACH kill ends OFFLOADED.
 */
const { seedStoredOffload } = await import(
  "../../../../packages/api/src/sandbox/testing/offload-fixtures"
);

async function stoppedSandbox(seed: Seed, onExpire: "stop" | "destroy" = "stop") {
  const sandboxId = await readySandbox(seed, onExpire);
  await stopSandbox(seed.owner, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
  await processSandboxOutboxBatch(clock);
  const stop = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId, kind: "STOP_SANDBOX" },
  });
  expect(await reportSucceeded(stop.id, "stopped", 1)).toEqual({ written: true });
  return sandboxId;
}

/** The sandbox's disk is STORED (seq 1) and cached on its host. */
async function cache(seed: Seed, sandboxId: string) {
  const s = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
  const stored = await seedStoredOffload(db.inspect, {
    userId: s.userId,
    sandboxId,
    hostId: seed.hostId,
  });
  await db.inspect.sandboxDiskOffload.update({
    where: { id: stored.offloadId },
    data: { sourceGeneration: s.generation },
  });
  await db.inspect.sandbox.update({
    where: { id: sandboxId },
    data: { diskOffloadId: stored.offloadId, cachedOffloadSeq: 1, offloadSeq: 1 },
  });
  return stored.offloadId;
}

const counters = async (hostId: string) => {
  const host = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: hostId } });
  const pools = await db.inspect.sandboxHostStoragePool.findMany({
    where: { sandboxHostId: hostId },
  });
  return { rootCount: host.rootCount, reserved: pools.reduce((n, p) => n + p.diskReservedGiB, 0) };
};

describe("offload census rule (§7 R2/N2, I3, I5)", () => {
  it("VM absent with the census root-absence proof: OFFLOADED, the root released once", async () => {
    const seed = await seedHost();
    const sandboxId = await stoppedSandbox(seed);
    const offloadId = await cache(seed, sandboxId);
    const before = await counters(seed.hostId);
    await census(await reconnectHost(seed), [{ sandboxId, state: "absent" }]);
    const row = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
    expect(row).toMatchObject({
      state: "OFFLOADED",
      sandboxHostId: null,
      diskReservationHeld: false,
      diskOffloadId: offloadId,
    });
    expect(await db.inspect.sandboxDiskCopy.count({ where: { sandboxId } })).toBe(0);
    expect((await counters(seed.hostId)).rootCount).toBe(before.rootCount - 1);
    expect(
      (await db.inspect.sandboxDiskOffload.findUniqueOrThrow({ where: { id: offloadId } })).state,
    ).toBe("STORED");
  });

  it("VM absent without root evidence (silence): the hold moves to a STALE copy, then OFFLOADED", async () => {
    const seed = await seedHost();
    const sandboxId = await stoppedSandbox(seed);
    await cache(seed, sandboxId);
    const before = await counters(seed.hostId);
    const s = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
    // A complete census that omits it: silent absence carries no root.
    await census(await reconnectHost(seed), []);
    const row = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
    expect(row.state).toBe("OFFLOADED");
    const create = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId, kind: "CREATE_SANDBOX" },
    });
    expect(
      await db.inspect.sandboxDiskCopy.findFirstOrThrow({ where: { sandboxId } }),
    ).toMatchObject({
      state: "STALE",
      hostId: seed.hostId,
      storageMarker: s.storageMarker,
      storagePoolName: s.storagePoolName,
      rootChargeGiB: s.rootChargeGiB,
      createKey: create.idempotencyKey,
      baseFingerprint: FP,
      diskReservationHeld: true,
    });
    expect(await counters(seed.hostId)).toEqual(before);
  });

  it.each([
    ["with the root-absence proof (root released)", true],
    ["without root evidence (a STALE copy)", false],
  ])(
    "I3: an ERROR row holding its stored disk, VM absent %s: OFFLOADED, never ERROR",
    async (_, proof) => {
      const seed = await seedHost();
      const sandboxId = await stoppedSandbox(seed);
      await cache(seed, sandboxId);
      // A restore whose cleanup stayed pending (§8.7 U10) keeps its stored disk.
      await db.inspect.sandbox.update({
        where: { id: sandboxId },
        data: { state: "ERROR", lastErrorCode: "restore_cleanup_pending" },
      });
      const before = await counters(seed.hostId);
      await census(await reconnectHost(seed), proof ? [{ sandboxId, state: "absent" }] : []);
      const row = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
      expect(row).toMatchObject({ state: "OFFLOADED", sandboxHostId: null });
      expect(row.diskOffloadId).not.toBeNull();
      expect(await db.inspect.sandboxDiskCopy.count({ where: { sandboxId } })).toBe(proof ? 0 : 1);
      expect((await counters(seed.hostId)).rootCount).toBe(before.rootCount - (proof ? 1 : 0));
    },
  );

  it("a host-reported expiry DESTROY is not a DELETED cause while the disk is offloaded", async () => {
    const seed = await seedHost();
    const sandboxId = await stoppedSandbox(seed, "destroy");
    await cache(seed, sandboxId);
    const past = new Date(Date.now() - 120_000);
    await db.inspect.sandbox.update({
      where: { id: sandboxId },
      data: { leaseExpiresAt: past, leaseExpiresAtEffective: past },
    });
    await census(await reconnectHost(seed), [
      { sandboxId, state: "absent", lease: await hostLeaseOf(sandboxId, true, 1) },
    ]);
    const row = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
    expect(row.state).toBe("OFFLOADED");
    expect(row.diskOffloadId).not.toBeNull();
    expect(
      await db.inspect.sandboxOperation.count({ where: { sandboxId, kind: "KILL_SANDBOX" } }),
    ).toBe(0);
  });

  it("a copy row on its host is discard input, never a remnant re-charge (§8.10 item 1)", async () => {
    const seed = await seedHost();
    const sandboxId = await stoppedSandbox(seed);
    await cache(seed, sandboxId);
    const sender = await reconnectHost(seed);
    await census(sender, []);
    const copy = await db.inspect.sandboxDiskCopy.findFirstOrThrow({ where: { sandboxId } });
    await db.inspect.sandboxDiskCopy.update({
      where: { id: copy.id },
      data: { discardSentAt: new Date() },
    });
    const before = await counters(seed.hostId);
    // The stale VM still reports on that host.
    const outcome = await convergeInventoryEntry(
      sender,
      { sandboxId, sandboxOwnerId: seed.owner.ownerId, state: "stopped" },
      clock,
      undefined,
      true,
    );
    expect(outcome).toEqual({ converged: false });
    expect(
      (await db.inspect.sandboxDiskCopy.findUniqueOrThrow({ where: { id: copy.id } }))
        .discardSentAt,
    ).toBeNull();
    const row = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
    expect(row).toMatchObject({ state: "OFFLOADED", liveResourcesHeld: false });
    expect(await counters(seed.hostId)).toEqual(before);
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: seed.hostId } }))
        .quarantinedAt,
    ).toBeNull();
    // §8.10 pg cell: once DELETED, the copy-row VM on that host is still
    // discarded once (copy first), never a remnant destroy re-charging it.
    await killSandbox(seed.owner, { id: sandboxId, idempotencyKey: `kill-${randomUUID()}` });
    expect((await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } })).state).toBe(
      "DELETED",
    );
    const deletedBefore = await counters(seed.hostId);
    for (const _report of [1, 2])
      expect(
        await convergeInventoryEntry(
          sender,
          { sandboxId, sandboxOwnerId: seed.owner.ownerId, state: "stopped" },
          clock,
          undefined,
          true,
        ),
      ).toEqual({ converged: false });
    expect(await counters(seed.hostId)).toEqual(deletedBefore);
    expect(
      await db.inspect.sandboxOperation.count({
        where: { sandboxId, kind: "KILL_SANDBOX", teardownPriorState: "DELETED" },
      }),
    ).toBe(0);
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: seed.hostId } })).liveCount,
    ).toBe(0);
  });

  it("an OFFLOADED sandbox's absence on its former host is no conflict", async () => {
    const seed = await seedHost();
    const sandboxId = await stoppedSandbox(seed);
    await cache(seed, sandboxId);
    const sender = await reconnectHost(seed);
    await census(sender, [{ sandboxId, state: "absent" }]);
    expect(
      await convergeInventoryEntry(
        sender,
        { sandboxId, sandboxOwnerId: seed.owner.ownerId, state: "absent" },
        clock,
        undefined,
        true,
      ),
    ).toEqual({ converged: false });
  });
});

describe("eviction marker (§7 steps 4, Expired grant without proof)", () => {
  async function evicting(seed: Seed, sandboxId: string, offloadId: string, expiresAt: Date) {
    const host = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: seed.hostId } });
    await db.inspect.sandboxDiskOffload.update({
      where: { id: offloadId },
      data: {
        state: "EVICTING",
        evictGrantId: `evg_${randomUUID().replaceAll("-", "")}`,
        evictHostId: seed.hostId,
        evictGrantEpoch: host.connectionEpoch,
        evictGrantedAt: new Date(expiresAt.getTime() - 600_000),
        evictGrantExpiresAt: expiresAt,
      },
    });
    return sandboxId;
  }

  it("a reconnect after the grant, before the proof, is refused sandbox.disk_evicting", async () => {
    const seed = await seedHost();
    const sandboxId = await stoppedSandbox(seed);
    const offloadId = await cache(seed, sandboxId);
    await evicting(seed, sandboxId, offloadId, new Date(Date.now() + 600_000));
    await expect(
      reconnectSandbox(seed.owner, { id: sandboxId, idempotencyKey: `re-${randomUUID()}` }),
    ).rejects.toMatchObject({ data: { code: "sandbox.disk_evicting" } });
    expect((await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } })).state).toBe(
      "STOPPED",
    );
  });

  it("an expired grant whose VM the census shows present is cleared back to STORED", async () => {
    const seed = await seedHost();
    const sandboxId = await stoppedSandbox(seed);
    const offloadId = await cache(seed, sandboxId);
    await evicting(seed, sandboxId, offloadId, new Date(Date.now() - 1000));
    await census(await reconnectHost(seed), [{ sandboxId, state: "stopped" }]);
    expect(
      await db.inspect.sandboxDiskOffload.findUniqueOrThrow({ where: { id: offloadId } }),
    ).toMatchObject({ state: "STORED", evictGrantId: null });
    expect((await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } })).state).toBe(
      "STOPPED",
    );
  });

  it("an expired grant whose root the census proves absent completes the eviction", async () => {
    const seed = await seedHost();
    const sandboxId = await stoppedSandbox(seed);
    const offloadId = await cache(seed, sandboxId);
    await evicting(seed, sandboxId, offloadId, new Date(Date.now() - 1000));
    await census(await reconnectHost(seed), [{ sandboxId, state: "absent" }]);
    expect((await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } })).state).toBe(
      "OFFLOADED",
    );
    expect(
      await db.inspect.sandboxDiskOffload.findUniqueOrThrow({ where: { id: offloadId } }),
    ).toMatchObject({ state: "STORED", evictGrantId: null });
  });
});

describe("teardown settle passes teardownIntent (M2)", () => {
  it("a settled SYSTEM_DETACH kill of an offloaded disk ends OFFLOADED, never DELETED", async () => {
    const seed = await seedHost();
    const sandboxId = await stoppedSandbox(seed);
    const offloadId = await cache(seed, sandboxId);
    const sender = await reconnectHost(seed);
    const s = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
    await db.inspect.sandbox.update({ where: { id: sandboxId }, data: { state: "STOPPING" } });
    const kill = await seedAcceptedOperation(db.inspect, {
      data: {
        userId: s.userId,
        sandboxId,
        kind: "KILL_SANDBOX",
        state: "DISPATCHED",
        generation: s.generation,
        idempotencyKey: `detach-${randomUUID()}`,
        requestBodyHash: "a".repeat(64),
        teardownIntent: "SYSTEM_DETACH",
        dispatchedHostId: seed.hostId,
        dispatchedConnectionEpoch: sender.connectionEpoch,
        dispatchAttempt: 1,
      },
    });
    const before = await counters(seed.hostId);
    await census(sender, [{ sandboxId, state: "absent" }]);
    const row = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
    expect(row).toMatchObject({
      state: "OFFLOADED",
      sandboxHostId: null,
      diskOffloadId: offloadId,
      diskReservationHeld: false,
    });
    expect(
      (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: kill.id } })).state,
    ).toBe("SUCCEEDED");
    expect((await counters(seed.hostId)).rootCount).toBe(before.rootCount - 1);
  });
});
