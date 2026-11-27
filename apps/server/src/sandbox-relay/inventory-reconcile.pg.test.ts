import { seedStoredOffload } from "../../../../packages/api/src/sandbox/testing/offload-fixtures";
import {
  acknowledgeFixtureExecutionConfigs,
  seedLaunchHost,
  seedSandboxInstance,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";
import { capacityFixture, helloFixture } from "./capacity-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, describe, expect, it, vi } from "vitest";
import { seedTemplateRevision } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";
import {
  canonicalDigestHex,
  parseLoginDefinition,
} from "../../../../packages/login-definition/src/index";

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
const { reclaimExpiredSandboxLeases } = await import("@wssp/api/sandbox/lease");
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

const { InventoryCensus, convergeInventoryEntry, judgeExpiryStatus, recordHostHeartbeat } =
  await import("./inventory-reconcile.js");
const { ObservationFence } = await import("./observation-fence.js");
const { commitHostHello } = await import("./host-hello.js");

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

/** Root evidence for `sandboxId`'s retained root still present while its VM
 * is gone: an orphan root, stamped with the pool's current observation
 * sequence. These C37 cells use it as the minimal root evidence VM absence
 * now needs; it is not the normal completed
 * enforcement-loss cleanup, which reports an absent root with network proof
 * (covered by the cancel-wire C37/C38 cells). */
async function presentRootOf(sandboxId: string) {
  const row = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
  const pool = await db.inspect.sandboxHostStoragePool.findFirstOrThrow({
    where: { marker: row.storageMarker!, name: row.storagePoolName! },
  });
  return {
    storagePoolName: row.storagePoolName!,
    storageMarker: row.storageMarker!,
    diskGiB: row.diskGiB!,
    state: "present" as const,
    networkCleanupComplete: false,
    observationSequence: Number(pool.observationSequence),
  };
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
  const pass = new InventoryCensus(sender, clock, options);
  const accepted = await pass.acceptPage({
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
  return pass.pageResults;
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

const lifecycleOps = (sandboxId: string) =>
  db.inspect.sandboxOperation.findMany({
    where: { sandboxId, kind: { in: ["STOP_SANDBOX", "KILL_SANDBOX"] } },
    orderBy: { generation: "asc" },
    select: { kind: true, state: true, generation: true, dispatchAttempt: true },
  });

/** Real STOP/absent followed by the initial cleanup KILL and both retries. */
async function exhaustedNeverReadyCleanup() {
  const seed = await seedHost();
  const sandbox = await createSandbox(
    seed.owner,
    createSandboxInput.parse({
      template: "revision/" + seed.templateId,
      sandboxHostId: seed.hostId,
      idempotencyKey: `create-${randomUUID()}`,
    }),
  );
  await stopSandbox(seed.owner, { id: sandbox.id, idempotencyKey: `stop-${randomUUID()}` });
  const sender = await reconnectHost(seed);
  // Census settles STOP/absent and queues the initial cleanup KILL (retry 0).
  await census(sender, [{ sandboxId: sandbox.id, state: "absent" }]);
  const row = () => db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } });
  const host = () => db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: seed.hostId } });
  const poolId = (await row()).storagePoolId!;
  const pool = () => db.inspect.sandboxHostStoragePool.findUniqueOrThrow({ where: { id: poolId } });

  // Initial cleanup KILL and both system retries (TEARDOWN_RETRY_MAX = 2) fail.
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const kill = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: sandbox.id, kind: "KILL_SANDBOX", state: "QUEUED" },
    });
    await db.inspect.sandboxOperation.update({
      where: { id: kill.id },
      data: {
        state: "ACCEPTED",
        dispatchAttempt: 1,
        acceptedAttempt: 1,
        dispatchedHostId: seed.hostId,
        dispatchedConnectionEpoch: sender.connectionEpoch,
      },
    });
    expect(
      await applyOperationResult(
        {
          sender,
          operationId: kill.id,
          sandboxId: sandbox.id,
          generation: kill.generation,
          attempt: 1,
          state: "failed",
          error: { code: "internal", message: "cleanup kill failed" },
        },
        clock,
      ),
    ).toEqual({ written: true });
  }

  const stuck = await row();
  expect(stuck).toMatchObject({
    state: "ERROR",
    readyAt: null,
    liveResourcesHeld: false,
    diskReservationHeld: true,
    diskOffloadId: null,
    sandboxHostId: seed.hostId,
  });
  expect(await host()).toMatchObject({ liveCount: 0, rootCount: 1 });
  expect((await pool()).diskReservedGiB).toBeGreaterThan(0);

  const root = await presentRootOf(sandbox.id);
  const entry = {
    sandboxOwnerId: seed.owner.ownerId,
    sandboxId: sandbox.id,
    state: "absent" as const,
    root: { ...root, state: "absent" as const, networkCleanupComplete: true },
  };
  return { seed, sandbox, sender, row, host, pool, stuck, entry };
}

/** An unresolved login lease with real FK-bound recoverable guest residue. */
async function recoveryLeaseFor(f: Awaited<ReturnType<typeof exhaustedNeverReadyCleanup>>) {
  const userId = f.seed.owner.ownerId;
  const document = {
    schemaVersion: 1,
    id: "cleanup-tool",
    displayName: "Cleanup tool",
    login: { command: "tool login", method: "device-code" },
    credentials: {
      files: { required: [".config/tool"], optional: [], exclude: [] },
      sharing: "exclusive",
    },
  };
  const parsed = parseLoginDefinition(document);
  if (!parsed.success) throw new Error("invalid test login definition");
  const digest = await canonicalDigestHex(parsed.canonical);
  const definition = await db.inspect.credentialDefinition.create({
    data: {
      userId,
      slug: "cleanup-tool",
      version: 1,
      document,
      digest,
      displayName: "Cleanup tool",
    },
  });
  const credential = await db.inspect.credential.create({
    data: {
      userId,
      name: "cleanup-tool",
      definitionId: definition.id,
      definitionDigest: digest,
      mode: "EXCLUSIVE",
      delivery: "GUEST",
      copyBack: true,
    },
  });
  const account = await db.inspect.credentialAccount.create({
    data: { userId, credentialId: credential.id, ordinal: 1 },
  });
  const instance = await db.inspect.credentialInstance.create({
    data: {
      userId,
      credentialId: credential.id,
      accountId: account.id,
      accountOrdinal: 1,
      ordinal: 1,
      activeLeases: 1,
    },
  });
  const operation = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: f.sandbox.id, generation: f.stuck.generation, kind: "KILL_SANDBOX" },
  });
  const lease = await db.inspect.credentialLease.create({
    data: {
      userId,
      credentialId: credential.id,
      accountId: account.id,
      instanceId: instance.id,
      sandboxId: f.sandbox.id,
      operationId: operation.id,
      kind: "WORKLOAD",
      exclusive: true,
      state: "RECOVERY_REQUIRED",
      hostId: f.seed.hostId,
      baseSeq: 1,
    },
  });
  const binding = await db.inspect.credentialBinding.create({
    data: {
      leaseId: lease.id,
      instanceId: instance.id,
      sandboxId: f.sandbox.id,
      hostId: f.seed.hostId,
      grantGeneration: f.stuck.generation,
      operationId: operation.id,
      baseSeq: 1,
      purpose: "INSTALL",
    },
  });
  await db.inspect.credentialLease.update({
    where: { id: lease.id },
    data: { currentBindingId: binding.id },
  });
  const residue = await db.inspect.credentialResidue.create({
    data: {
      sandboxId: f.sandbox.id,
      userId,
      credentialId: credential.id,
      instanceId: instance.id,
      leaseId: lease.id,
      bindingId: binding.id,
      grantGeneration: f.stuck.generation,
      paths: [".config/tool"],
      recoverable: true,
    },
  });
  return { lease, residue, instance, binding };
}

describe("VM absence waits for root and network cleanup evidence", () => {
  it.each([
    { state: "READY", held: true },
    { state: "STOPPED", held: true },
    { state: "ERROR", held: true },
    { state: "ERROR", held: false },
  ] as const)(
    "$state (live resources held=$held) retries incomplete root absence",
    async ({ state, held }) => {
      for (const rootState of ["present", "absent-incomplete", "absent-complete"] as const) {
        const seed = await seedHost();
        const sandboxId = await readySandbox(seed, "destroy");
        // Exercise both the held-state and the non-held ERROR fallback.
        await db.inspect.sandbox.update({
          where: { id: sandboxId },
          data: { state, liveResourcesHeld: held },
        });
        if (!held)
          await db.inspect.sandboxHost.update({
            where: { id: seed.hostId },
            data: { liveCount: 0 },
          });
        const root = await presentRootOf(sandboxId);
        // Recover an earlier, shorten-only host deadline: lease adoption alone
        // must not acknowledge an absent root whose network cleanup is pending.
        const lease = await hostLeaseOf(sandboxId, true);
        lease.lease.deadlineUnixMs = Date.now() - 1_000;
        const result = await judgeExpiryStatus(
          { userId: seed.owner.ownerId, hostId: seed.hostId, connectionEpoch: 1 },
          [
            {
              sandboxOwnerId: seed.owner.ownerId,
              sandboxId,
              state: "absent",
              lease: { ...lease, lease: { ...lease.lease, shortenOnly: true } },
              root: {
                ...root,
                state: rootState === "present" ? "present" : "absent",
                networkCleanupComplete: rootState === "absent-complete",
              },
            },
          ],
          clock,
        );
        expect(result).toEqual({
          results: [
            {
              sandboxId,
              outcome: rootState === "absent-incomplete" ? "not_converged" : "converged",
            },
          ],
        });
        const row = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
        expect(row.liveResourcesHeld).toBe(false);
        expect(row.diskReservationHeld).toBe(rootState !== "absent-complete");
      }
    },
  );
});

describe("C33 (real PostgreSQL): offline lifecycle convergence", () => {
  it("C37 connected enforcement-loss completion releases exactly the current arm, without timer expiry", async () => {
    const seed = await seedHost();
    const sandboxId = await readySandbox(seed);
    const sender = { userId: seed.owner.ownerId, hostId: seed.hostId, connectionEpoch: 1 };
    const lease = { ...(await hostLeaseOf(sandboxId, true)), timerExpired: false };
    const row = () => db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
    const host = () => db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: seed.hostId } });
    expect((await host()).liveCount).toBe(1);
    expect(lease.lease.deadlineUnixMs).toBeGreaterThan(clock().getTime());
    // Incomplete deletion is not absence proof and releases nothing.
    expect(
      await judgeExpiryStatus(
        sender,
        [
          {
            root: null,
            sandboxOwnerId: sender.userId,
            sandboxId,
            state: "unreachable",
            lease: { ...lease, expiryComplete: false },
          },
        ],
        clock,
      ),
    ).toHaveProperty("results");
    expect(await row()).toMatchObject({ state: "READY", liveResourcesHeld: true });
    expect((await host()).liveCount).toBe(1);
    expect(
      await judgeExpiryStatus(
        sender,
        [
          {
            root: await presentRootOf(sandboxId),
            sandboxOwnerId: sender.userId,
            sandboxId,
            state: "absent",
            lease,
          },
        ],
        clock,
      ),
    ).toHaveProperty("results");
    expect(await row()).toMatchObject({
      state: "ERROR",
      liveResourcesHeld: false,
      generation: lease.generation + 1,
      lastErrorCode: "instance_missing",
      hostExpiryAction: null,
    });
    expect((await host()).liveCount).toBe(0);
    // Replay is idempotent; it cannot debit capacity twice.
    expect(
      await judgeExpiryStatus(
        sender,
        [
          {
            root: await presentRootOf(sandboxId),
            sandboxOwnerId: sender.userId,
            sandboxId,
            state: "absent",
            lease,
          },
        ],
        clock,
      ),
    ).toHaveProperty("results");
    expect((await host()).liveCount).toBe(0);
    expect((await host()).connectionEpoch).toBe(1);
  });

  it("a rootless absence claiming expiry of a lease not yet due releases nothing", async () => {
    const seed = await seedHost();
    const sandboxId = await readySandbox(seed);
    const sender = { userId: seed.owner.ownerId, hostId: seed.hostId, connectionEpoch: 1 };
    const row = () => db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
    const host = () => db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: seed.hostId } });
    const before = await row();
    expect(before.diskReservationHeld).toBe(true);
    const lease = await hostLeaseOf(sandboxId, true);
    expect(lease.lease.deadlineUnixMs).toBeGreaterThan(clock().getTime());
    for (const attack of [
      { ...lease, timerExpired: false },
      { ...lease, expiryComplete: false, timerExpired: false },
    ]) {
      const entry = {
        root: null,
        sandboxOwnerId: sender.userId,
        sandboxId,
        state: "absent" as const,
        lease: attack,
      };
      expect(await judgeExpiryStatus(sender, [entry], clock)).toHaveProperty("results");
      expect(await judgeExpiryStatus(sender, [entry], clock)).toEqual({
        results: [{ sandboxId, outcome: "not_converged" }],
      });
    }
    expect(await row()).toMatchObject({
      state: "READY",
      generation: before.generation,
      liveResourcesHeld: true,
    });
    expect((await host()).liveCount).toBe(1);
  });

  it("C37 a stale enforcement-loss completion cannot settle a newer successful allocation", async () => {
    const seed = await seedHost();
    const sandboxId = await readySandbox(seed);
    const stale = { ...(await hostLeaseOf(sandboxId, true)), timerExpired: false };
    await stopSandbox(seed.owner, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
    await processSandboxOutboxBatch(clock);
    const stop = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId, kind: "STOP_SANDBOX" },
    });
    expect(await reportSucceeded(stop.id, "stopped", 1)).toEqual({ written: true });
    await reconnectSandbox(seed.owner, { id: sandboxId, idempotencyKey: `re-${randomUUID()}` });
    await processSandboxOutboxBatch(clock);
    const reconnect = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId, kind: "RECONNECT_SANDBOX", state: "DISPATCHED" },
    });
    expect(await reportSucceeded(reconnect.id, "ready", 1)).toEqual({ written: true });
    const sender = { userId: seed.owner.ownerId, hostId: seed.hostId, connectionEpoch: 1 };
    const before = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
    expect(before).toMatchObject({ state: "READY", liveResourcesHeld: true });
    expect(
      await judgeExpiryStatus(
        sender,
        [
          {
            root: await presentRootOf(sandboxId),
            sandboxOwnerId: sender.userId,
            sandboxId,
            state: "absent",
            lease: stale,
          },
        ],
        clock,
      ),
    ).toHaveProperty("results");
    expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } })).toEqual({
      ...before,
      updatedAt: expect.any(Date),
    });
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: seed.hostId } })).liveCount,
    ).toBe(1);
    // The current arm remains actionable (inverse against unconditional veto).
    const current = { ...(await hostLeaseOf(sandboxId, true)), timerExpired: false };
    expect(
      await judgeExpiryStatus(
        sender,
        [
          {
            root: await presentRootOf(sandboxId),
            sandboxOwnerId: sender.userId,
            sandboxId,
            state: "absent",
            lease: current,
          },
        ],
        clock,
      ),
    ).toHaveProperty("results");
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: seed.hostId } })).liveCount,
    ).toBe(0);
  });

  // A deferred stopped-root proof of the first arm, then a
  // reconnect that booted the VM but failed startup (FAILED, cleanup stop
  // queued). The old arm's proof says nothing about the instance the failed
  // reconnect booted, so it must not settle that cleanup or release its hold.
  it("an older arm's stopped-root proof cannot settle cleanup of a later reconnect that failed after booting", async () => {
    const seed = await seedHost();
    const sandboxId = await readySandbox(seed);
    const stale = await hostLeaseOf(sandboxId, false);
    await stopSandbox(seed.owner, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
    await processSandboxOutboxBatch(clock);
    const stop = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId, kind: "STOP_SANDBOX" },
    });
    expect(await reportSucceeded(stop.id, "stopped", 1)).toEqual({ written: true });
    await reconnectSandbox(seed.owner, { id: sandboxId, idempotencyKey: `re-${randomUUID()}` });
    await processSandboxOutboxBatch(clock);
    const reconnect = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId, kind: "RECONNECT_SANDBOX", state: "DISPATCHED" },
    });
    const sender = { userId: seed.owner.ownerId, hostId: seed.hostId, connectionEpoch: 1 };
    expect(
      await applyOperationResult(
        {
          sender,
          operationId: reconnect.id,
          sandboxId,
          generation: reconnect.generation,
          attempt: reconnect.dispatchAttempt,
          state: "failed",
          error: { code: "startup_failed", message: "start command failed" },
        },
        clock,
      ),
    ).toMatchObject({ written: true });
    const cleanup = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId, kind: "STOP_SANDBOX", generation: { gt: reconnect.generation } },
    });
    const before = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
    expect(before).toMatchObject({ liveResourcesHeld: true, diskReservationHeld: true });
    expect(stale.generation).toBeLessThan(reconnect.generation);
    // Root evidence current for the pool (the sequence rule does not apply):
    // only the later-allocation fence stands between it and the cleanup.
    const pool = await db.inspect.sandboxHostStoragePool.update({
      where: { id: before.storagePoolId! },
      data: { reportedAt: new Date() },
    });
    const outcome = await convergeInventoryEntry(sender, {
      sandboxOwnerId: sender.userId,
      sandboxId,
      state: "stopped",
      lease: stale,
      root: {
        storagePoolName: before.storagePoolName!,
        storageMarker: before.storageMarker!,
        diskGiB: before.diskGiB,
        state: "present",
        networkCleanupComplete: false,
        observationSequence: Number(pool.observationSequence),
      },
    });
    expect(outcome).not.toHaveProperty("conflict");
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: cleanup.id } }),
    ).toMatchObject({ state: cleanup.state, dispatchAttempt: cleanup.dispatchAttempt });
    expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } })).toMatchObject({
      state: before.state,
      liveResourcesHeld: true,
    });
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: seed.hostId } })).liveCount,
    ).toBe(1);
  });

  it("a census page judges each entry: converged, refused for stale storage, or unchanged", async () => {
    const seed = await seedHost();
    const ids = [
      await readySandbox(seed),
      await readySandbox(seed),
      await readySandbox(seed),
    ].sort();
    const sender = await reconnectHost(seed);
    await db.inspect.sandboxHostStoragePool.updateMany({
      where: { sandboxHostId: seed.hostId },
      data: { observationSequence: 5n },
    });
    const plan: Record<string, { state: "stopped" | "ready"; sequence: number }> = {
      [ids[0]!]: { state: "stopped", sequence: 5 },
      [ids[1]!]: { state: "stopped", sequence: 4 },
      [ids[2]!]: { state: "ready", sequence: 5 },
    };
    const entries = await Promise.all(
      ids.map(async (sandboxId) => {
        const s = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
        return {
          sandboxOwnerId: s.userId,
          sandboxId,
          state: plan[sandboxId]!.state,
          root: {
            storagePoolName: s.storagePoolName!,
            storageMarker: s.storageMarker!,
            diskGiB: s.diskGiB,
            state: "present" as const,
            networkCleanupComplete: false,
            observationSequence: plan[sandboxId]!.sequence,
          },
        };
      }),
    );
    const census = new InventoryCensus(sender, clock);
    expect(
      await census.acceptPage({ type: "sandbox.inventory", page: 0, complete: false, entries }),
    ).toEqual({ ok: true });
    expect(census.pageResults).toEqual([
      { sandboxId: ids[0], outcome: "converged" },
      { sandboxId: ids[1], outcome: "stale_storage" },
      { sandboxId: ids[2], outcome: "not_converged" },
    ]);
    const state = async (id: string) =>
      (await db.inspect.sandbox.findUniqueOrThrow({ where: { id } })).state;
    expect([await state(ids[0]!), await state(ids[1]!), await state(ids[2]!)]).toEqual([
      "STOPPED",
      "READY",
      "READY",
    ]);
  });

  it("two full stop/reconnect cycles converge across outages without a repeated destructive effect", async () => {
    const seed = await seedHost();
    const sandboxId = await readySandbox(seed);
    const row = () => db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
    const hostRow = () => db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: seed.hostId } });
    let epoch = 1;

    for (const cycle of [1, 2]) {
      // Outage: cycle 1 queues a user stop the host never receives; in cycle 2
      // nothing is requested. Either way the host stops the VM on its own.
      if (cycle === 1)
        await stopSandbox(seed.owner, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
      const outage = await reconnectHost(seed);
      epoch = outage.connectionEpoch;
      await census(outage, [
        { sandboxId, state: "stopped", lease: await hostLeaseOf(sandboxId, false) },
      ]);
      expect(await row()).toMatchObject({
        state: "STOPPED",
        sandboxHostId: seed.hostId,
        liveResourcesHeld: false,
      });
      expect((await hostRow()).liveCount).toBe(0);
      // The retained stopped disk is still listed for its owner.
      expect(
        await db.inspect.sandbox.count({
          where: { userId: seed.owner.ownerId, id: sandboxId, state: "STOPPED" },
        }),
      ).toBe(1);
      // The converged stop is never dispatched afterwards.
      expect(await processSandboxOutboxBatch(clock)).toBe(0);

      // Reconnect runs it again on the same host.
      await reconnectSandbox(seed.owner, {
        id: sandboxId,
        idempotencyKey: `re-${cycle}-${randomUUID()}`,
      });
      await processSandboxOutboxBatch(clock);
      const reconnect = await db.inspect.sandboxOperation.findFirstOrThrow({
        where: { sandboxId, kind: "RECONNECT_SANDBOX", state: "DISPATCHED" },
      });
      expect(await reportSucceeded(reconnect.id, "ready", epoch)).toEqual({ written: true });
      expect(await row()).toMatchObject({ state: "READY", liveResourcesHeld: true });
      expect((await hostRow()).liveCount).toBe(1);
    }

    // A restart replays a census of the running VM: nothing changes.
    const ready = await row();
    await census(await reconnectHost(seed), [
      { sandboxId, state: "ready", lease: await hostLeaseOf(sandboxId, false) },
    ]);
    expect(await row()).toMatchObject({ state: "READY", generation: ready.generation });
    expect(
      (await lifecycleOps(sandboxId)).map((op) => [op.kind, op.state, op.dispatchAttempt]),
    ).toEqual([
      ["STOP_SANDBOX", "SUCCEEDED", 0],
      ["STOP_SANDBOX", "SUCCEEDED", 0],
    ]);
    expect(await hostRow()).toMatchObject({
      liveCount: 1,
      inventorySeq: 3,
      quarantinedAt: null,
    });
  });

  it("an explicit stop keeps the destroy timer: its offline expiry converges DELETED", async () => {
    const seed = await seedHost();
    const sandboxId = await readySandbox(seed, "destroy");
    await stopSandbox(seed.owner, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
    await processSandboxOutboxBatch(clock);
    const stop = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId, kind: "STOP_SANDBOX" },
    });
    expect(await reportSucceeded(stop.id, "stopped", 1)).toEqual({ written: true });
    const stopped = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
    expect(stopped).toMatchObject({ state: "STOPPED", generation: 2, liveResourcesHeld: false });
    // Time passes offline: the gen-1 destroy deadline elapses and the host deletes the disk.
    const past = new Date(Date.now() - 120_000);
    await db.inspect.sandbox.update({
      where: { id: sandboxId },
      data: { leaseExpiresAt: past, leaseExpiresAtEffective: past },
    });
    await census(await reconnectHost(seed), [
      { sandboxId, state: "absent", lease: await hostLeaseOf(sandboxId, true, 1) },
    ]);
    expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } })).toMatchObject({
      state: "DELETED",
      sandboxHostId: null,
      hostExpiryAction: "DESTROY",
      hostExpiryRevision: stopped.leaseRevisionEffective,
    });
    expect(await processSandboxOutboxBatch(clock)).toBe(0);
    expect((await lifecycleOps(sandboxId)).map((op) => [op.kind, op.state])).toEqual([
      ["STOP_SANDBOX", "SUCCEEDED"],
      ["KILL_SANDBOX", "SUCCEEDED"],
    ]);
  });

  it("a destroy expiry the host executed offline converges DELETED once; the server scanner adds nothing", async () => {
    const seed = await seedHost();
    const sandboxId = await readySandbox(seed);
    const past = new Date(Date.now() - 120_000);
    // The host holds an acknowledged destroy lease whose deadline passed offline.
    await db.inspect.sandbox.update({
      where: { id: sandboxId },
      data: {
        leaseExpiresAt: past,
        leaseExpireAction: "DESTROY",
        leaseExpiresAtEffective: past,
        leaseExpireActionEffective: "DESTROY",
      },
    });
    const sender = await reconnectHost(seed);
    await census(sender, [
      { sandboxId, state: "absent", lease: await hostLeaseOf(sandboxId, true) },
    ]);
    const row = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
    expect(row).toMatchObject({
      state: "DELETED",
      sandboxHostId: null,
      liveResourcesHeld: false,
      hostExpiryRevision: row.leaseRevisionEffective,
      hostExpiryAction: "DESTROY",
    });
    expect(row.hostExpiryConfirmedAt).toBeInstanceOf(Date);

    expect(await reclaimExpiredSandboxLeases(clock)).toBe(0);
    expect(await processSandboxOutboxBatch(clock)).toBe(0);
    expect(await lifecycleOps(sandboxId)).toEqual([
      expect.objectContaining({ kind: "KILL_SANDBOX", state: "SUCCEEDED", dispatchAttempt: 0 }),
    ]);
    expect(await db.inspect.sandboxHost.findUnique({ where: { id: seed.hostId } })).toMatchObject({
      liveCount: 0,
    });
  });

  it("interior silence never proves retained root absence, including bounded replay", async () => {
    const seed = await seedHost();
    const ids: string[] = [];
    for (let i = 0; i < 4; i += 1) ids.push(await readySandbox(seed));
    ids.sort();
    const [first, second, third, last] = ids as [string, string, string, string];
    const states = async () =>
      (
        await db.inspect.sandbox.findMany({
          where: { id: { in: [second, third] } },
          orderBy: { id: "asc" },
          select: { state: true, liveResourcesHeld: true },
        })
      ).map((row) => `${row.state}:${row.liveResourcesHeld}`);
    const replay = async () =>
      census(
        await reconnectHost(seed),
        [
          { sandboxId: first, state: "ready" },
          { sandboxId: last, state: "ready" },
        ],
        { pendingAbsentMax: 1 },
      );
    await replay();
    expect(await states()).toEqual(["READY:true", "READY:true"]);
    await replay();
    expect(await states()).toEqual(["READY:true", "READY:true"]);
    // The present rows' compare-and-set touches updatedAt; nothing else moves.
    const rows = async () =>
      (
        await db.inspect.sandbox.findMany({ where: { id: { in: ids } }, orderBy: { id: "asc" } })
      ).map(({ updatedAt: _updatedAt, ...row }) => row);
    const settled = await rows();
    await replay();
    expect(await rows()).toEqual(settled);
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: seed.hostId } })).liveCount,
    ).toBe(4);
  });

  it("a failing host expiry is shown with its reason and holds the slot until the host stops it", async () => {
    const seed = await seedHost();
    const sandboxId = await readySandbox(seed);
    const past = new Date(Date.now() - 120_000);
    await db.inspect.sandbox.update({
      where: { id: sandboxId },
      data: { leaseExpiresAt: past, leaseExpiresAtEffective: past },
    });
    const lease = await hostLeaseOf(sandboxId, true);
    await census(await reconnectHost(seed), [
      {
        sandboxId,
        state: "ready",
        lease: {
          ...lease,
          expiryComplete: false,
          expiryFailure: {
            reason: "synthetic-env-expiry-3a c3ludGhldGljLWVudi1leHBpcnktM2E=",
            attempts: 3,
            sinceUnixMs: past.getTime(),
          },
        },
      },
    ]);
    expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } })).toMatchObject({
      state: "ERROR",
      liveResourcesHeld: true,
      lastErrorCode: "expiry_failed",
      lastErrorDetail: "Host could not enforce sandbox expiry.",
    });
    const { getSandboxView } = await import(
      "../../../../packages/api/src/sandbox/services/sandbox-views"
    );
    const visible = await getSandboxView(seed.owner, { id: sandboxId });
    expect(visible.expiryFailureReason).toBe("Host could not enforce sandbox expiry.");
    expect(JSON.stringify(visible)).not.toContain("synthetic-env-expiry-3a");
    expect(JSON.stringify(visible)).not.toContain("c3ludGhldGljLWVudi1leHBpcnktM2E=");
    await census(await reconnectHost(seed), [{ sandboxId, state: "stopped", lease }]);
    expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } })).toMatchObject({
      state: "STOPPED",
      liveResourcesHeld: false,
      lastErrorCode: null,
      hostExpiryAction: "STOP",
    });
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: seed.hostId } })).liveCount,
    ).toBe(0);
  });

  it("a failing expiry the server queued offline shows ERROR, then recovery settles that stop once", async () => {
    const seed = await seedHost();
    const sandboxId = await readySandbox(seed);
    const row = () => db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
    const reserved = async () =>
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: seed.hostId } })).liveCount;
    const past = new Date(Date.now() - 120_000);
    await db.inspect.sandbox.update({
      where: { id: sandboxId },
      data: { leaseExpiresAt: past, leaseExpiresAtEffective: past },
    });
    // The host is offline when the server's scanner queues the expiry stop.
    expect(await reclaimExpiredSandboxLeases(clock)).toBe(1);
    const queued = await row();
    expect(queued.state).toBe("STOPPING");
    const lease = await hostLeaseOf(sandboxId, true, 1);
    await census(await reconnectHost(seed), [
      {
        sandboxId,
        state: "ready",
        lease: {
          ...lease,
          expiryComplete: false,
          expiryFailure: { reason: "forced stop failed", attempts: 2, sinceUnixMs: past.getTime() },
        },
      },
    ]);
    expect(await row()).toMatchObject({
      state: "ERROR",
      generation: queued.generation,
      liveResourcesHeld: true,
      lastErrorCode: "expiry_failed",
      lastErrorDetail: "Host could not enforce sandbox expiry.",
    });
    expect(await reserved()).toBe(1);
    // The pending stop is never sent to a host that is still failing the expiry.
    await processSandboxOutboxBatch(clock);
    expect(await lifecycleOps(sandboxId)).toEqual([
      expect.objectContaining({ kind: "STOP_SANDBOX", dispatchAttempt: 0 }),
    ]);

    await census(await reconnectHost(seed), [{ sandboxId, state: "stopped", lease }]);
    expect(await row()).toMatchObject({
      state: "STOPPED",
      generation: queued.generation,
      liveResourcesHeld: false,
      lastErrorCode: null,
      lastErrorDetail: null,
      hostExpiryAction: "STOP",
    });
    expect(await reserved()).toBe(0);
    expect(await processSandboxOutboxBatch(clock)).toBe(0);
    expect(await lifecycleOps(sandboxId)).toEqual([
      expect.objectContaining({ kind: "STOP_SANDBOX", state: "SUCCEEDED", dispatchAttempt: 0 }),
    ]);
  });

  it("census settles a never-ready STOP/absent and queues one root cleanup KILL", async () => {
    const seed = await seedHost();
    const sandbox = await createSandbox(
      seed.owner,
      createSandboxInput.parse({
        template: "revision/" + seed.templateId,
        sandboxHostId: seed.hostId,
        idempotencyKey: `create-${randomUUID()}`,
      }),
    );
    // Stop before the queued create ever runs: no uncertain allocation can
    // block the census, but the reserved root still needs a KILL proof.
    await stopSandbox(seed.owner, { id: sandbox.id, idempotencyKey: `stop-${randomUUID()}` });
    const stop = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: sandbox.id, kind: "STOP_SANDBOX" },
    });
    const row = () => db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } });
    expect(await row()).toMatchObject({
      state: "STOPPING",
      readyAt: null,
      diskReservationHeld: true,
      diskOffloadId: null,
    });
    const sender = await reconnectHost(seed);
    await census(sender, [{ sandboxId: sandbox.id, state: "absent" }]);
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: stop.id } }),
    ).toMatchObject({ state: "SUCCEEDED", result: { state: "absent" } });
    expect(await row()).toMatchObject({
      state: "STOPPING",
      generation: stop.generation + 1,
      liveResourcesHeld: false,
      diskReservationHeld: true,
      sandboxHostId: seed.hostId,
    });
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: seed.hostId } }),
    ).toMatchObject({ liveCount: 0, rootCount: 1 });
    const kills = await db.inspect.sandboxOperation.findMany({
      where: { sandboxId: sandbox.id, kind: "KILL_SANDBOX" },
      take: 2,
    });
    expect(kills).toHaveLength(1);
    expect(kills[0]).toMatchObject({ state: "QUEUED", generation: stop.generation + 1 });
    expect(
      await db.inspect.outboxEvent.findFirstOrThrow({ where: { operationId: kills[0]!.id } }),
    ).toMatchObject({
      processedAt: null,
      payload: { kind: "sandbox.kill", credentialTeardown: "system" },
    });
    // Root proof in the next census settles that KILL; it never creates a
    // second cleanup or leaves a restartable STOPPED row.
    await census(sender, [{ sandboxId: sandbox.id, state: "absent" }]);
    expect(await row()).toMatchObject({
      state: "DELETED",
      diskReservationHeld: false,
      sandboxHostId: null,
    });
    expect(
      await db.inspect.sandboxOperation.count({
        where: { sandboxId: sandbox.id, kind: "KILL_SANDBOX" },
      }),
    ).toBe(1);
  });

  it("census settles an exhausted never-ready cleanup KILL on exact root absence", async () => {
    const { seed, sandbox, sender, row, host, pool, stuck } = await exhaustedNeverReadyCleanup();

    // Incomplete root absence (root present, network cleanup incomplete, or
    // rootless) never releases the reservation.
    const root = await presentRootOf(sandbox.id);
    for (const partialRoot of [
      null,
      root,
      { ...root, state: "absent" as const, networkCleanupComplete: false },
    ]) {
      expect(
        await new InventoryCensus(sender, clock).acceptPage({
          type: "sandbox.inventory",
          page: 0,
          complete: true,
          entries: [
            {
              sandboxOwnerId: seed.owner.ownerId,
              sandboxId: sandbox.id,
              state: "absent",
              root: partialRoot,
            },
          ],
        }),
      ).toEqual({ ok: true });
      expect(await row()).toMatchObject({
        state: "ERROR",
        generation: stuck.generation,
        diskReservationHeld: true,
        sandboxHostId: seed.hostId,
      });
    }

    // Complete root + network absence settles the exhausted cleanup to DELETED
    // and releases the disk reservation.
    const nextSender = await reconnectHost(seed);
    expect(await census(nextSender, [{ sandboxId: sandbox.id, state: "absent" }])).toEqual([
      { sandboxId: sandbox.id, outcome: "converged", rootRetired: true },
    ]);
    expect(await row()).toMatchObject({
      state: "DELETED",
      generation: stuck.generation + 1,
      liveResourcesHeld: false,
      diskReservationHeld: false,
      sandboxHostId: null,
      storagePoolId: null,
      lastErrorCode: null,
      lastErrorDetail: null,
    });
    expect(await host()).toMatchObject({ liveCount: 0, rootCount: 0 });
    expect(await pool()).toMatchObject({ diskReservedGiB: 0 });

    // Replaying the same absence is idempotent and never releases twice.
    expect(await census(nextSender, [{ sandboxId: sandbox.id, state: "absent" }])).toEqual([
      { sandboxId: sandbox.id, outcome: "converged", rootRetired: true },
    ]);
    expect(await host()).toMatchObject({ liveCount: 0, rootCount: 0 });
    expect(await pool()).toMatchObject({ diskReservedGiB: 0 });
  });

  it("retirement ACK replay preserves host, owner, root and fresh-pool authority", async () => {
    const f = await exhaustedNeverReadyCleanup();
    expect(await convergeInventoryEntry(f.sender, f.entry, clock)).toEqual({
      converged: true,
      rootRetired: true,
    });
    for (const root of [
      null,
      { ...f.entry.root, state: "present" as const },
      { ...f.entry.root, networkCleanupComplete: false },
      { ...f.entry.root, diskGiB: f.entry.root.diskGiB + 1 },
      { ...f.entry.root, storageMarker: "b".repeat(32) },
      { ...f.entry.root, storagePoolName: "other" },
    ]) {
      expect(await convergeInventoryEntry(f.sender, { ...f.entry, root }, clock)).toEqual({
        converged: false,
      });
    }
    const foreign = await seedHost();
    const foreignSender = await reconnectHost(foreign);
    expect(await convergeInventoryEntry(foreignSender, f.entry, clock)).toEqual({
      conflict: "foreign_sandbox",
    });
    expect(
      await convergeInventoryEntry(
        f.sender,
        { ...f.entry, sandboxOwnerId: foreign.owner.ownerId },
        clock,
      ),
    ).toEqual({ stale: true });
    expect(
      await convergeInventoryEntry({ ...f.sender, userId: foreign.owner.ownerId }, f.entry, clock),
    ).toEqual({ stale: true });
    const pool = await f.pool();
    await db.inspect.sandboxHostStoragePool.update({
      where: { id: pool.id },
      data: { observationSequence: 101n },
    });
    expect(await convergeInventoryEntry(f.sender, f.entry, clock)).toEqual({
      converged: false,
      staleStorage: true,
    });
    const fresh = { ...f.entry, root: { ...f.entry.root, observationSequence: 101 } };
    expect(await convergeInventoryEntry(f.sender, fresh, clock)).toEqual({
      converged: true,
      rootRetired: true,
    });
    const nextSender = await reconnectHost(f.seed);
    const replay = new InventoryCensus(nextSender, clock);
    expect(
      await replay.acceptPage({
        type: "sandbox.inventory",
        page: 0,
        complete: true,
        entries: [fresh],
      }),
    ).toEqual({ ok: true });
    expect(replay.pageResults).toEqual([
      { sandboxId: f.sandbox.id, outcome: "converged", rootRetired: true },
    ]);
    expect(await f.host()).toMatchObject({ rootCount: 0, liveCount: 0 });
    expect(await f.pool()).toMatchObject({ diskReservedGiB: 0 });
  });

  it("replays a lost retirement ACK after real hello omits the retained pool without changing frozen metadata", async () => {
    const f = await exhaustedNeverReadyCleanup();
    // The server commits deletion, but the daemon loses this retirement ACK.
    expect(await convergeInventoryEntry(f.sender, f.entry, clock)).toEqual({
      converged: true,
      rootRetired: true,
    });
    const retired = await f.row();
    const pool = await f.pool();
    await db.inspect.sandboxHostStoragePool.update({
      where: { id: pool.id },
      data: {
        capacitySource: "implicit",
        capacityGiB: 64,
        totalBasedCapacityGiB: 128,
        implicitCeilingGiB: 64,
        derivationTotalBytes: 128n * 1024n ** 3n,
        derivationFreeBytes: 96n * 1024n ** 3n,
        derivationCommittedBytes: 33n * 1024n ** 3n,
        derivationActualBytes: 1024n ** 3n,
        derivationHeadroomBytes: 1024n ** 3n,
        draining: true,
        health: "unavailable",
        healthReason: "io",
        reportedAt: new Date(0),
      },
    });
    const unrelated = await db.inspect.sandboxHostStoragePool.create({
      data: {
        ...pool,
        id: randomUUID(),
        name: "unrelated",
        marker: randomUUID(),
        health: "unavailable",
        healthReason: "io",
      },
    });
    const message = { ...helloFixture(f.seed.hostId), storagePools: [] };
    const sender = {
      userId: f.seed.owner.ownerId,
      hostId: f.seed.hostId,
      connectionEpoch: await commitHostHello({ identity: f.sender, message, now: clock() }),
    };
    const omitted = await f.pool();
    expect(omitted).toMatchObject({
      connectionEpoch: f.sender.connectionEpoch,
      configured: false,
      newRootsAllowed: false,
      health: "unavailable",
      reportedAt: new Date(0),
    });
    expect(sender.connectionEpoch).toBe(f.sender.connectionEpoch + 1);
    const unrelatedOmitted = await db.inspect.sandboxHostStoragePool.findUniqueOrThrow({
      where: { id: unrelated.id },
    });
    const frozenCapacity = (await f.host()).capacityReport;
    const foreign = await seedHost();
    for (const root of [
      null,
      { ...f.entry.root, state: "present" as const },
      { ...f.entry.root, networkCleanupComplete: false },
      { ...f.entry.root, diskGiB: f.entry.root.diskGiB + 1 },
      { ...f.entry.root, storageMarker: unrelated.marker },
      { ...f.entry.root, storagePoolName: unrelated.name },
    ]) {
      expect(await convergeInventoryEntry(sender, { ...f.entry, root }, clock)).toEqual({
        converged: false,
      });
    }
    expect(await convergeInventoryEntry(await reconnectHost(foreign), f.entry, clock)).toEqual({
      conflict: "foreign_sandbox",
    });
    for (const [transport, entry] of [
      [{ ...sender, userId: foreign.owner.ownerId }, f.entry],
      [sender, { ...f.entry, sandboxOwnerId: foreign.owner.ownerId }],
    ] as const) {
      expect(await convergeInventoryEntry(transport, entry, clock)).toEqual({ stale: true });
    }
    // Even an authorized refresh must roll back if its sender loses the socket.
    expect(
      await convergeInventoryEntry({ ...sender, isCurrent: () => false }, f.entry, clock),
    ).toEqual({ stale: true });
    expect(await f.pool()).toEqual(omitted);

    // Sequence numbers are epoch-local; a fresh exact proof may reset them.
    const fresh = { ...f.entry, root: { ...f.entry.root, observationSequence: 1 } };
    const replay = new InventoryCensus(sender, clock);
    expect(
      await replay.acceptPage({
        type: "sandbox.inventory",
        page: 0,
        complete: true,
        entries: [fresh],
      }),
    ).toEqual({ ok: true });
    expect(replay.pageResults).toEqual([
      { sandboxId: f.sandbox.id, outcome: "converged", rootRetired: true },
    ]);
    const repaired = await f.pool();
    expect(repaired).toEqual({
      ...omitted,
      health: "healthy",
      healthReason: null,
      connectionEpoch: sender.connectionEpoch,
      observationSequence: 1n,
      reportedAt: expect.any(Date),
      updatedAt: expect.any(Date),
    });
    expect(repaired.reportedAt.getTime()).toBeGreaterThan(omitted.reportedAt.getTime());
    expect(await judgeExpiryStatus(sender, [fresh], clock, () => false)).toEqual({
      results: [{ sandboxId: f.sandbox.id, outcome: "converged", rootRetired: true }],
    });
    expect(await f.pool()).toEqual(repaired);
    expect(await f.row()).toEqual(retired);
    expect(await f.host()).toMatchObject({
      rootCount: 0,
      liveCount: 0,
      capacityReport: frozenCapacity,
    });
    expect(
      await db.inspect.sandboxHostStoragePool.findUniqueOrThrow({ where: { id: unrelated.id } }),
    ).toEqual(unrelatedOmitted);
  });

  it("omitted-pool retirement replay requires a newer proof to repair negative or aged health", async () => {
    const f = await exhaustedNeverReadyCleanup();
    expect(await convergeInventoryEntry(f.sender, f.entry, clock)).toEqual({
      converged: true,
      rootRetired: true,
    });
    const sender = {
      ...f.sender,
      connectionEpoch: await commitHostHello({
        identity: f.sender,
        message: { ...helloFixture(f.seed.hostId), storagePools: [] },
        now: clock(),
      }),
    };
    expect((await f.pool()).connectionEpoch).toBe(f.sender.connectionEpoch);
    expect(await convergeInventoryEntry(sender, f.entry, clock)).toEqual({
      converged: true,
      rootRetired: true,
    });
    const pool = await f.pool();
    const negative = await db.inspect.sandboxHostStoragePool.update({
      where: { id: pool.id },
      data: {
        health: "unavailable",
        healthReason: "io",
        observationSequence: pool.observationSequence + 1n,
      },
    });
    expect(await convergeInventoryEntry(sender, f.entry, clock)).toEqual({
      converged: false,
      staleStorage: true,
    });
    const current = {
      ...f.entry,
      root: { ...f.entry.root, observationSequence: Number(negative.observationSequence) },
    };
    expect(await convergeInventoryEntry(sender, current, clock)).toEqual({ converged: false });
    expect(await f.pool()).toEqual(negative);
    // Explicit proof newer than the negative observation repairs only this pool.
    const fresh = {
      ...f.entry,
      root: { ...f.entry.root, observationSequence: current.root.observationSequence + 1 },
    };
    expect(await convergeInventoryEntry(sender, fresh, clock)).toEqual({
      converged: true,
      rootRetired: true,
    });
    const healthy = await f.pool();
    expect(healthy).toEqual({
      ...negative,
      health: "healthy",
      healthReason: null,
      observationSequence: BigInt(fresh.root.observationSequence),
      reportedAt: expect.any(Date),
      updatedAt: expect.any(Date),
    });
    for (const reportedAt of [new Date(0), new Date(Date.now() + 60_000)]) {
      const stale = await db.inspect.sandboxHostStoragePool.update({
        where: { id: pool.id },
        data: { reportedAt },
      });
      expect(await convergeInventoryEntry(sender, fresh, clock)).toEqual({
        converged: false,
        staleStorage: true,
      });
      expect(await f.pool()).toEqual(stale);
    }
    const newer = {
      ...fresh,
      root: { ...fresh.root, observationSequence: fresh.root.observationSequence + 1 },
    };
    expect(await convergeInventoryEntry(sender, newer, clock)).toEqual({
      converged: true,
      rootRetired: true,
    });
    expect(await f.pool()).toMatchObject({
      configured: false,
      newRootsAllowed: false,
      observationSequence: BigInt(newer.root.observationSequence),
    });
  });

  it.each([
    "credential_capture_failed",
    "older-generation",
    "offloaded",
    "open-lease",
    "teardown-intent",
  ] as const)(
    "failed cleanup census excludes %s even with complete host proof",
    async (excluded) => {
      const f = await exhaustedNeverReadyCleanup();
      const recovery = excluded === "open-lease" ? await recoveryLeaseFor(f) : null;
      if (excluded === "credential_capture_failed" || excluded === "teardown-intent") {
        await db.inspect.sandboxOperation.updateMany({
          where: { sandboxId: f.sandbox.id, generation: f.stuck.generation, kind: "KILL_SANDBOX" },
          data:
            excluded === "credential_capture_failed"
              ? { errorCode: "credential_capture_failed" }
              : { teardownIntent: "OWNER_DESTROY" },
        });
      }
      if (excluded === "older-generation") {
        await db.inspect.sandbox.update({
          where: { id: f.sandbox.id },
          data: { generation: { increment: 1 } },
        });
      }
      let offloadId: string | null = null;
      if (excluded === "offloaded") {
        // A retained restore root can coexist with an offload. It must never
        // enter this cleanup-only deletion path or end its stored-disk pointer.
        const offload = await db.prisma.$transaction((tx) =>
          seedStoredOffload(tx, {
            sandboxId: f.sandbox.id,
            userId: f.seed.owner.ownerId,
            hostId: f.seed.hostId,
          }),
        );
        offloadId = offload.offloadId;
        await db.inspect.sandbox.update({
          where: { id: f.sandbox.id },
          data: { diskOffloadId: offloadId, offloadSeq: 1 },
        });
      }
      const before = await f.row();
      const host = await f.host();
      const pool = await f.pool();
      // A STORED disk follows the established OFFLOADED detach, never this
      // new DELETED path. Other excluded cases keep the retained ERROR root.
      expect(await convergeInventoryEntry(f.sender, f.entry, clock)).toEqual({
        converged: !!offloadId,
      });
      expect(await f.row()).toMatchObject({
        state: offloadId ? "OFFLOADED" : "ERROR",
        generation: before.generation + (offloadId ? 1 : 0),
        diskReservationHeld: !offloadId,
        diskOffloadId: offloadId,
        sandboxHostId: offloadId ? null : f.seed.hostId,
        lastErrorCode: before.lastErrorCode,
        lastErrorDetail: before.lastErrorDetail,
      });
      expect(await f.host()).toMatchObject({
        rootCount: offloadId ? 0 : host.rootCount,
        liveCount: host.liveCount,
      });
      expect(await f.pool()).toMatchObject({
        diskReservedGiB: offloadId ? 0 : pool.diskReservedGiB,
      });
      expect(
        await db.inspect.sandboxOperation.count({
          where: { sandboxId: f.sandbox.id, kind: "KILL_SANDBOX", state: "SUCCEEDED" },
        }),
      ).toBe(0);
      if (offloadId) {
        expect(
          await db.inspect.sandboxDiskOffload.findUniqueOrThrow({ where: { id: offloadId } }),
        ).toMatchObject({ state: "STORED", liveSandboxId: f.sandbox.id, destroyOperationId: null });
      }
      if (recovery) {
        expect(
          await db.inspect.credentialLease.findUniqueOrThrow({ where: { id: recovery.lease.id } }),
        ).toMatchObject({
          state: "RECOVERY_REQUIRED",
          releasedAt: null,
          currentBindingId: recovery.binding.id,
        });
        expect(
          await db.inspect.credentialResidue.findUniqueOrThrow({
            where: { id: recovery.residue.id },
          }),
        ).toMatchObject({
          clearedAt: null,
          recoverable: true,
        });
        expect(
          await db.inspect.credentialInstance.findUniqueOrThrow({
            where: { id: recovery.instance.id },
          }),
        ).toMatchObject({ activeLeases: 1 });
      }
    },
  );

  it("failed cleanup census accepts a null error once login recovery is resolved", async () => {
    const f = await exhaustedNeverReadyCleanup();
    const recovery = await recoveryLeaseFor(f);
    await db.inspect.sandboxOperation.updateMany({
      where: { sandboxId: f.sandbox.id, generation: f.stuck.generation, kind: "KILL_SANDBOX" },
      data: { errorCode: null },
    });
    await db.inspect.credentialLease.update({
      where: { id: recovery.lease.id },
      data: { state: "FORCE_RELEASED", releasedAt: new Date(), endReason: "force_released" },
    });
    await db.inspect.credentialInstance.update({
      where: { id: recovery.instance.id },
      data: { activeLeases: 0 },
    });
    expect(await convergeInventoryEntry(f.sender, f.entry, clock)).toEqual({
      converged: true,
      rootRetired: true,
    });
    expect(await f.row()).toMatchObject({
      state: "DELETED",
      diskReservationHeld: false,
      sandboxHostId: null,
      storagePoolId: null,
    });
    expect(
      await db.inspect.credentialLease.findUniqueOrThrow({ where: { id: recovery.lease.id } }),
    ).toMatchObject({
      state: "FORCE_RELEASED",
      releasedAt: expect.any(Date),
    });
    expect(
      await db.inspect.credentialResidue.findUniqueOrThrow({ where: { id: recovery.residue.id } }),
    ).toMatchObject({
      clearedAt: expect.any(Date),
      recoverable: false,
    });
    expect(
      await db.inspect.credentialInstance.findUniqueOrThrow({
        where: { id: recovery.instance.id },
      }),
    ).toMatchObject({ activeLeases: 0 });
    expect(await f.host()).toMatchObject({ rootCount: 0, liveCount: 0 });
    expect(await f.pool()).toMatchObject({ diskReservedGiB: 0 });
  });

  it("concurrent failed cleanup census replay releases the root exactly once", async () => {
    const f = await exhaustedNeverReadyCleanup();
    const gate = db.pauseAt("cleanup-one", { after: "sandboxOperation.create" });
    const first = db.run("cleanup-one", () => convergeInventoryEntry(f.sender, f.entry, clock));
    await gate.waitReached();
    const second = db.run("cleanup-two", () => convergeInventoryEntry(f.sender, f.entry, clock));
    try {
      expect((await db.waitUntilBlocked("cleanup-two", { by: "cleanup-one" })).query).toMatch(
        /sandbox_host/,
      );
    } finally {
      gate.release();
    }
    const outcomes = await Promise.all([first, second]);
    expect(outcomes.filter((outcome) => "converged" in outcome && outcome.converged)).toHaveLength(
      1,
    );
    expect(await f.row()).toMatchObject({
      state: "DELETED",
      generation: f.stuck.generation + 1,
      diskReservationHeld: false,
      sandboxHostId: null,
      storagePoolId: null,
    });
    expect(await f.host()).toMatchObject({ rootCount: 0, liveCount: 0 });
    expect(await f.pool()).toMatchObject({ diskReservedGiB: 0 });
    expect(
      await db.inspect.sandboxOperation.count({
        where: { sandboxId: f.sandbox.id, kind: "KILL_SANDBOX", state: "SUCCEEDED" },
      }),
    ).toBe(1);
    expect(await convergeInventoryEntry(f.sender, f.entry, clock)).toEqual({
      converged: true,
      rootRetired: true,
    });
    expect(await f.host()).toMatchObject({ rootCount: 0 });
    expect(await f.pool()).toMatchObject({ diskReservedGiB: 0 });
  });

  it.each(["generation", "epoch"] as const)(
    "a concurrent %s advance fences failed cleanup census settlement",
    async (advance) => {
      const f = await exhaustedNeverReadyCleanup();
      const { lockOwnerForAdmission } = await import("@wssp/db/account-deletion");
      const { lockHostByEpoch } = await import("@wssp/api/sandbox/relay-fence");
      const gate = db.pauseAt("cleanup-writer", {
        after: advance === "generation" ? "sandbox.update" : "sandboxHost.update",
      });
      const writer = db.run("cleanup-writer", () =>
        db.prisma.$transaction(async (tx) => {
          await lockOwnerForAdmission(tx, f.seed.owner.ownerId);
          await lockHostByEpoch(tx, f.seed.hostId, f.sender.connectionEpoch, f.seed.owner.ownerId);
          if (advance === "generation") {
            await tx.sandbox.update({
              where: { id: f.sandbox.id },
              data: { generation: { increment: 1 } },
            });
          } else {
            await tx.sandboxHost.update({
              where: { id: f.seed.hostId },
              data: { connectionEpoch: { increment: 1 } },
            });
          }
        }),
      );
      await gate.waitReached();
      const report = db.run("cleanup-census", () =>
        convergeInventoryEntry(f.sender, f.entry, clock),
      );
      try {
        expect(
          (await db.waitUntilBlocked("cleanup-census", { by: "cleanup-writer" })).query,
        ).toMatch(/sandbox_host/);
      } finally {
        gate.release();
      }
      await writer;
      expect(await report).toEqual({ stale: true });
      expect(await f.row()).toMatchObject({
        state: "ERROR",
        diskReservationHeld: true,
        generation: f.stuck.generation + (advance === "generation" ? 1 : 0),
        sandboxHostId: f.seed.hostId,
      });
      expect(await f.host()).toMatchObject({ rootCount: 1, liveCount: 0 });
      expect((await f.pool()).diskReservedGiB).toBeGreaterThan(0);
    },
  );

  it("census does not turn a never-ready failed CREATE without a failed KILL into DELETED", async () => {
    const seed = await seedHost();
    const sandbox = await createSandbox(
      seed.owner,
      createSandboxInput.parse({
        template: "revision/" + seed.templateId,
        sandboxHostId: seed.hostId,
        idempotencyKey: `create-${randomUUID()}`,
      }),
    );
    await processSandboxOutboxBatch(clock);
    const create = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: sandbox.id, kind: "CREATE_SANDBOX" },
    });
    expect(
      await applyOperationResult(
        {
          sender: { userId: seed.owner.ownerId, hostId: seed.hostId, connectionEpoch: 1 },
          operationId: create.id,
          sandboxId: sandbox.id,
          generation: create.generation,
          attempt: create.dispatchAttempt,
          state: "failed",
          error: { code: "internal", message: "create failed" },
        },
        clock,
      ),
    ).toEqual({ written: true });
    const row = () => db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } });
    expect(await row()).toMatchObject({
      state: "ERROR",
      readyAt: null,
      liveResourcesHeld: false,
      diskReservationHeld: true,
    });
    const sender = await reconnectHost(seed);
    await census(sender, [{ sandboxId: sandbox.id, state: "absent" }]);
    expect(await row()).toMatchObject({
      state: "ERROR",
      diskReservationHeld: true,
      sandboxHostId: seed.hostId,
    });
  });

  it("a completed expiry releases the slot a cold reconnect left held and settles its unknown outcome", async () => {
    const seed = await seedHost();
    const sandboxId = await readySandbox(seed);
    const row = () => db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
    const reserved = async () =>
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: seed.hostId } })).liveCount;

    // Stop cleanly, then cold-reconnect: the slot is reserved again while the
    // server state stays STOPPED.
    await stopSandbox(seed.owner, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
    await processSandboxOutboxBatch(clock);
    const stop = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId, kind: "STOP_SANDBOX" },
    });
    expect(await reportSucceeded(stop.id, "stopped", 1)).toEqual({ written: true });
    expect(await row()).toMatchObject({ state: "STOPPED", liveResourcesHeld: false });
    expect(await reserved()).toBe(0);

    await reconnectSandbox(seed.owner, { id: sandboxId, idempotencyKey: `re-${randomUUID()}` });
    await processSandboxOutboxBatch(clock);
    const reconnect = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId, kind: "RECONNECT_SANDBOX", state: "DISPATCHED" },
    });
    // The host's answer is lost: the server keeps STOPPED and the held slot.
    const reconnectEvent = await db.inspect.outboxEvent.findFirstOrThrow({
      where: { aggregateId: sandboxId, payload: { path: ["operationId"], equals: reconnect.id } },
    });
    const reconnectPayload = reconnectEvent.payload as Record<string, unknown>;
    expect(
      await applyOperationResult(
        {
          sender: { userId: seed.owner.ownerId, hostId: seed.hostId, connectionEpoch: 1 },
          operationId: reconnect.id,
          sandboxId,
          generation: reconnect.generation,
          attempt: reconnect.dispatchAttempt,
          state: "unknown_outcome",
          error: { code: "unknown_outcome", message: "connection lost" },
        },
        clock,
      ),
    ).toEqual({ written: true, allocationUnknown: true });
    expect(await row()).toMatchObject({ state: "STOPPED", liveResourcesHeld: true });
    expect(await reserved()).toBe(1);

    // Time passes; the reconnect lease the host holds expires on the host.
    const past = new Date(Date.now() - 120_000);
    const leaseRevision = (reconnectPayload.lease as { revision: number }).revision;
    const warpedLease = {
      ...(reconnectPayload.lease as Record<string, unknown>),
      deadlineUnixMs: past.getTime(),
    };
    await db.inspect.sandbox.update({
      where: { id: sandboxId },
      data: { leaseExpiresAt: past },
    });
    await db.inspect.outboxEvent.update({
      where: { id: reconnectEvent.id },
      data: { payload: { ...reconnectPayload, lease: warpedLease } },
    });
    // Warp the accepted tuple with this fixture's clock; production never edits it.
    await db.inspect.sandboxOperation.update({
      where: { id: reconnect.id },
      data: {
        leaseExpiresAtAccepted: past,
        leaseAcceptedAt: new Date(past.getTime() - (reconnect.leaseTimeoutMs ?? 300000)),
      },
    });
    const arm = {
      generation: reconnect.generation,
      lease: warpedLease,
      expired: true,
      expiryComplete: true,
      timerExpired: true,
    };
    const connected = await reconnectHost(seed);
    // While the arm is still failing, the uncertain allocation blocks every
    // inference; nothing about the sandbox changes.
    expect(
      await judgeExpiryStatus(
        connected,
        [
          {
            root: null,
            sandboxOwnerId: connected.userId,
            sandboxId,
            state: "ready",
            lease: {
              ...arm,
              expiryComplete: false,
              expiryFailure: { reason: "stop failed", attempts: 1, sinceUnixMs: past.getTime() },
            },
          } as never,
        ],
        clock,
      ),
    ).toHaveProperty("results");
    expect(await row()).toMatchObject({ state: "STOPPED", liveResourcesHeld: true });
    // The completed recovery frees the held slot and settles the allocation.
    expect(
      await judgeExpiryStatus(
        connected,
        [
          {
            root: null,
            sandboxOwnerId: connected.userId,
            sandboxId,
            state: "stopped",
            lease: arm,
          } as never,
        ],
        clock,
      ),
    ).toHaveProperty("results");
    expect(await row()).toMatchObject({
      state: "STOPPED",
      generation: reconnect.generation,
      liveResourcesHeld: false,
      hostExpiryAction: "STOP",
      hostExpiryRevision: leaseRevision,
    });
    expect(await reserved()).toBe(0);
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: reconnect.id } }),
    ).toMatchObject({ state: "CANCELLED" });
    expect(await processSandboxOutboxBatch(clock)).toBe(0);
    expect(await reclaimExpiredSandboxLeases(clock)).toBe(0);
  });
});

describe("reconciler health owner/epoch CAS on disposable PostgreSQL", () => {
  it("records current health, refuses stale epoch and foreign owner, and never changes admission", async () => {
    const ownerId = `health-${randomUUID()}`;
    await db.inspect.user.create({
      data: { id: ownerId, name: "Owner", email: `${ownerId}@example.test` },
    });
    const host = await seedLaunchHost(db.inspect, {
      data: {
        userId: ownerId,
        slug: "lab",
        label: "Lab",
        connectionEpoch: 2,
        egressEnforcement: false,
        liveCount: 1,
      },
    });
    const sender = { hostId: host.id, userId: ownerId, connectionEpoch: 2 };
    const health = {
      enabled: true,
      lastPassUnixMs: 123,
      verified: 0,
      drift: 1,
      inconclusive: 0,
      foreign: 0,
      absent: 0,
      pending: 0,
    };
    const now = new Date("2030-01-01T00:00:00.000Z");
    expect(await recordHostHeartbeat(sender, health, now)).toBe(true);
    expect(
      await recordHostHeartbeat(
        { ...sender, connectionEpoch: 1 },
        { ...health, drift: 0 },
        new Date(now.getTime() + 1),
      ),
    ).toBe(false);
    expect(
      await recordHostHeartbeat(
        { ...sender, userId: `foreign-${randomUUID()}` },
        { ...health, drift: 0 },
        new Date(now.getTime() + 2),
      ),
    ).toBe(false);
    const result = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: host.id } });
    expect(result.policyReconcilerHealth).toEqual({
      ...health,
      reportedAt: result.lastHeartbeatAt!.toISOString(),
    });
    expect(Math.abs(result.lastHeartbeatAt!.getTime() - Date.now())).toBeLessThan(10_000);
    expect(result.lastHeartbeatAt).not.toEqual(now);
    expect(result).toMatchObject({ egressEnforcement: false, liveCount: 1, connectionEpoch: 2 });
    expect(await recordHostHeartbeat(sender, undefined, now)).toBe(true);
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: host.id } }))
        .policyReconcilerHealth,
    ).toEqual(result.policyReconcilerHealth);
  });
});

describe("2A admission and epoch-bound censuses", () => {
  it("admission_refuses_stale_epoch_without_changing_legacy_enforcement", async () => {
    const { recordHostAdmission } = await import("./inventory-reconcile.js");
    const f = await seedHost();
    const sender = { userId: f.owner.ownerId, hostId: f.hostId, connectionEpoch: 1 };
    const report = {
      vmCapacity: capacityFixture(f.hostId).vmCapacity,
      storagePools: capacityFixture(f.hostId).storagePools,
      journalId: "1234567890abcdef1234567890abcdef",
      type: "host.admission" as const,
      connectionEpoch: 1,
      runtimeKind: "fake" as const,
      schedulable: false,
      egressPolicy: false,
      terminal: false,
    };
    expect(await recordHostAdmission(sender, report, clock(), {})).toBe(true);
    const row = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } });
    expect(row).toMatchObject({
      admissionEpoch: 1,
      daemonSchedulable: false,
      egressEnforcement: true,
    });
    await reconnectHost(f);
    expect(await recordHostAdmission(sender, { ...report, schedulable: true }, clock(), {})).toBe(
      false,
    );
    expect(await recordHostAdmission({ ...sender, connectionEpoch: 2 }, report, clock(), {})).toBe(
      false,
    );
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } }),
    ).toMatchObject({ daemonSchedulable: false });
  });

  it("inventory_ack_epoch_requires_complete_current_census", async () => {
    const f = await seedHost();
    // A complete census never substitutes for a journal key ACK.
    await db.inspect.sandboxHost.update({
      where: { id: f.hostId },
      data: {
        inventoryAcknowledgedEpoch: null,
        journalKeyVersion: 1,
        journalKeyId: "d".repeat(32),
        journalKeyAcknowledgedEpoch: null,
      },
    });
    const sender = { userId: f.owner.ownerId, hostId: f.hostId, connectionEpoch: 1 };
    const census = new InventoryCensus(sender);
    await census.acceptPage({ type: "sandbox.inventory", page: 0, complete: false, entries: [] });
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } }),
    ).toMatchObject({ inventoryAcknowledgedEpoch: null, journalKeyAcknowledgedEpoch: null });
    await reconnectHost(f);
    expect(
      await census.acceptPage({ type: "sandbox.inventory", page: 1, complete: true, entries: [] }),
    ).toEqual({ stale: true });
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } }),
    ).toMatchObject({ inventoryAcknowledgedEpoch: null, journalKeyAcknowledgedEpoch: null });
    const current = new InventoryCensus({ ...sender, connectionEpoch: 2 });
    await current.acceptPage({ type: "sandbox.inventory", page: 0, complete: true, entries: [] });
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } }),
    ).toMatchObject({ inventoryAcknowledgedEpoch: 2, journalKeyAcknowledgedEpoch: null });
  });

  it("availability_requires_exact_request_page_epoch_binding_and_omission_proves_nothing", async () => {
    const { AvailabilityCensus } = await import("./availability-census.js");
    const f = await seedHost();
    const sender = { userId: f.owner.ownerId, hostId: f.hostId, connectionEpoch: 1 };
    const requests: Extract<
      import("./protocol.js").ServerControlMessage,
      { type: "availability.request" }
    >[] = [];
    const census = new AvailabilityCensus(sender, (message) => {
      if (message.type === "availability.request") requests.push(message);
    });
    await census.next();
    await census.next();
    expect(requests).toHaveLength(1);
    const request = requests[0]!;
    const result = {
      type: "availability.result" as const,
      requestId: request.requestId,
      connectionEpoch: 1,
      page: 0,
      entries: [{ binding: request.bindings[0]!, status: "present" as const }],
    };
    for (const bad of [
      { ...result, requestId: "wrong" },
      { ...result, connectionEpoch: 2 },
      { ...result, page: 1 },
    ])
      await census.accept(bad);
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } }),
    ).toMatchObject({ availabilityEpoch: null });
    await expect(
      census.accept({
        ...result,
        entries: [
          {
            ...result.entries[0]!,
            binding: { ...request.bindings[0]!, manifestHash: "e".repeat(64) },
          },
        ],
      }),
    ).rejects.toThrow("availability binding mismatch");
    await census.accept({ ...result, entries: [] });
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } }),
    ).toMatchObject({ availabilityEpoch: 1, availabilityCensusComplete: false });
    expect(
      await db.inspect.sandboxTemplateAvailability.findFirst({
        where: { revisionId: f.templateId, hostId: f.hostId },
      }),
    ).toMatchObject({ status: "AVAILABLE", verifiedConnectionEpoch: 1 });
    const retry = new AvailabilityCensus(sender, (message) => {
      if (message.type === "availability.request") requests.push(message);
    });
    await retry.next();
    await retry.accept({ ...result, requestId: requests[1]!.requestId });
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } }),
    ).toMatchObject({
      availabilityCensusComplete: true,
    });
    expect(
      await db.inspect.sandboxTemplateAvailability.findFirst({
        where: { revisionId: f.templateId, hostId: f.hostId },
      }),
    ).toMatchObject({ status: "AVAILABLE", verifiedConnectionEpoch: 1 });
    const stale = new AvailabilityCensus(sender, (message) => {
      if (message.type === "availability.request") requests.push(message);
    });
    await stale.next();
    await reconnectHost(f);
    await stale.accept({
      ...result,
      requestId: requests[2]!.requestId,
      entries: [{ binding: request.bindings[0]!, status: "missing" }],
    });
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } }),
    ).toMatchObject({
      availabilityEpoch: 1,
    });
  });

  it("availability_timeout_does_not_record_a_verdict", async () => {
    const { AvailabilityCensus } = await import("./availability-census.js");
    const f = await seedHost();
    let now = 0;
    let request:
      | Extract<import("./protocol.js").ServerControlMessage, { type: "availability.request" }>
      | undefined;
    const census = new AvailabilityCensus(
      { userId: f.owner.ownerId, hostId: f.hostId, connectionEpoch: 1 },
      (message) => {
        if (message.type === "availability.request") request = message;
      },
      () => now,
    );
    await census.next();
    if (!request) throw new Error("expected request");
    now = 30_001;
    await census.accept({
      type: "availability.result",
      requestId: request.requestId,
      connectionEpoch: 1,
      page: 0,
      entries: [{ binding: request.bindings[0]!, status: "present" }],
    });
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } }),
    ).toMatchObject({ availabilityEpoch: null, availabilityCensusComplete: false });
  });
});

describe("UNKNOWN targeted attestation on real PostgreSQL", () => {
  async function unknownCreate(
    state: "PROVISIONING" | "REQUESTED" | "SCHEDULED" = "PROVISIONING",
    reconnect = true,
  ) {
    const seed = await seedHost();
    await db.inspect.sandboxHost.update({
      where: { id: seed.hostId },
      data: {
        relayProtocolVersion: "1.0",
        relayProtocolEpoch: 1,
        daemonFeatures: { egressPolicy: true, terminal: false, journalId: "a".repeat(32) },
      },
    });
    const sandbox = await createSandbox(
      seed.owner,
      createSandboxInput.parse({
        template: "revision/" + seed.templateId,
        sandboxHostId: seed.hostId,
        idempotencyKey: `unknown-${randomUUID()}`,
      }),
    );
    await processSandboxOutboxBatch(clock);
    const op = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: sandbox.id, kind: "CREATE_SANDBOX" },
    });
    expect(op.dispatchAttempt).toBe(1);
    const event = await db.inspect.outboxEvent.findFirstOrThrow({
      where: { aggregateId: sandbox.id, payload: { path: ["operationId"], equals: op.id } },
    });
    const payload = event.payload as Record<string, unknown>;
    expect(payload).toMatchObject({
      allocationJournalId: "a".repeat(32),
      allocationJournalEpoch: 1,
      allocationJournalAttempt: 1,
    });
    // Preserve uncertain allocation evidence until a targeted observation
    // proves it never issued; a pending cleanup alone releases no charge.
    await db.inspect.sandboxOperation.update({
      where: { id: op.id },
      data: {
        state: "UNKNOWN_OUTCOME",
        errorCode: "host_capacity",
        errorDetail: "Host capacity is full.",
        completedAt: clock(),
        result: {},
      },
    });
    // Exercise the reported PROVISIONING hold; REQUESTED refusals are covered
    // by the same production predicate and the unit evidence matrix.
    await db.inspect.sandbox.update({ where: { id: sandbox.id }, data: { state } });
    const sender = reconnect
      ? await reconnectHost(seed)
      : { userId: seed.owner.ownerId, hostId: seed.hostId, connectionEpoch: 1 };
    if (!reconnect)
      await db.inspect.outboxEvent.update({
        where: { id: event.id },
        data: {
          payload: { ...payload, allocationDispatchSequence: 1 },
        },
      });
    await db.inspect.sandboxHost.update({
      where: { id: seed.hostId },
      data: {
        relayProtocolVersion: "1.0",
        relayProtocolEpoch: sender.connectionEpoch,
        admissionEpoch: sender.connectionEpoch,
        inventoryAcknowledgedEpoch: null,
      },
    });
    const row = () => db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } });
    const host = () => db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: seed.hostId } });
    const pass = () => ({
      convergedCount: 0,
      async acceptPage(frame: {
        connectionEpoch?: number;
        barrier?: number;
        journalId?: string;
        entries: { sandboxId: string; sandboxOwnerId?: string; settledNeverIssued: boolean }[];
      }) {
        if (
          frame.connectionEpoch === undefined ||
          frame.barrier === undefined ||
          frame.journalId === undefined
        )
          return { ok: true };
        for (const entry of frame.entries) {
          if (!entry.settledNeverIssued) continue;
          const result = await convergeInventoryEntry(
            sender,
            {
              sandboxOwnerId: sender.userId,
              root: null,
              sandboxId: entry.sandboxId,
              state: "absent",
            },
            undefined,
            {
              connectionEpoch: frame.connectionEpoch,
              barrier: frame.barrier,
              journalId: frame.journalId,
              root: {
                storagePoolName: sandbox.storagePoolName!,
                storageMarker: sandbox.storageMarker!,
                diskGiB: sandbox.diskGiB,
              },
            },
          );
          if ("stale" in result) return result;
          if ("converged" in result && result.converged) this.convergedCount++;
        }
        return { ok: true };
      },
    });
    const frame = {
      root: {
        storagePoolName: sandbox.storagePoolName!,
        storageMarker: sandbox.storageMarker!,
        diskGiB: sandbox.diskGiB,
      },
      connectionEpoch: sender.connectionEpoch,
      barrier: 10,
      journalId: "a".repeat(32),
      entries: [{ sandboxOwnerId: sender.userId, sandboxId: sandbox.id, settledNeverIssued: true }],
    };
    const success = () =>
      applyOperationResult({
        sender,
        operationId: op.id,
        sandboxId: sandbox.id,
        generation: op.generation,
        attempt: op.dispatchAttempt,
        state: "succeeded",
        receipt: {
          bodyHash: op.requestBodyHash,
          idempotencyKey: op.idempotencyKey,
          kind: "sandbox.create",
        },
        result: { state: "ready", lease: payload.lease },
      });
    expect(await row()).toMatchObject({ state, liveResourcesHeld: true });
    expect(await host()).toMatchObject({ liveCount: 1, memoryReservedMiB: 1344 });
    return { seed, sandbox, op, event, payload, sender, row, host, pass, frame, success };
  }

  it.each(["host_capacity", "sandbox_not_found", "state_conflict"] as const)(
    "a refused first cold reconnect (%s) releases its slot once and preserves STOPPED",
    async (code) => {
      const seed = await seedHost();
      const sandboxId = await readySandbox(seed);
      await stopSandbox(seed.owner, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
      await processSandboxOutboxBatch(clock);
      const stop = await db.inspect.sandboxOperation.findFirstOrThrow({
        where: { sandboxId, kind: "STOP_SANDBOX" },
      });
      expect(await reportSucceeded(stop.id, "stopped", 1)).toEqual({ written: true });
      await reconnectSandbox(seed.owner, { id: sandboxId, idempotencyKey: `cold-${randomUUID()}` });
      await processSandboxOutboxBatch(clock);
      const op = await db.inspect.sandboxOperation.findFirstOrThrow({
        where: { sandboxId, kind: "RECONNECT_SANDBOX" },
      });
      expect(op.dispatchAttempt).toBe(1);
      expect(op.launchMode).toBe("COLD");
      const row = () => db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
      const host = () => db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: seed.hostId } });
      expect(await row()).toMatchObject({ state: "STOPPED", liveResourcesHeld: true });
      expect(await host()).toMatchObject({ liveCount: 1, memoryReservedMiB: 1344 });
      const refusal = {
        sender: { userId: seed.owner.ownerId, hostId: seed.hostId, connectionEpoch: 1 },
        operationId: op.id,
        sandboxId,
        generation: op.generation,
        attempt: op.dispatchAttempt,
        state: "failed" as const,
        error: { code, message: "host refused dispatch admission" },
      };
      expect(await applyOperationResult(refusal)).toEqual({ written: true });
      const errorCode = code === "sandbox_not_found" ? "start_disk_missing" : code;
      expect(
        await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: op.id } }),
      ).toMatchObject({ state: "FAILED", errorCode });
      expect(await row()).toMatchObject({ lastErrorCode: errorCode });
      expect(await row()).toMatchObject({ state: "STOPPED", liveResourcesHeld: false });
      expect(await host()).toMatchObject({ liveCount: 0, memoryReservedMiB: 0 });
      expect(await applyOperationResult(refusal)).toEqual({ written: false });
      expect(await row()).toMatchObject({ state: "STOPPED", liveResourcesHeld: false });
      expect(await host()).toMatchObject({ liveCount: 0, memoryReservedMiB: 0 });
    },
  );

  it("refusal FAILED cannot release another host's allocation or cross its operation fence", async () => {
    const f = await unknownCreate("REQUESTED", false);
    // This is the first report of the current dispatch, before any UNKNOWN
    // has been adopted. An adopted UNKNOWN must never be demoted by a refusal.
    await db.inspect.sandboxOperation.update({
      where: { id: f.op.id },
      data: { state: "DISPATCHED" },
    });
    const other = await seedLaunchHost(db.inspect, {
      data: {
        userId: f.seed.owner.ownerId,
        slug: "other",
        label: "Other",
        status: "CONNECTED",
        connectionEpoch: 1,
        egressEnforcement: true,
      },
    });
    const refusal = {
      sender: f.sender,
      operationId: f.op.id,
      sandboxId: f.sandbox.id,
      generation: f.op.generation,
      attempt: f.op.dispatchAttempt,
      state: "failed" as const,
      error: { code: "host_capacity" as const, message: "host refused dispatch admission" },
    };
    const fenced = [
      { ...refusal, sender: { ...f.sender, hostId: other.id } },
      { ...refusal, sender: { ...f.sender, userId: "other-owner" } },
      { ...refusal, sender: { ...f.sender, connectionEpoch: 0 } },
      { ...refusal, generation: f.op.generation + 1 },
      { ...refusal, attempt: f.op.dispatchAttempt + 1 },
      { ...refusal, operationId: "other-operation" },
    ];
    for (const report of fenced) {
      expect(await applyOperationResult(report)).toEqual({ written: false });
      expect(await f.row()).toMatchObject({ state: "REQUESTED", liveResourcesHeld: true });
      expect(await f.host()).toMatchObject({ liveCount: 1, memoryReservedMiB: 1344 });
    }
    // Even a matching refusal cannot demote an already adopted UNKNOWN.
    await db.inspect.sandboxOperation.update({
      where: { id: f.op.id },
      data: { state: "UNKNOWN_OUTCOME" },
    });
    expect(await applyOperationResult(refusal)).toEqual({ written: false });
    expect(await f.row()).toMatchObject({ liveResourcesHeld: true });
    await db.inspect.sandboxOperation.update({
      where: { id: f.op.id },
      data: { state: "DISPATCHED" },
    });
    // The inverse pins prompt release of a genuine first-attempt refusal.
    expect(await applyOperationResult(refusal)).toEqual({ written: true });
    expect(await f.row()).toMatchObject({ state: "ERROR", liveResourcesHeld: false });
    expect(await f.host()).toMatchObject({ liveCount: 0, memoryReservedMiB: 0 });
    expect(await applyOperationResult(refusal)).toEqual({ written: false });
    expect(await f.host()).toMatchObject({ liveCount: 0, memoryReservedMiB: 0 });
  });

  it.each(["census", "success"])(
    "auto-release vs late SUCCEEDED: %s holds locks first",
    async (first) => {
      const f = await unknownCreate();
      const gate = db.pauseAt(first, { after: "sandboxOperation.updateMany" });
      const lead = db.run(first, async () =>
        first === "census" ? await f.pass().acceptPage(f.frame) : await f.success(),
      );
      await gate.waitReached();
      const second = first === "census" ? "success" : "census";
      const follower = db.run(second, async () =>
        second === "census" ? await f.pass().acceptPage(f.frame) : await f.success(),
      );
      try {
        expect((await db.waitUntilBlocked(second, { by: first })).query).toMatch(/sandbox_host/);
      } finally {
        gate.release();
      }
      const [a, b] = await Promise.all([lead, follower]);
      if (first === "census") {
        expect(b).toEqual({ written: false });
        expect(await f.row()).toMatchObject({
          state: "ERROR",
          generation: 2,
          liveResourcesHeld: false,
        });
        expect(await f.host()).toMatchObject({ liveCount: 0, memoryReservedMiB: 0 });
        const failed = await db.inspect.sandboxOperation.findUniqueOrThrow({
          where: { id: f.op.id },
        });
        expect(failed).toMatchObject({ state: "FAILED", errorCode: "host_effect_not_issued" });
        // The clock is sampled after O, not from the injected census wall clock.
        expect(Math.abs(failed.completedAt!.getTime() - Date.now())).toBeLessThan(10_000);
        expect(await f.success()).toEqual({ written: false });
        expect(
          await new InventoryCensus(f.sender).acceptPage({
            type: "sandbox.inventory",
            page: 0,
            complete: true,
            entries: [
              {
                sandboxOwnerId: f.sender.userId,
                root: null,
                sandboxId: f.sandbox.id,
                state: "ready",
              },
            ],
          }),
        ).toEqual({ ok: true });
        expect(await f.host()).toMatchObject({
          quarantinedAt: expect.any(Date),
          liveCount: 0,
          memoryReservedMiB: 0,
        });
      } else {
        expect(a).toEqual({ written: true });
        expect(await f.row()).toMatchObject({ state: "READY", liveResourcesHeld: true });
        expect(await f.host()).toMatchObject({ liveCount: 1, memoryReservedMiB: 1344 });
      }
    },
  );

  it.each(["stop", "destroy"] as const)(
    "auto-release vs concurrent %s, both lock orders",
    async (kind) => {
      for (const first of ["census", "teardown"]) {
        const f = await unknownCreate();
        const teardown = () =>
          (kind === "stop" ? stopSandbox : killSandbox)(f.seed.owner, {
            id: f.sandbox.id,
            idempotencyKey: `race-${kind}-${randomUUID()}`,
          });
        const outcome = (work: Promise<unknown>) =>
          work.then(
            (value) => ({ value, error: null }),
            (error: unknown) => ({ value: null, error }),
          );
        const gate = db.pauseAt(
          first,
          first === "census"
            ? { after: "sandboxOperation.updateMany" }
            : { after: "outboxEvent.create" },
        );
        const lead = db.run(first, () =>
          outcome(first === "census" ? f.pass().acceptPage(f.frame) : teardown()),
        );
        await gate.waitReached();
        const second = first === "census" ? "teardown" : "census";
        const follower = db.run(second, () =>
          outcome(second === "census" ? f.pass().acceptPage(f.frame) : teardown()),
        );
        try {
          expect((await db.waitUntilBlocked(second, { by: first })).query).toMatch(/sandbox_host/);
        } finally {
          gate.release();
        }
        const results = await Promise.all([lead, follower]);
        if (first === "census" && kind === "stop") {
          expect(results[1].error).toMatchObject({ data: { code: "sandbox.state_conflict" } });
          expect(await f.row()).toMatchObject({ state: "ERROR", liveResourcesHeld: false });
        } else {
          expect(results.every((result) => result.error === null)).toBe(true);
          const held = first === "teardown";
          expect(await f.row()).toMatchObject({ liveResourcesHeld: held });
          expect(await f.host()).toMatchObject({
            liveCount: held ? 1 : 0,
            memoryReservedMiB: held ? 1344 : 0,
          });
          // Teardown wins a generation; its host result supplies the normal
          // deletion proof. Replaying it or the old allocation never releases twice.
          await processSandboxOutboxBatch(clock);
          const op = await db.inspect.sandboxOperation.findFirstOrThrow({
            where: {
              sandboxId: f.sandbox.id,
              kind: kind === "stop" ? "STOP_SANDBOX" : "KILL_SANDBOX",
            },
          });
          const result = {
            sender: f.sender,
            operationId: op.id,
            sandboxId: f.sandbox.id,
            generation: op.generation,
            attempt: op.dispatchAttempt,
            state: "succeeded",
            result: { state: kind === "stop" ? "absent" : "deleted" },
          };
          // Reconciliation opens dispatch only after its complete census.
          expect(op.dispatchAttempt).toBe(1);
          expect(await applyOperationResult(result)).toEqual({ written: true });
          expect(await applyOperationResult(result)).toEqual({ written: false });
          expect(await f.success()).toEqual({ written: false });
          expect(await f.row()).toMatchObject({
            state: kind === "stop" ? "STOPPING" : "DELETED",
            liveResourcesHeld: false,
          });
        }
        expect(await f.host()).toMatchObject({ liveCount: 0, memoryReservedMiB: 0 });
      }
    },
  );

  it("two concurrent attestation passes release exactly once under the host lock", async () => {
    const f = await unknownCreate();
    const one = f.pass(),
      two = f.pass();
    const gate = db.pauseAt("one", { after: "sandboxOperation.updateMany" });
    const first = db.run("one", () => one.acceptPage(f.frame));
    await gate.waitReached();
    const second = db.run("two", () => two.acceptPage(f.frame));
    try {
      expect((await db.waitUntilBlocked("two", { by: "one" })).query).toMatch(/sandbox_host/);
    } finally {
      gate.release();
    }
    await Promise.all([first, second]);
    expect(one.convergedCount + two.convergedCount).toBe(1);
    expect(await f.row()).toMatchObject({ state: "ERROR", liveResourcesHeld: false });
    expect(await f.host()).toMatchObject({ liveCount: 0, memoryReservedMiB: 0 });
  });

  it.each([
    "present",
    "inflight",
    "no-attestation",
    "old-host",
    "new-generation",
    "stale-session",
    "partial",
  ])("%s cannot release a held allocation on PostgreSQL", async (evidence) => {
    const f = await unknownCreate();
    if (evidence === "old-host")
      await db.inspect.sandboxHost.update({
        where: { id: f.seed.hostId },
        data: { relayProtocolVersion: "0.7" },
      });
    if (evidence === "new-generation")
      await db.inspect.sandbox.update({
        where: { id: f.sandbox.id },
        data: { generation: { increment: 1 } },
      });
    if (evidence === "stale-session")
      await db.inspect.sandboxHost.update({
        where: { id: f.seed.hostId },
        data: { connectionEpoch: { increment: 1 } },
      });
    const outcome = await f.pass().acceptPage({
      ...f.frame,
      entries: [
        {
          sandboxOwnerId: f.sender.userId,
          sandboxId: f.sandbox.id,
          settledNeverIssued: !["present", "inflight"].includes(evidence),
        },
      ],
      connectionEpoch: ["no-attestation", "partial"].includes(evidence)
        ? undefined
        : f.sender.connectionEpoch,
    });
    expect(outcome).toEqual(evidence === "stale-session" ? { stale: true } : { ok: true });
    expect(await f.row()).toMatchObject({ liveResourcesHeld: true });
    expect(await f.host()).toMatchObject({ liveCount: 1, memoryReservedMiB: 1344 });
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.op.id } }),
    ).toMatchObject({ state: "UNKNOWN_OUTCOME" });
  });

  it("admission persists an epoch-bound immutable journal identity", async () => {
    const f = await unknownCreate();
    const { recordHostAdmission } = await import("./inventory-reconcile.js");
    const state: import("./inventory-reconcile.js").HostAdmissionState = {};
    const report = {
      storagePools: capacityFixture(f.sender.hostId).storagePools,
      type: "host.admission" as const,
      connectionEpoch: f.sender.connectionEpoch,
      runtimeKind: "fake" as const,
      schedulable: true,
      egressPolicy: true,
      terminal: false,
      vmCapacity: { vcpuBudget: 64, memoryBudgetMiB: 65536, maxCpuCount: 32 },
      journalId: "a".repeat(32),
    };
    expect(await recordHostAdmission(f.sender, report, clock(), state)).toBe(true);
    expect((await f.host()).daemonFeatures).toMatchObject({ journalId: "a".repeat(32) });
    await expect(
      recordHostAdmission(f.sender, { ...report, journalId: "b".repeat(32) }, clock(), state),
    ).rejects.toThrow("An internal error occurred.");
    expect((await f.host()).daemonFeatures).toMatchObject({ journalId: "a".repeat(32) });
  });

  it.each(["fresh-journal", "missing-history"])(
    "%s cannot release an older session's allocation",
    async (evidence) => {
      const f = await unknownCreate();
      const frame = { ...f.frame };
      if (evidence === "fresh-journal") {
        await db.inspect.sandboxHost.update({
          where: { id: f.seed.hostId },
          data: { daemonFeatures: { journalId: "b".repeat(32) } },
        });
        frame.journalId = "b".repeat(32);
      } else {
        await db.inspect.outboxEvent.update({
          where: { id: f.event.id },
          data: { payload: { ...f.payload, allocationJournalId: null } },
        });
      }
      await f.pass().acceptPage(frame);
      expect(await f.row()).toMatchObject({ liveResourcesHeld: true });
      expect(await f.host()).toMatchObject({ liveCount: 1, memoryReservedMiB: 1344 });
    },
  );

  it("settles a lost UNKNOWN after reconciliation and targeted proof; reconciliation cannot resurrect it", async () => {
    const f = await unknownCreate();
    await db.inspect.sandboxOperation.update({
      where: { id: f.op.id },
      data: { state: "DISPATCHED", completedAt: null },
    });
    const { finishHostReconciliation } = await import("./operation-handlers.js");
    expect(await finishHostReconciliation(f.sender)).toBe(true);
    const pass = f.pass();
    expect(await pass.acceptPage(f.frame)).toEqual({ ok: true });
    expect(pass.convergedCount).toBe(1);
    expect(await finishHostReconciliation(f.sender)).toBe(true);
    expect(await f.row()).toMatchObject({
      state: "ERROR",
      generation: 2,
      liveResourcesHeld: false,
    });
    const op = await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.op.id } });
    expect(op).toMatchObject({ state: "FAILED", errorCode: "host_effect_not_issued" });
    expect(Math.abs(op.completedAt!.getTime() - Date.now())).toBeLessThan(10_000);
    expect(await f.host()).toMatchObject({ liveCount: 0, memoryReservedMiB: 0 });
    expect(await f.success()).toEqual({ written: false });
  });

  it("a barrier before a later attempt, or without attestation, never releases", async () => {
    const f = await unknownCreate();
    // Model a snapshot captured in the same epoch as a later dispatch. A
    // reconnect barrier must be strictly NEWER than its dispatched epoch.
    await db.inspect.sandboxOperation.update({
      where: { id: f.op.id },
      data: { dispatchedConnectionEpoch: f.sender.connectionEpoch, dispatchAttempt: 2 },
    });
    await db.inspect.outboxEvent.update({
      where: { id: f.event.id },
      data: {
        payload: {
          ...f.payload,
          allocationJournalEpoch: f.sender.connectionEpoch,
          allocationJournalAttempt: 2,
        },
      },
    });
    await f.pass().acceptPage(f.frame);
    expect(await f.row()).toMatchObject({ state: "PROVISIONING", liveResourcesHeld: true });
    expect(await f.host()).toMatchObject({ liveCount: 1, memoryReservedMiB: 1344 });
    const { barrier: _barrier, ...withoutBarrier } = f.frame;
    await f.pass().acceptPage(withoutBarrier);
    expect(await f.row()).toMatchObject({ state: "PROVISIONING", liveResourcesHeld: true });
    expect(await f.host()).toMatchObject({ liveCount: 1, memoryReservedMiB: 1344 });
  });
  it.each([
    ["REQUESTED", false],
    ["SCHEDULED", false],
    ["PROVISIONING", true],
  ] as const)(
    "%s UNKNOWN -> targeted request -> release (reconnect: %s)",
    async (state, reconnect) => {
      const f = await unknownCreate(state, reconnect);
      await db.inspect.sandboxHost.update({
        where: { id: f.seed.hostId },
        data: { relayProtocolVersion: "1.0" },
      });
      const { AllocationAttestation } = await import("./allocation-attestation.js");
      const requests: Extract<
        import("./protocol.js").ServerControlMessage,
        { type: "allocation.attest.request" }
      >[] = [];
      const attestation = new AllocationAttestation(
        f.sender,
        () => 2,
        (request) => requests.push(request),
      );
      try {
        await attestation.request();
        expect(requests).toEqual([
          {
            type: "allocation.attest.request",
            connectionEpoch: f.sender.connectionEpoch,
            barrier: 2,
            sandboxIds: [f.sandbox.id],
            allocations: [
              {
                sandboxOwnerId: f.sender.userId,
                sandboxId: f.sandbox.id,
                allocation: expect.objectContaining({
                  storagePoolName: f.sandbox.storagePoolName,
                  storageMarker: f.sandbox.storageMarker,
                  diskGiB: f.sandbox.diskGiB,
                  chargedMemoryMiB: 1344,
                  chargedVcpu: 1,
                }),
              },
            ],
          },
        ]);
        expect(
          await attestation.accept({
            type: "allocation.attest.result",
            connectionEpoch: f.sender.connectionEpoch,
            barrier: 2,
            journalId: "a".repeat(32),
            entries: [
              {
                sandboxOwnerId: f.sender.userId,
                sandboxId: f.sandbox.id,
                settledNeverIssued: true,
              },
            ],
          }),
        ).toBe(true);
        expect(await f.row()).toMatchObject({
          state: "ERROR",
          liveResourcesHeld: false,
          lastErrorCode: "host_effect_not_issued",
        });
        expect(await f.host()).toMatchObject({
          connectionEpoch: f.sender.connectionEpoch,
          liveCount: 0,
          memoryReservedMiB: 0,
        });
      } finally {
        attestation.close();
      }
    },
  );

  it("owner admission precedes H and holds no host lock while waiting on the owner", async () => {
    const f = await unknownCreate();
    const gate = db.pauseAt("owner", { after: /sql:SELECT id FROM "user".*FOR UPDATE/ });
    const owner = db.run("owner", () =>
      db.prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${f.seed.owner.ownerId} FOR UPDATE`;
      }),
    );
    await gate.waitReached();
    const release = db.run("release", () => f.pass().acceptPage(f.frame));
    try {
      expect((await db.waitUntilBlocked("release", { by: "owner" })).query).toMatch(
        /user.*FOR SHARE/,
      );
      // H would NOWAIT-fail if release had acquired it before owner admission.
      await db.prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${f.seed.hostId} FOR UPDATE NOWAIT`;
      });
    } finally {
      gate.release();
    }
    await Promise.all([owner, release]);
    expect(await f.row()).toMatchObject({ liveResourcesHeld: false });
  });

  it("the DB clock is sampled after O and after a post-lock database timestamp", async () => {
    const f = await unknownCreate();
    await db.inspect.sandboxOperation.update({
      where: { id: f.op.id },
      data: { completedAt: null },
    });
    const gate = db.pauseAt("release-clock", { before: /sql:SELECT clock_timestamp/ });
    const release = db.run("release-clock", () => f.pass().acceptPage(f.frame));
    await gate.waitReached();
    const follower = db.run("operation-lock", () =>
      db.prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE id = ${f.op.id} FOR UPDATE`;
      }),
    );
    let marker: Date;
    try {
      expect((await db.waitUntilBlocked("operation-lock", { by: "release-clock" })).query).toMatch(
        /sandbox_mutation_operation/,
      );
      const rows = await db.inspect.$queryRaw<{ now: Date }[]>`SELECT clock_timestamp() AS now`;
      marker = rows[0]!.now;
    } finally {
      gate.release();
    }
    await Promise.all([release, follower]);
    const failed = await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.op.id } });
    expect(failed.completedAt!.getTime()).toBeGreaterThanOrEqual(marker!.getTime());
  });

  it.each(["foreign_sandbox", "released_instance_present"])(
    "completed census recomputes %s from a still-observed released placement",
    async (previousReason) => {
      const f = await unknownCreate();
      await f.pass().acceptPage(f.frame);
      await db.inspect.sandboxHost.update({
        where: { id: f.seed.hostId },
        data: { quarantineReason: previousReason, quarantinedAt: new Date(0) },
      });
      const pass = new InventoryCensus(f.sender);
      expect(
        await pass.acceptPage({
          type: "sandbox.inventory",
          page: 0,
          complete: true,
          entries: [
            {
              sandboxOwnerId: f.sender.userId,
              root: null,
              sandboxId: f.sandbox.id,
              state: "stopped",
            },
          ],
        }),
      ).toEqual({ ok: true });
      expect(pass.complete).toBe(true);
      expect(await f.host()).toMatchObject({ quarantineReason: "released_instance_present" });
    },
  );

  it.each(["STOP_SANDBOX", "KILL_SANDBOX"] as const)(
    "%s with an injected not-issued code is not an auto-release contradiction",
    async (kind) => {
      const f = await unknownCreate();
      await f.pass().acceptPage(f.frame);
      await db.inspect.sandboxOperation.update({
        where: { id: f.op.id },
        data: { kind },
      });
      expect(await f.row()).toMatchObject({
        state: "ERROR",
        liveResourcesHeld: false,
        lastErrorCode: "host_effect_not_issued",
      });
      const outcome = await convergeInventoryEntry(f.sender, {
        sandboxOwnerId: f.sender.userId,
        root: null,
        sandboxId: f.sandbox.id,
        state: "stopped",
      });
      expect(outcome).not.toEqual({ conflict: "released_instance_present" });
      expect(await f.host()).toMatchObject({ quarantineReason: null, liveCount: 0 });
      const op = await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.op.id } });
      expect(op.result).not.toHaveProperty("allocationPresenceCensus");
    },
  );

  it.each(["STOP_SANDBOX", "KILL_SANDBOX"] as const)(
    "%s with an injected not-issued witness cannot retain auto-release quarantine",
    async (kind) => {
      const f = await unknownCreate();
      await f.pass().acceptPage(f.frame);
      await census(f.sender, [{ sandboxId: f.sandbox.id, state: "stopped" }]);
      expect(await f.host()).toMatchObject({ quarantineReason: "released_instance_present" });
      const op = await db.inspect.sandboxOperation.update({
        where: { id: f.op.id },
        data: { kind },
      });
      expect(op.result).toHaveProperty("allocationPresenceCensus");
      const { lockOwnerForAdmission } = await import("@wssp/db/account-deletion");
      const { lockHostByEpoch } = await import("@wssp/api/sandbox/relay-fence");
      const { clearRetiredReleaseQuarantine } = await import("@wssp/api/sandbox/host-admission");
      await db.prisma.$transaction(async (tx) => {
        await lockOwnerForAdmission(tx, f.seed.owner.ownerId);
        await lockHostByEpoch(tx, f.seed.hostId, f.sender.connectionEpoch, f.seed.owner.ownerId);
        await clearRetiredReleaseQuarantine(tx, f.seed.hostId, f.seed.owner.ownerId);
      });
      expect(await f.host()).toMatchObject({ quarantineReason: null, quarantinedAt: null });
    },
  );

  it("a still-observed foreign contradiction is contained to its sandbox: the census completes and the node is not quarantined (E3-A-01)", async () => {
    const f = await unknownCreate();
    const other = await seedLaunchHost(db.inspect, {
      data: {
        userId: f.seed.owner.ownerId,
        slug: `other-${randomUUID()}`,
        label: "Other",
      },
    });
    await db.inspect.sandbox.update({
      where: { id: f.sandbox.id },
      data: { sandboxHostId: other.id, storagePoolId: null, diskReservationHeld: false },
    });
    await db.inspect.sandboxHost.update({
      where: { id: f.seed.hostId },
      data: {
        quarantineReason: "foreign_sandbox",
        quarantinedAt: new Date(0),
      },
    });
    const pass = new InventoryCensus(f.sender);
    expect(
      await pass.acceptPage({
        type: "sandbox.inventory",
        page: 0,
        complete: true,
        entries: [
          {
            sandboxOwnerId: f.sender.userId,
            root: null,
            sandboxId: f.sandbox.id,
            state: "stopped",
          },
        ],
      }),
    ).toEqual({ ok: true });
    expect(pass.complete).toBe(true);
    expect(pass.contained).toEqual([{ sandboxId: f.sandbox.id, reason: "foreign_sandbox" }]);
    expect(await f.host()).toMatchObject({ quarantineReason: null, quarantinedAt: null });
    // Nothing was concluded about the other host's sandbox.
    expect(await f.row()).toMatchObject({ sandboxHostId: other.id });
  });

  it("release finalization clears only the held H, skipping a different noted dispatched host after S/O", async () => {
    const f = await unknownCreate();
    const other = await seedLaunchHost(db.inspect, {
      data: {
        userId: f.seed.owner.ownerId,
        slug: `other-${randomUUID()}`,
        label: "Other",
      },
    });
    await db.inspect.sandboxHost.updateMany({
      where: { id: { in: [f.seed.hostId, other.id] } },
      data: {
        quarantineReason: "released_instance_present",
        quarantinedAt: new Date(0),
      },
    });
    const { lockOwnerForAdmission } = await import("@wssp/db/account-deletion");
    const { lockHostByEpoch } = await import("@wssp/api/sandbox/relay-fence");
    const { finalizeReleasedHosts, noteHostBlockerReleased } = await import(
      "@wssp/api/sandbox/host-admission"
    );
    await db.prisma.$transaction(async (tx) => {
      await lockOwnerForAdmission(tx, f.seed.owner.ownerId);
      await lockHostByEpoch(tx, f.seed.hostId, f.sender.connectionEpoch, f.seed.owner.ownerId);
      await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${f.sandbox.id} FOR UPDATE`;
      await tx.$queryRaw`SELECT id FROM sandbox_mutation_operation WHERE id = ${f.op.id} FOR UPDATE`;
      noteHostBlockerReleased(tx, f.seed.hostId, f.seed.owner.ownerId);
      noteHostBlockerReleased(tx, other.id, f.seed.owner.ownerId);
      await finalizeReleasedHosts(tx);
    });
    expect(await f.host()).toMatchObject({ quarantineReason: null });
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: other.id } }),
    ).toMatchObject({ quarantineReason: "released_instance_present" });
  });

  it.each([
    ["none", "result"],
    ["none", "inventory"],
    ["present", "result"],
    ["absent", "result"],
    ["previous-census", "result"],
    ["stale-foreign", "result"],
    ["other-quarantine", "result"],
  ] as const)(
    "quarantine clears after owner destroy only when no other contradiction remains: %s via %s",
    async (other, via) => {
      const another = other === "present";
      const f = await unknownCreate();
      await f.pass().acceptPage(f.frame);
      const initialCensus = new InventoryCensus(f.sender);
      expect(
        await initialCensus.acceptPage({
          type: "sandbox.inventory",
          page: 0,
          complete: true,
          entries: [
            {
              sandboxOwnerId: f.sender.userId,
              root: null,
              sandboxId: f.sandbox.id,
              state: "stopped",
            },
          ],
        }),
      ).toEqual({ ok: true });
      expect(initialCensus.complete).toBe(true);
      expect(await f.host()).toMatchObject({ quarantineReason: "released_instance_present" });
      if (other === "stale-foreign") {
        // Completion replaces a previous session reason not seen this census.
        await db.inspect.sandboxHost.update({
          where: { id: f.seed.hostId },
          data: { quarantineReason: "foreign_sandbox" },
        });
        await census(f.sender, [{ sandboxId: f.sandbox.id, state: "stopped" }]);
      } else if (other === "other-quarantine") {
        // A different contradiction observed after completion is not cleared
        // by released-placement retirement.
        await db.inspect.sandboxHost.update({
          where: { id: f.seed.hostId },
          data: { quarantineReason: "foreign_sandbox" },
        });
      } else if (other !== "none") {
        // A distinct released placement on this host also contradicts the census.
        const sibling = await seedSandboxInstance(db.inspect, {
          data: {
            userId: f.seed.owner.ownerId,
            sandboxHostId: f.seed.hostId,
            originHostId: f.seed.hostId,
            templateId: f.sandbox.templateId,
            templateRevisionId: f.sandbox.templateRevisionId,
            originalSelector: "test",
            state: "ERROR",
            lastErrorCode: "host_effect_not_issued",
          },
        });
        await db.inspect.sandboxOperation.updateMany({
          where: { sandboxId: sibling.id },
          data: { state: "FAILED", errorCode: "host_effect_not_issued" },
        });
        if (another || other === "previous-census")
          expect(
            await convergeInventoryEntry(f.sender, {
              sandboxOwnerId: f.sender.userId,
              root: null,
              sandboxId: sibling.id,
              state: "stopped",
            }),
          ).toEqual({ conflict: "released_instance_present" });
        if (other === "previous-census") {
          await census(f.sender, []);
          expect(await f.host()).toMatchObject({ quarantineReason: null });
          await census(f.sender, [{ sandboxId: f.sandbox.id, state: "stopped" }]);
          expect(await f.host()).toMatchObject({ quarantineReason: "released_instance_present" });
        } else {
          // Even an in-progress teardown must not hide this other contradiction.
          await killSandbox(f.seed.owner, {
            id: sibling.id,
            idempotencyKey: `kill-sibling-${randomUUID()}`,
          });
        }
      }
      await killSandbox(f.seed.owner, {
        id: f.sandbox.id,
        idempotencyKey: `destroy-${randomUUID()}`,
      });
      await processSandboxOutboxBatch(clock);
      const operation = await db.inspect.sandboxOperation.findFirstOrThrow({
        where: { sandboxId: f.sandbox.id, kind: "KILL_SANDBOX" },
      });
      expect(operation.dispatchedHostId).toBe(f.seed.hostId);
      expect(operation.state).toBe("DISPATCHED");
      if (via === "inventory") {
        expect(
          await convergeInventoryEntry(f.sender, {
            sandboxOwnerId: f.sender.userId,
            root: null,
            sandboxId: f.sandbox.id,
            state: "absent",
          }),
        ).toEqual({ converged: true });
      } else
        expect(
          await applyOperationResult({
            sender: f.sender,
            operationId: operation.id,
            sandboxId: f.sandbox.id,
            generation: operation.generation,
            attempt: operation.dispatchAttempt,
            state: "succeeded",
            result: { state: "deleted" },
          }),
        ).toEqual({ written: true });
      expect(await f.row()).toMatchObject({ state: "DELETED", liveResourcesHeld: false });
      expect(await f.host()).toMatchObject({
        liveCount: 0,
        memoryReservedMiB: 0,
        quarantineReason:
          other === "other-quarantine"
            ? "foreign_sandbox"
            : another
              ? "released_instance_present"
              : null,
        ...(another || other === "other-quarantine" ? {} : { quarantinedAt: null }),
      });
      await db.inspect.sandboxTemplateAvailability.updateMany({
        where: { hostId: f.seed.hostId },
        data: { verifiedConnectionEpoch: f.sender.connectionEpoch },
      });
      const create = () =>
        createSandbox(
          f.seed.owner,
          createSandboxInput.parse({
            template: "revision/" + f.seed.templateId,
            sandboxHostId: f.seed.hostId,
            idempotencyKey: `after-retire-${randomUUID()}`,
          }),
        );
      if (another || other === "other-quarantine") await expect(create()).rejects.toThrow();
      else {
        const admitted = await create();
        expect(
          await db.inspect.sandbox.findUniqueOrThrow({ where: { id: admitted.id } }),
        ).toMatchObject({ liveResourcesHeld: true });
      }
    },
  );
});

describe("E3-A-01: a node daemon restart with a running build VM and an in-flight create", () => {
  const features = {
    egressPolicy: true,
    terminal: true,
    image: {
      fetch: true,
      serve: true,
      publish: true,
      capture: true,
      acceptForeign: false,
      leaseFromReady: true,
      captureStorageMarkers: [],
    },
  };
  const rowOf = (id: string) => db.inspect.sandbox.findUniqueOrThrow({ where: { id } });
  const arm = (lease: unknown) => ({
    generation: 1,
    lease,
    expired: false,
    expiryComplete: false,
    timerExpired: false,
  });

  /**
   * A reference-host incident, with the census the real daemon sent afterwards
   * (captured from the node): the build VM is still running, its root
   * unobserved (`root: null`), its READY-settled lease of generation 1; the
   * interrupted create has no VM, only its provisional lease and its retained
   * root bookkeeping (`networkCleanupComplete: false`, sequence 0).
   */
  async function incident(hostDeadlineSkewMs = 0) {
    const seed = await seedHost();
    await db.inspect.sandboxHost.update({
      where: { id: seed.hostId },
      data: { daemonFeatures: features },
    });
    const sender1 = { userId: seed.owner.ownerId, hostId: seed.hostId, connectionEpoch: 1 };
    const launch = async () => {
      const s = await createSandbox(
        seed.owner,
        createSandboxInput.parse({
          template: "revision/" + seed.templateId,
          sandboxHostId: seed.hostId,
          idempotencyKey: `create-${randomUUID()}`,
          timeoutMs: 1_800_000,
          lifecycle: { onTimeout: "kill" },
        }),
      );
      await processSandboxOutboxBatch(clock);
      const op = await db.inspect.sandboxOperation.findFirstOrThrow({
        where: { sandboxId: s.id, kind: "CREATE_SANDBOX" },
      });
      const event = await db.inspect.outboxEvent.findFirstOrThrow({
        where: { aggregateId: s.id, payload: { path: ["operationId"], equals: op.id } },
      });
      const lease = (event.payload as { lease: Record<string, unknown> }).lease;
      expect(lease.fromReadyMs).toBe(1_800_000);
      return { id: s.id, op, lease };
    };
    // The build VM: READY with its READY-settled lease, then killed by the
    // build's cleanup once its interrupted step failed the build.
    const build = await launch();
    const settled = { ...build.lease, deadlineUnixMs: Date.now() + 1_800_000 };
    await applyOperationResult(
      {
        sender: sender1,
        operationId: build.op.id,
        sandboxId: build.id,
        generation: 1,
        attempt: build.op.dispatchAttempt,
        state: "succeeded",
        result: { state: "ready", lease: settled },
      },
      clock,
    );
    // The create in flight when the daemon restarts.
    const create = await launch();
    // The daemon goes down. The build's interrupted step fails the build and
    // its cleanup destroys the build VM (queued: the node is offline).
    await killSandbox(seed.owner, { id: build.id, idempotencyKey: `kill-${randomUUID()}` });
    // The stopping daemon reported the create unknown_outcome.
    await applyOperationResult(
      {
        sender: sender1,
        operationId: create.op.id,
        sandboxId: create.id,
        generation: 1,
        attempt: create.op.dispatchAttempt,
        state: "unknown_outcome",
        error: { code: "unknown_outcome", message: "unknown_outcome" },
      },
      clock,
    );
    for (const id of [build.id, create.id])
      expect(await rowOf(id)).toMatchObject({ state: "STOPPING", generation: 2 });
    const root = async (id: string) => {
      const s = await rowOf(id);
      return {
        storagePoolName: s.storagePoolName,
        storageMarker: s.storageMarker,
        diskGiB: s.diskGiB,
        state: "absent",
        networkCleanupComplete: false,
        observationSequence: 0,
      };
    };
    const entries = [
      {
        sandboxId: build.id,
        sandboxOwnerId: seed.owner.ownerId,
        state: "ready",
        root: null,
        lease: arm({ ...settled, deadlineUnixMs: settled.deadlineUnixMs + hostDeadlineSkewMs }),
      },
      {
        sandboxId: create.id,
        sandboxOwnerId: seed.owner.ownerId,
        state: "absent",
        root: await root(create.id),
        lease: arm(create.lease),
      },
    ].sort((x, y) => (x.sandboxId < y.sandboxId ? -1 : 1));
    return { seed, build, create, entries };
  }

  async function reconnectAndCensus(seed: Seed, entries: unknown[]) {
    const sender = await reconnectHost(seed);
    const census = new InventoryCensus(sender, clock);
    const outcome = await census.acceptPage({
      type: "sandbox.inventory",
      page: 0,
      complete: true,
      entries: entries as never,
    });
    const host = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: seed.hostId } });
    return { sender, census, outcome, host };
  }

  /** After reconciliation the queued destroys reach the host; it reports both gone. */
  async function settleQueuedDestroys(
    sender: Awaited<ReturnType<typeof reconnectHost>>,
    ids: string[],
  ) {
    await processSandboxOutboxBatch(clock);
    for (const sandboxId of ids) {
      const kill = await db.inspect.sandboxOperation.findFirstOrThrow({
        where: { sandboxId, kind: "KILL_SANDBOX", generation: 2 },
      });
      expect(kill.state).toBe("DISPATCHED");
      const applied = await applyOperationResult(
        {
          sender,
          operationId: kill.id,
          sandboxId,
          generation: 2,
          attempt: kill.dispatchAttempt,
          state: "succeeded",
          result: { state: "deleted" },
        },
        clock,
      );
      expect(applied).toEqual({ written: true });
      expect(await rowOf(sandboxId)).toMatchObject({ state: "DELETED" });
    }
  }

  it("the reconnect census completes and both queued destroys settle", async () => {
    const { seed, build, create, entries } = await incident();
    for (let attempt = 0; attempt < 2; attempt++) {
      const { outcome, host, census } = await reconnectAndCensus(seed, entries);
      expect(outcome).toEqual({ ok: true });
      expect(census.contained).toEqual([]);
      expect(host).toMatchObject({ quarantinedAt: null, quarantineReason: null });
    }
    const sender = await reconnectHost(seed);
    await new InventoryCensus(sender, clock).acceptPage({
      type: "sandbox.inventory",
      page: 0,
      complete: true,
      entries: entries as never,
    });
    await settleQueuedDestroys(sender, [build.id, create.id]);
  });

  it("one sandbox's lease disagreement is contained to it: no quarantine, the node reconnects, its destroy settles", async () => {
    // The build VM's host lease disagrees with the server's acknowledged one.
    const { seed, build, create, entries } = await incident(60_000);
    // A prior reconciliation quarantined the node for the same conflict.
    await db.inspect.sandboxHost.update({
      where: { id: seed.hostId },
      data: { quarantinedAt: new Date(), quarantineReason: "lease_mismatch" },
    });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const { sender, outcome, host, census } = await reconnectAndCensus(seed, entries);
    expect(outcome).toEqual({ ok: true });
    expect(census.complete).toBe(true);
    expect(census.contained).toEqual([{ sandboxId: build.id, reason: "lease_mismatch" }]);
    expect(host).toMatchObject({
      quarantinedAt: null,
      quarantineReason: null,
      inventoryAcknowledgedEpoch: sender.connectionEpoch,
    });
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining(`sandbox=${build.id} reason=lease_mismatch`),
    );
    warn.mockRestore();
    // The contained entry concluded nothing about its sandbox.
    expect(await rowOf(build.id)).toMatchObject({ state: "STOPPING", generation: 2 });
    await settleQueuedDestroys(sender, [build.id, create.id]);
  });
});

describe("a deleted sandbox's VM still present: durable, contained remediation", () => {
  type Sender = { userId: string; hostId: string; connectionEpoch: number };
  const rowOf = (id: string) => db.inspect.sandbox.findUniqueOrThrow({ where: { id } });
  const hostOf = (id: string) => db.inspect.sandboxHost.findUniqueOrThrow({ where: { id } });
  const remnantKills = (sandboxId: string) =>
    db.inspect.sandboxOperation.findMany({
      where: { sandboxId, kind: "KILL_SANDBOX", teardownPriorState: "DELETED" },
      orderBy: { generation: "asc" },
      select: { id: true, state: true, generation: true },
    });

  async function reportDestroy(sender: Sender, operationId: string, state: "succeeded" | "failed") {
    const op = await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: operationId } });
    return applyOperationResult(
      {
        sender,
        operationId,
        sandboxId: op.sandboxId,
        generation: op.generation,
        attempt: op.dispatchAttempt,
        state,
        ...(state === "succeeded"
          ? { result: { state: "deleted" } }
          : { error: { code: "internal", message: "destroy failed" } }),
      },
      clock,
    );
  }

  /** A sandbox destroyed normally: DELETED, detached, its charge released. */
  async function deletedSandbox() {
    const seed = await seedHost();
    const sandboxId = await readySandbox(seed);
    const sender = { userId: seed.owner.ownerId, hostId: seed.hostId, connectionEpoch: 1 };
    await killSandbox(seed.owner, { id: sandboxId, idempotencyKey: `kill-${randomUUID()}` });
    await processSandboxOutboxBatch(clock);
    const kill = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId, kind: "KILL_SANDBOX" },
    });
    expect(await reportDestroy(sender, kill.id, "succeeded")).toEqual({ written: true });
    expect((await hostOf(seed.hostId)).liveCount).toBe(0);
    expect(await rowOf(sandboxId)).toMatchObject({
      state: "DELETED",
      sandboxHostId: null,
      liveResourcesHeld: false,
    });
    return { seed, sandboxId, sender };
  }

  async function presentCensus(sender: Sender, sandboxId: string) {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const census = new InventoryCensus(sender, clock);
    const outcome = await census.acceptPage({
      type: "sandbox.inventory",
      page: 0,
      complete: true,
      entries: [{ sandboxId, sandboxOwnerId: sender.userId, state: "stopped" }] as never,
    });
    warn.mockRestore();
    return { outcome, census };
  }

  it("repeated reports keep one charged destroy; the node stays schedulable; the destroy's success releases it", async () => {
    const { seed, sandboxId, sender } = await deletedSandbox();
    const before = await rowOf(sandboxId);
    const placement = await db.inspect.sandboxPlacement.findUniqueOrThrow({
      where: { id: before.currentPlacementId! },
    });
    for (const _report of [1, 2, 3]) {
      const { outcome, census } = await presentCensus(sender, sandboxId);
      expect(outcome).toEqual({ ok: true });
      expect(census.contained).toEqual([{ sandboxId, reason: "deleted_instance_present" }]);
    }
    expect(await hostOf(seed.hostId)).toMatchObject({
      quarantinedAt: null,
      quarantineReason: null,
      liveCount: 1,
      memoryReservedMiB: placement.chargedMemoryMiB,
      vcpuReserved: placement.chargedVcpu,
    });
    expect(await rowOf(sandboxId)).toMatchObject({
      state: "DELETED",
      generation: before.generation + 1,
      sandboxHostId: seed.hostId,
      liveResourcesHeld: true,
    });
    expect(await remnantKills(sandboxId)).toEqual([
      expect.objectContaining({ state: "QUEUED", generation: before.generation + 1 }),
    ]);
    // D5: the remnant writer stores the indexed operationId column.
    const [queued] = await remnantKills(sandboxId);
    expect(
      await db.inspect.outboxEvent.findMany({
        where: { aggregateId: sandboxId, operationId: queued!.id },
        select: { eventType: true },
      }),
    ).toEqual([{ eventType: "sandbox.kill_requested" }]);

    // The destroy dispatches to the node like any kill; its success settles it.
    await processSandboxOutboxBatch(clock);
    const [kill] = await remnantKills(sandboxId);
    expect(kill).toMatchObject({ state: "DISPATCHED" });
    expect(await reportDestroy(sender, kill!.id, "succeeded")).toEqual({ written: true });
    expect(await rowOf(sandboxId)).toMatchObject({
      state: "DELETED",
      sandboxHostId: null,
      liveResourcesHeld: false,
    });
    expect(await hostOf(seed.hostId)).toMatchObject({
      liveCount: 0,
      memoryReservedMiB: 0,
      vcpuReserved: 0,
    });
    expect(await remnantKills(sandboxId)).toEqual([
      expect.objectContaining({ state: "SUCCEEDED" }),
    ]);
  });

  it("concurrent census reports race to one obligation and one charge", async () => {
    const { seed, sandboxId, sender } = await deletedSandbox();
    const results = await Promise.all([
      presentCensus(sender, sandboxId),
      presentCensus(sender, sandboxId),
      presentCensus(sender, sandboxId),
    ]);
    // Serialized on H → S: a census that lost the generation CAS is fenced
    // stale (replayed later), never a second writer.
    const outcomes = results.map((r) => r.outcome);
    expect(outcomes).toContainEqual({ ok: true });
    for (const outcome of outcomes) expect([{ ok: true }, { stale: true }]).toContainEqual(outcome);
    // The replay of a fenced census adds nothing either.
    expect((await presentCensus(sender, sandboxId)).outcome).toEqual({ ok: true });
    expect(await remnantKills(sandboxId)).toEqual([expect.objectContaining({ state: "QUEUED" })]);
    expect((await hostOf(seed.hostId)).liveCount).toBe(1);
    expect(
      await db.inspect.outboxEvent.count({
        where: { aggregateId: sandboxId, eventType: "sandbox.kill_requested", processedAt: null },
      }),
    ).toBe(1);
  });

  it("a failed destroy keeps the charge; the next report re-obligates once; absence releases it", async () => {
    const { seed, sandboxId, sender } = await deletedSandbox();
    await presentCensus(sender, sandboxId);
    await processSandboxOutboxBatch(clock);
    const [first] = await remnantKills(sandboxId);
    expect(await reportDestroy(sender, first!.id, "failed")).toEqual({ written: true });
    // A failure never resurrects the sandbox and releases nothing.
    expect(await rowOf(sandboxId)).toMatchObject({ state: "DELETED", liveResourcesHeld: true });
    expect((await hostOf(seed.hostId)).liveCount).toBe(1);

    await presentCensus(sender, sandboxId);
    await presentCensus(sender, sandboxId);
    expect((await remnantKills(sandboxId)).map((k) => k.state)).toEqual(["FAILED", "QUEUED"]);
    expect((await hostOf(seed.hostId)).liveCount).toBe(1);

    // Silence in a later complete census proves the VM gone.
    expect(
      await new InventoryCensus(sender, clock).acceptPage({
        type: "sandbox.inventory",
        page: 0,
        complete: true,
        entries: [],
      }),
    ).toEqual({ ok: true });
    expect(await rowOf(sandboxId)).toMatchObject({
      state: "DELETED",
      sandboxHostId: null,
      liveResourcesHeld: false,
    });
    expect(await hostOf(seed.hostId)).toMatchObject({ liveCount: 0, memoryReservedMiB: 0 });
    expect((await remnantKills(sandboxId)).map((k) => k.state)).toEqual(["FAILED", "SUCCEEDED"]);
  });

  /** Offload §8.10: the sandbox was restored from host A (its first host,
   * `Sandbox.originHostId`) onto the seed host B, where it was destroyed. */
  async function movedDeletedSandbox() {
    const deleted = await deletedSandbox();
    const first = await seedLaunchHost(db.inspect, {
      data: {
        userId: deleted.sender.userId,
        slug: `first-${randomUUID().slice(0, 8)}`,
        label: "First",
        status: "CONNECTED",
        connectionEpoch: 1,
        egressEnforcement: true,
      },
    });
    await db.inspect.sandbox.update({
      where: { id: deleted.sandboxId },
      data: { originHostId: first.id },
    });
    return { ...deleted, firstHostId: first.id };
  }

  it("§8.10: a DELETED restored sandbox whose VM is on B gets the remnant destroy on B", async () => {
    const { seed, sandboxId, sender, firstHostId } = await movedDeletedSandbox();
    const { outcome, census } = await presentCensus(sender, sandboxId);
    expect(outcome).toEqual({ ok: true });
    expect(census.contained).toEqual([{ sandboxId, reason: "deleted_instance_present" }]);
    expect(await remnantKills(sandboxId)).toEqual([expect.objectContaining({ state: "QUEUED" })]);
    expect(await rowOf(sandboxId)).toMatchObject({ sandboxHostId: seed.hostId });
    // Its first host, where it no longer ran, is never obliged a remnant.
    const first = { userId: sender.userId, hostId: firstHostId, connectionEpoch: 1 };
    const elsewhere = await presentCensus(first, sandboxId);
    expect(elsewhere.census.contained).toEqual([{ sandboxId, reason: "foreign_sandbox" }]);
    expect(await remnantKills(sandboxId)).toHaveLength(1);
  });

  it("§8.10: a transfer accepted on A blocks A's deletion, not B's", async () => {
    const { seed, sandboxId, sender, firstHostId } = await movedDeletedSandbox();
    const { assertHostDeletable } = await import("@wssp/api/sandbox/host-admission");
    const transfer = (acceptedHostId: string) =>
      db.inspect.sandboxTransfer.create({
        data: {
          id: randomUUID(),
          userId: sender.userId,
          sandboxId,
          generation: 1,
          direction: "UPLOAD",
          guestPath: "/tmp/x",
          idempotencyKey: randomUUID(),
          requestBodyHash: "h",
          totalBytes: 1n,
          idleExpiresAt: new Date(Date.now() + 60_000),
          expiresAt: new Date(Date.now() + 60_000),
          acceptedHostId,
        },
      });
    const deletable = (hostId: string) =>
      db.prisma.$transaction((tx) => assertHostDeletable(tx, hostId, sender.userId));
    // Accepted on the seed host (the transport then), origin elsewhere.
    await db.inspect.sandbox.update({
      where: { id: sandboxId },
      data: { originHostId: firstHostId },
    });
    await transfer(seed.hostId);
    await expect(deletable(seed.hostId)).rejects.toMatchObject({ code: "CONFLICT" });
    await expect(deletable(firstHostId)).resolves.toBeUndefined();
  });
});

/** On real PostgreSQL: a cold reconnect installs its new
 * lease before a targeted observation snapshots the still-STOPPED VM; the
 * reconnect's READY result is applied before that queued observation. The
 * session's observation fence answers it superseded: no downgrade, no
 * generation bump, no capacity release. An observation numbered after the
 * one in flight at the result is judged, and (the VM really stopped later)
 * converges STOPPED with the live slot released exactly once. */
describe("WP2 follow-up (real PostgreSQL): the observation fence", () => {
  it("a reconnect result fences current-arm stopped evidence observed before it", async () => {
    const seed = await seedHost();
    const sandboxId = await readySandbox(seed);
    await stopSandbox(seed.owner, { id: sandboxId, idempotencyKey: `stop-${randomUUID()}` });
    await processSandboxOutboxBatch(clock);
    const stop = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId, kind: "STOP_SANDBOX" },
    });
    expect(await reportSucceeded(stop.id, "stopped", 1)).toEqual({ written: true });
    await reconnectSandbox(seed.owner, { id: sandboxId, idempotencyKey: `re-${randomUUID()}` });
    await processSandboxOutboxBatch(clock);
    const reconnect = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId, kind: "RECONNECT_SANDBOX", state: "DISPATCHED" },
    });
    // The daemon admitted the reconnect (its new lease is the current arm)
    // and observation 1 read the VM while it was still stopped.
    const stale = {
      root: await presentRootOf(sandboxId),
      sandboxOwnerId: seed.owner.ownerId,
      sandboxId,
      state: "stopped" as const,
    };
    const fence = new ObservationFence();
    // The reconnect's result reaches the server first.
    fence.noteResult(sandboxId);
    expect(await reportSucceeded(reconnect.id, "ready", 1)).toEqual({ written: true });
    const sender = { userId: seed.owner.ownerId, hostId: seed.hostId, connectionEpoch: 1 };
    const row = () => db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
    const liveCount = async () =>
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: seed.hostId } })).liveCount;
    const before = await row();
    expect(before).toMatchObject({ state: "READY", liveResourcesHeld: true });
    expect(await liveCount()).toBe(1);
    const lease = await hostLeaseOf(sandboxId, false);
    expect(lease.generation).toBe(before.generation);
    // Then the queued observation 1.
    expect(fence.accept(1)).toBe(true);
    expect(
      await judgeExpiryStatus(sender, [{ ...stale, lease }], clock, (id) => fence.predates(id, 1)),
    ).toEqual({ results: [{ sandboxId, outcome: "superseded" }] });
    expect(await row()).toEqual({ ...before, updatedAt: expect.any(Date) });
    expect(await liveCount()).toBe(1);
    // Inverse: the same entry unfenced is exactly the downgrade the fence
    // prevents; observation 2 (begun after the server answered 1) is
    // judged by the census rules: the VM really stopped later.
    expect(fence.accept(2)).toBe(true);
    expect(fence.predates(sandboxId, 2)).toBe(false);
    const later = { ...stale, root: await presentRootOf(sandboxId), lease };
    expect(await judgeExpiryStatus(sender, [later], clock, (id) => fence.predates(id, 2))).toEqual({
      results: [{ sandboxId, outcome: "converged" }],
    });
    expect(await row()).toMatchObject({
      state: "STOPPED",
      generation: before.generation + 1,
      liveResourcesHeld: false,
      diskReservationHeld: true,
    });
    expect(await liveCount()).toBe(0);
    // A replay releases nothing twice.
    expect(
      await judgeExpiryStatus(sender, [later], clock, (id) => fence.predates(id, 2)),
    ).toMatchObject({ results: [{ sandboxId }] });
    expect(await liveCount()).toBe(0);
  });

  /** A daemon that jumps past the fenced observation
   * (2, or MAX_SAFE_INTEGER, as its first batch) is refused before any
   * judgement: the READY row and its capacity stay. */
  it("refuses an observation that jumps past the fenced one", async () => {
    const seed = await seedHost();
    const sandboxId = await readySandbox(seed);
    const sender = { userId: seed.owner.ownerId, hostId: seed.hostId, connectionEpoch: 1 };
    const row = () => db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } });
    const before = await row();
    const stale = {
      root: await presentRootOf(sandboxId),
      sandboxOwnerId: sender.userId,
      sandboxId,
      state: "stopped" as const,
      lease: await hostLeaseOf(sandboxId, false),
    };
    for (const jump of [2, Number.MAX_SAFE_INTEGER]) {
      const fence = new ObservationFence();
      fence.noteResult(sandboxId);
      // The session refuses the frame; nothing is judged.
      expect(fence.accept(jump)).toBe(false);
      expect(fence.predates(sandboxId, 1)).toBe(true);
    }
    // What judging that batch would have done is exactly the downgrade:
    // with the fence intact the first legal observation (1) is superseded.
    const fence = new ObservationFence();
    fence.noteResult(sandboxId);
    expect(fence.accept(1)).toBe(true);
    expect(await judgeExpiryStatus(sender, [stale], clock, (id) => fence.predates(id, 1))).toEqual({
      results: [{ sandboxId, outcome: "superseded" }],
    });
    expect(await row()).toEqual({ ...before, updatedAt: expect.any(Date) });
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: seed.hostId } })).liveCount,
    ).toBe(1);
  });
});
