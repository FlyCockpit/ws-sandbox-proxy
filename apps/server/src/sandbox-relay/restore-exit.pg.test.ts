/**
 * The restore exit on real PostgreSQL: every way a restore
 * attempt ends without READY lands in OFFLOADED with the root, disk and lease
 * fields cleared and the stored copy intact — directly on a no-effect proof,
 * otherwise through the SYSTEM_DETACH kill (result handler or census). A
 * wedged cleanup ends ERROR(restore_cleanup_pending) and the owner's Retry
 * cleanup re-queues the same kill.
 */
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "restore-exit-fixture",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
  consumeImageGrantBudget: async () => {},
}));
vi.mock("../../../../packages/api/src/sandbox/sharing-budgets", () => ({
  consumePoolCapacityRead: async () => {},
  consumeSharingWrite: async () => {},
  consumeInviteAccept: async () => {},
  consumeLeasePreview: async () => {},
  consumeInviteIssue: async () => {},
}));
vi.mock("@wssp/queue", () => ({
  redisConnection: {},
  imageStoreMaintenanceQueue: { add: vi.fn() },
  ensureRunnableJob: vi.fn(),
}));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("./session-manager.js", () => ({
  sandboxRelaySessionManager: {
    isHostConnected: vi.fn().mockReturnValue(true),
    dispatchOperation: vi.fn().mockResolvedValue("sent"),
  },
}));

import { randomBytes, randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const db = await pgTestDatabase();
afterAll(() => db.close());

const { createSandbox, killSandbox, reconnectSandbox, retryRestoreCleanup } = await import(
  "../../../../packages/api/src/sandbox/services/sandboxes"
);
const {
  commitLockedSandboxLeaseExpiry,
  leaseNow,
  reclaimExpiredSandboxLeases,
  TEARDOWN_RETRY_MAX,
} = await import("@wssp/api/sandbox/lease");
const { lockHostForSandboxOperation } = await import("@wssp/api/sandbox/host-admission");
const { acknowledgeFixtureExecutionConfigs } = await import(
  "../../../../packages/api/src/sandbox/testing/resource-fixtures"
);
const { OFFLOAD_HOST_FEATURES, offloadSandboxForTest } = await import(
  "../../../../packages/api/src/sandbox/testing/offload-fixtures"
);
const { allOwnedPoolKey, poolFixture } = await import(
  "../../../../packages/api/src/sandbox/testing/pool-fixtures"
);
const { processSandboxOutboxBatch } = await import("./outbox-processor.js");
const { applyOperationResult, confirmOperationReceipt } = await import("./operation-handlers.js");
const { InventoryCensus, convergeInventoryEntry } = await import("./inventory-reconcile.js");
const { readDiskWrapKeys } = await import("@wssp/api/sandbox/disk-offload/keys");
const { offloadUsageBytes } = await import("@wssp/api/sandbox/disk-offload/quota");
const { handleImageFetchRequest } = await import("./image-handlers.js");
const { transferAuthorized, transferAuthoritySelect } = await import("./image-authority.js");
const { sandboxRelaySessionManager: manager } = await import("./session-manager.js");

const ENV = {
  DATA_ENCRYPTION_KEY: randomBytes(32).toString("hex"),
  IMAGE_S3_BUCKET: "b",
  IMAGE_S3_ENDPOINT: "http://127.0.0.1:9",
  IMAGE_S3_ACCESS_KEY_ID: "a",
  IMAGE_S3_SECRET_ACCESS_KEY: "s",
};
const saved: Record<string, string | undefined> = {};
beforeAll(() => {
  for (const [key, value] of Object.entries(ENV)) {
    saved[key] = process.env[key];
    process.env[key] = value;
  }
});
afterAll(() => {
  for (const [key, value] of Object.entries(saved))
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
});
beforeEach(() => {
  vi.mocked(manager.dispatchOperation).mockReset();
  vi.mocked(manager.dispatchOperation).mockResolvedValue("sent");
});

type Fixture = Awaited<ReturnType<typeof poolFixture>>;
const clock = () => new Date();

async function capable(f: Fixture) {
  for (const host of [f.host, f.other]) {
    await db.inspect.sandboxHost.update({
      where: { id: host.id },
      data: {
        daemonFeatures: { ...OFFLOAD_HOST_FEATURES, egressOpen: true, guestSudo: true },
        daemonDiskOffload: true,
      },
    });
    await db.inspect.sandboxHostStoragePool.updateMany({
      where: { sandboxHostId: host.id },
      data: { newRootsAllowed: true },
    });
  }
}

/** An OFFLOADED sandbox (created on host one) whose restore is placed;
 * `byKey`: the restore is authorized by an ALL_OWNED SDK key. */
async function placedRestore(byKey = false) {
  const f = await poolFixture(db);
  await capable(f);
  const key = byKey ? await allOwnedPoolKey(f) : null;
  const created = await createSandbox(f.owner, {
    template: "base",
    sandboxHostId: f.host.id,
    idempotencyKey: randomUUID(),
  });
  await db.inspect.outboxEvent.updateMany({
    where: { aggregateId: created.id },
    data: { processedAt: new Date() },
  });
  // The create's own holds on host one are not under test: release them as
  // the stop and the detach that preceded the offload would have.
  await db.inspect.sandboxHost.updateMany({
    where: { id: f.host.id },
    data: { liveCount: 0, rootCount: 0, memoryReservedMiB: 0, vcpuReserved: 0 },
  });
  const stored = await db.prisma.$transaction((tx) =>
    offloadSandboxForTest(tx, {
      userId: f.id,
      sandboxId: created.id,
      hostId: f.host.id,
      keys: readDiskWrapKeys() ?? undefined,
    }),
  );
  // The lineage's create ran and its stop proved the VM gone before the
  // offload: no earlier attempt is possibly live.
  await db.inspect.sandboxOperation.updateMany({
    where: { sandboxId: created.id, kind: "CREATE_SANDBOX" },
    data: { state: "SUCCEEDED", completedAt: new Date(), result: { state: "ready" } },
  });
  const accepted = await reconnectSandbox(
    key?.principal ?? f.owner,
    { id: created.id, idempotencyKey: randomUUID() },
    leaseNow,
  );
  await acknowledgeFixtureExecutionConfigs(db.inspect);
  const config = await db.inspect.sandboxExecutionConfig.findFirstOrThrow({
    where: { sandboxId: created.id },
  });
  const target = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: config.hostId } });
  await db.inspect.sandboxExecutionConfig.update({
    where: { id: config.id },
    data: { acknowledgedEpoch: target.connectionEpoch, acknowledgedAt: new Date() },
  });
  return { f, key, sandboxId: created.id, operationId: accepted.operationId, stored, target };
}

type Placed = Awaited<ReturnType<typeof placedRestore>>;

/** Placed and dispatched (attempt 1 on the target's epoch). */
async function dispatchedRestore() {
  const placed = await placedRestore();
  await processSandboxOutboxBatch(clock);
  const op = await db.inspect.sandboxOperation.findUniqueOrThrow({
    where: { id: placed.operationId },
  });
  expect(op).toMatchObject({ state: "DISPATCHED", dispatchAttempt: 1 });
  return placed;
}

async function report(
  operationId: string,
  state: "succeeded" | "failed" | "unknown_outcome",
  extra: { error?: { code: string; message: string; reason?: string }; result?: object } = {},
) {
  const op = await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: operationId } });
  return applyOperationResult(
    {
      sender: {
        userId: (await db.inspect.sandboxHost.findUniqueOrThrow({
          where: { id: op.dispatchedHostId! },
        }))!.userId,
        hostId: op.dispatchedHostId!,
        connectionEpoch: op.dispatchedConnectionEpoch!,
      },
      operationId: op.id,
      sandboxId: op.sandboxId,
      generation: op.generation,
      attempt: op.dispatchAttempt,
      state,
      ...(extra.error ? { error: extra.error as never } : {}),
      ...(extra.result ? { result: extra.result as Record<string, unknown> } : {}),
    },
    clock,
  );
}

/** The SYSTEM_DETACH kill queued for the attempt, dispatched. */
async function detachKillOf(placed: Placed) {
  const sandbox = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: placed.sandboxId } });
  expect(sandbox.state).toBe("STOPPING");
  const kill = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: placed.sandboxId, kind: "KILL_SANDBOX", generation: sandbox.generation },
  });
  const attempt = await db.inspect.sandboxOperation.findUniqueOrThrow({
    where: { id: placed.operationId },
  });
  expect(kill).toMatchObject({
    teardownIntent: "SYSTEM_DETACH",
    attemptOperationId: placed.operationId,
    attemptGeneration: attempt.generation,
  });
  await processSandboxOutboxBatch(clock);
  return db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: kill.id } });
}

/** OFFLOADED with every host, root, disk and lease field cleared; the store copy intact. */
async function expectOffloaded(placed: Placed) {
  const sandbox = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: placed.sandboxId } });
  expect(sandbox).toMatchObject({
    state: "OFFLOADED",
    diskOffloadId: placed.stored.offloadId,
    sandboxHostId: null,
    hostOwnerId: null,
    currentPlacementId: null,
    storagePoolId: null,
    liveResourcesHeld: false,
    diskReservationHeld: false,
    leaseExpiresAt: null,
    leaseExpiresAtRequested: null,
    leaseExpiresAtEffective: null,
  });
  const offload = await db.inspect.sandboxDiskOffload.findUniqueOrThrow({
    where: { id: placed.stored.offloadId },
  });
  expect(offload.state).toBe("STORED");
  expect(offload.wrappedKey).not.toBeNull();
  expect(offload.shreddedAt).toBeNull();
  const target = await db.inspect.sandboxHost.findUniqueOrThrow({
    where: { id: placed.target.id },
  });
  expect(target).toMatchObject({ liveCount: 0, rootCount: 0 });
  // The attempt's fetch transfer never outlives it.
  expect(
    await db.inspect.sandboxImageTransfer.count({
      where: { operationId: placed.operationId, purpose: "RESTORE_FETCH", state: "OPEN" },
    }),
  ).toBe(0);
  return sandbox;
}

/** The target's daemon reconnected (a new epoch): the attempt's event is
 * reopened for the replacement session, the operation still DISPATCHED on
 * the old epoch, so the next claim is a later attempt (attempt 2). */
async function reconnectTarget(placed: Placed) {
  const host = await db.inspect.sandboxHost.update({
    where: { id: placed.target.id },
    data: {
      connectionEpoch: { increment: 1 },
      relayProtocolEpoch: { increment: 1 },
      admissionEpoch: { increment: 1 },
      journalKeyAcknowledgedEpoch: { increment: 1 },
      daemonEgressGuardEpoch: { increment: 1 },
    },
  });
  await db.inspect.sandboxHostStoragePool.updateMany({
    where: { sandboxHostId: host.id },
    data: { connectionEpoch: host.connectionEpoch, reportedAt: new Date() },
  });
  await db.inspect.sandboxExecutionConfig.updateMany({
    where: { sandboxId: placed.sandboxId },
    data: { acknowledgedEpoch: host.connectionEpoch, acknowledgedAt: new Date() },
  });
  await db.inspect.outboxEvent.updateMany({
    where: { aggregateId: placed.sandboxId, processedAt: null },
    data: { sentAt: null, claimToken: null, claimedAt: null },
  });
  return host;
}

/** The attempt ended FAILED with `code` and the sandbox OFFLOADED with no kill. */
async function expectNoEffectExit(placed: Placed, code: string) {
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: placed.operationId } }),
  ).toMatchObject({ state: "FAILED", errorCode: code });
  await expectOffloaded(placed);
  expect(
    await db.inspect.sandboxOperation.count({
      where: { sandboxId: placed.sandboxId, kind: "KILL_SANDBOX" },
    }),
  ).toBe(0);
}

/** A later attempt's refusal: the attempt settled FAILED with its code (never
 * rewritten `superseded`), the SYSTEM_DETACH kill, then OFFLOADED. */
async function expectKillPathExit(placed: Placed, code: string) {
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: placed.operationId } }),
  ).toMatchObject({ state: "FAILED", errorCode: code });
  const kill = await detachKillOf(placed);
  expect((await report(kill.id, "succeeded", { result: { state: "deleted" } })).written).toBe(true);
  await expectOffloaded(placed);
}

/** Make the stored copy unsendable (a zero size), then put it back. */
async function withUnsendableCopy(placed: Placed, work: () => Promise<unknown>) {
  const offload = await db.inspect.sandboxDiskOffload.findUniqueOrThrow({
    where: { id: placed.stored.offloadId },
  });
  await db.inspect.sandboxDiskOffload.update({
    where: { id: offload.id },
    data: { sizeBytes: 0n },
  });
  try {
    await work();
  } finally {
    await db.inspect.sandboxDiskOffload.update({
      where: { id: offload.id },
      data: { sizeBytes: offload.sizeBytes },
    });
  }
}

const offGuard = (placed: Placed) =>
  db.inspect.sandboxHost.update({
    where: { id: placed.target.id },
    data: { daemonEgressGuardOk: false },
  });

const revokeKey = (placed: Placed) =>
  db.inspect.sdkKey.update({
    where: { id: placed.key!.principal.keyId },
    data: { revokedAt: new Date() },
  });

async function census(placed: Placed, kill: { dispatchedConnectionEpoch: number | null }) {
  const s = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: placed.sandboxId } });
  const sender = {
    userId: placed.target.userId,
    hostId: placed.target.id,
    connectionEpoch: kill.dispatchedConnectionEpoch!,
  };
  const accepted = await new InventoryCensus(sender, clock).acceptPage({
    type: "sandbox.inventory",
    page: 0,
    complete: true,
    entries: [
      {
        sandboxId: s.id,
        sandboxOwnerId: s.userId,
        state: "absent",
        root: {
          storagePoolName: s.storagePoolName,
          storageMarker: s.storageMarker,
          diskGiB: s.diskGiB,
          state: "absent",
          networkCleanupComplete: true,
          observationSequence: 100,
        },
      },
    ] as never,
  });
  expect(accepted).toEqual({ ok: true });
}

describe("restore exits end OFFLOADED (§8.7)", () => {
  for (const [label, state, error] of [
    ["fetch FAILED", "failed", { code: "image_unavailable", message: "fetch" }],
    ["validate FAILED", "failed", { code: "image_corrupt", message: "validate" }],
    ["import FAILED", "failed", { code: "image_rejected", message: "import" }],
    ["unknown_outcome", "unknown_outcome", { code: "unknown_outcome", message: "lost" }],
  ] as const)
    it(`${label} → SYSTEM_DETACH kill → OFFLOADED`, async () => {
      const placed = await dispatchedRestore();
      expect((await report(placed.operationId, state, { error })).written).toBe(true);
      const kill = await detachKillOf(placed);
      expect((await report(kill.id, "succeeded", { result: { state: "deleted" } })).written).toBe(
        true,
      );
      await expectOffloaded(placed);
    });

  it("readiness failure → restore_boot_failed, kill, OFFLOADED", async () => {
    const placed = await dispatchedRestore();
    await report(placed.operationId, "failed", {
      error: { code: "guest_unavailable", message: "boot", reason: "agent" },
    });
    const kill = await detachKillOf(placed);
    await report(kill.id, "succeeded", { result: { state: "deleted" } });
    const sandbox = await expectOffloaded(placed);
    expect(sandbox.lastErrorCode).toBe("restore_boot_failed");
    expect(
      (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: placed.operationId } }))
        .state,
    ).toBe("FAILED");
  });

  it("expiry past the deadline with leaseExpireAction DESTROY → SYSTEM_DETACH, never DELETED (T3)", async () => {
    const placed = await dispatchedRestore();
    await db.inspect.sandbox.update({
      where: { id: placed.sandboxId },
      data: { leaseExpireAction: "DESTROY", leaseExpiresAt: new Date(Date.now() - 60_000) },
    });
    await report(placed.operationId, "unknown_outcome", {
      error: { code: "unknown_outcome", message: "lost" },
    });
    const kill = await detachKillOf(placed);
    await report(kill.id, "succeeded", { result: { state: "deleted" } });
    await expectOffloaded(placed);
  });

  it("an expired, never-dispatched restore reverts server-side with no teardown (M4, T6)", async () => {
    const placed = await placedRestore();
    await db.inspect.sandbox.update({
      where: { id: placed.sandboxId },
      data: { leaseExpiresAt: new Date(Date.now() - 60_000) },
    });
    expect(await reclaimExpiredSandboxLeases(clock)).toBe(0);
    await expectOffloaded(placed);
    expect(
      await db.inspect.sandboxOperation.count({
        where: { sandboxId: placed.sandboxId, kind: "KILL_SANDBOX" },
      }),
    ).toBe(0);
    expect(
      (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: placed.operationId } }))
        .state,
    ).toBe("FAILED");
  });

  it("a census-settled SYSTEM_DETACH kill → OFFLOADED (M2)", async () => {
    const placed = await dispatchedRestore();
    await report(placed.operationId, "failed", {
      error: { code: "image_unavailable", message: "fetch" },
    });
    const kill = await detachKillOf(placed);
    await census(placed, kill);
    await expectOffloaded(placed);
    expect(
      (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: kill.id } })).state,
    ).toBe("SUCCEEDED");
  });

  it("a teardown retry inherits the intent; past the retries ERROR(restore_cleanup_pending); Retry cleanup re-queues (M1, U10)", async () => {
    const placed = await dispatchedRestore();
    await report(placed.operationId, "failed", {
      error: { code: "image_unavailable", message: "fetch" },
    });
    const attempt = await db.inspect.sandboxOperation.findUniqueOrThrow({
      where: { id: placed.operationId },
    });
    let kill = await detachKillOf(placed);
    for (let retry = 1; retry <= TEARDOWN_RETRY_MAX; retry += 1) {
      await report(kill.id, "failed", { error: { code: "internal", message: "stuck" } });
      // The retry is again a SYSTEM_DETACH kill of the same attempt.
      kill = await detachKillOf(placed);
      expect(kill.idempotencyKey).toMatch(/^teardown-retry:/);
    }
    await report(kill.id, "failed", { error: { code: "internal", message: "stuck" } });
    const wedged = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: placed.sandboxId } });
    expect(wedged).toMatchObject({
      state: "ERROR",
      lastErrorCode: "restore_cleanup_pending",
      diskOffloadId: placed.stored.offloadId,
      liveResourcesHeld: true,
    });
    await retryRestoreCleanup(placed.f.owner, { id: placed.sandboxId });
    kill = await detachKillOf(placed);
    expect(kill).toMatchObject({
      attemptOperationId: attempt.id,
      attemptGeneration: attempt.generation,
    });
    await report(kill.id, "succeeded", { result: { state: "deleted" } });
    await expectOffloaded(placed);
  });

  it("Retry cleanup refuses a sandbox that is not ERROR(restore_cleanup_pending)", async () => {
    const placed = await placedRestore();
    await expect(retryRestoreCleanup(placed.f.owner, { id: placed.sandboxId })).rejects.toThrow();
  });
});

/** The restore's READY result, echoing the dispatched lease like a daemon. */
async function reportReady(operationId: string) {
  const op = await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: operationId } });
  const event = await db.inspect.outboxEvent.findFirstOrThrow({
    where: { aggregateId: op.sandboxId, payload: { path: ["operationId"], equals: op.id } },
  });
  const payload = event.payload as Record<string, unknown>;
  return report(operationId, "succeeded", {
    result: { state: "ready", ...(payload.lease ? { lease: payload.lease } : {}) },
  });
}

async function setGrace(value: string | null) {
  const key = "sandbox.offload.consumedGraceSeconds";
  if (value === null) await db.inspect.appSetting.deleteMany({ where: { key } });
  else
    await db.inspect.appSetting.upsert({
      where: { key },
      create: { key, value },
      update: { value },
    });
}

describe("READY consumes the stored copy (§8.8, §6a)", () => {
  for (const [label, value, seconds] of [
    ["default", null, 3600],
    ["0", "0", 0],
    ["the maximum", "604800", 604_800],
  ] as const)
    it(`writes deleteAfter from the setting (${label})`, async () => {
      await setGrace(value);
      try {
        const placed = await dispatchedRestore();
        const before = Date.now();
        expect((await reportReady(placed.operationId)).written).toBe(true);
        const sandbox = await db.inspect.sandbox.findUniqueOrThrow({
          where: { id: placed.sandboxId },
        });
        expect(sandbox).toMatchObject({
          state: "READY",
          diskOffloadId: null,
          cachedOffloadSeq: null,
          diskBaseFingerprint: `sha256:${"d".repeat(64)}`,
        });
        const offload = await db.inspect.sandboxDiskOffload.findUniqueOrThrow({
          where: { id: placed.stored.offloadId },
        });
        expect(offload).toMatchObject({ state: "CONSUMED", liveSandboxId: null });
        const delta = offload.deleteAfter!.getTime() - offload.consumedAt!.getTime();
        expect(delta).toBe(seconds * 1000);
        expect(offload.consumedAt!.getTime()).toBeGreaterThanOrEqual(before - 5_000);
      } finally {
        await setGrace(null);
      }
    });

  it("a CONSUMED copy is refused by the fetch grant and never counted toward quota", async () => {
    const placed = await dispatchedRestore();
    const sender = {
      hostId: placed.target.id,
      userId: placed.target.userId,
      connectionEpoch: placed.target.connectionEpoch,
    };
    const replies: Record<string, unknown>[] = [];
    const ctx = {
      sender,
      reply: (frame: Record<string, unknown>) => replies.push(frame),
      sendTo: () => false,
      isHostCurrent: () => true,
      spool: {} as never,
    };
    const op = await db.inspect.sandboxOperation.findUniqueOrThrow({
      where: { id: placed.operationId },
    });
    const request = () =>
      handleImageFetchRequest(ctx as never, {
        type: "image.fetch.request",
        requestId: randomUUID(),
        operationId: op.id,
        sandboxId: placed.sandboxId,
        generation: op.generation,
        attempt: op.dispatchAttempt,
        fingerprint: `sha256:${"d".repeat(64)}`,
        resumeOffset: 0,
      });
    await request();
    expect(replies.pop()).toMatchObject({ type: "image.fetch.grant" });
    const usageBefore = await db.prisma.$transaction((tx) => offloadUsageBytes(tx, placed.f.id));
    expect(usageBefore).toBeGreaterThan(0n);
    await reportReady(placed.operationId);
    const transfer = await db.inspect.sandboxImageTransfer.findFirstOrThrow({
      where: { operationId: op.id, purpose: "RESTORE_FETCH" },
      select: { id: true, state: true, ...transferAuthoritySelect },
    });
    // READY completes the fetch transfer; its authority is gone with the copy.
    expect(transfer.state).toBe("COMPLETE");
    expect(await db.prisma.$transaction((tx) => transferAuthorized(tx, transfer, new Date()))).toBe(
      false,
    );
    await request();
    expect(replies.pop()).toMatchObject({ type: "image.fetch.refused" });
    expect(await db.prisma.$transaction((tx) => offloadUsageBytes(tx, placed.f.id))).toBe(0n);
  });
});

describe("restore races (§11, S2/M1)", () => {
  it("owner kill × restore → DELETED through endOffloadForDestroy (OWNER_DESTROY)", async () => {
    const placed = await dispatchedRestore();
    await killSandbox(placed.f.owner, { id: placed.sandboxId, idempotencyKey: randomUUID() });
    const sandbox = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: placed.sandboxId } });
    const kill = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: placed.sandboxId, kind: "KILL_SANDBOX", generation: sandbox.generation },
    });
    expect(kill.teardownIntent).toBe("OWNER_DESTROY");
    await processSandboxOutboxBatch(clock);
    await report(kill.id, "succeeded", { result: { state: "deleted" } });
    expect(
      await db.inspect.sandbox.findUniqueOrThrow({ where: { id: placed.sandboxId } }),
    ).toMatchObject({ state: "DELETED", diskOffloadId: null, liveResourcesHeld: false });
    expect(
      await db.inspect.sandboxDiskOffload.findUniqueOrThrow({
        where: { id: placed.stored.offloadId },
      }),
    ).toMatchObject({ state: "DELETING", destroyOperationId: kill.id });
  });

  it("access destroy of ERROR(restore_cleanup_pending) is a SYSTEM_DETACH kill → OFFLOADED", async () => {
    const placed = await dispatchedRestore();
    await report(placed.operationId, "failed", {
      error: { code: "image_unavailable", message: "fetch" },
    });
    let kill = await detachKillOf(placed);
    for (let retry = 0; retry <= TEARDOWN_RETRY_MAX; retry += 1) {
      await report(kill.id, "failed", { error: { code: "internal", message: "stuck" } });
      if (retry < TEARDOWN_RETRY_MAX) kill = await detachKillOf(placed);
    }
    const wedged = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: placed.sandboxId } });
    expect(wedged).toMatchObject({ state: "ERROR", lastErrorCode: "restore_cleanup_pending" });
    // The access-loss deadline passed: the access writer queues the destroy.
    await db.inspect.sandbox.update({
      where: { id: wedged.id },
      data: { accessGraceUntil: new Date(Date.now() - 60_000), accessGraceReason: "access" },
    });
    const queued = await db.prisma.$transaction(async (tx) => {
      await lockHostForSandboxOperation(tx, wedged.sandboxHostId, wedged.userId, wedged.id);
      await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${wedged.id} FOR NO KEY UPDATE`;
      const row = await tx.sandbox.findUniqueOrThrow({ where: { id: wedged.id } });
      return commitLockedSandboxLeaseExpiry(tx, row, new Date(), false, "access");
    });
    expect(queued).toBe(true);
    const stopping = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: wedged.id } });
    const access = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: wedged.id, kind: "KILL_SANDBOX", generation: stopping.generation },
    });
    // Forced SYSTEM_DETACH, never an owner destroy (T16).
    expect(access.teardownIntent).toBe("SYSTEM_DETACH");
    await processSandboxOutboxBatch(clock);
    kill = await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: access.id } });
    await report(kill.id, "succeeded", { result: { state: "deleted" } });
    await expectOffloaded(placed);
  });
});

/** The exact receipt of `operationId`, re-sent by `host` after the server
 * row is terminal (a reconnect's receipt replay). */
async function confirmFrom(
  operationId: string,
  host: { id: string; userId: string; connectionEpoch: number },
  kind: string,
) {
  const op = await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: operationId } });
  return confirmOperationReceipt({
    sender: { userId: host.userId, hostId: host.id, connectionEpoch: host.connectionEpoch },
    operationId: op.id,
    sandboxId: op.sandboxId,
    generation: op.generation,
    attempt: op.dispatchAttempt,
    written: false,
    state: "succeeded",
    receipt: { bodyHash: op.requestBodyHash!, idempotencyKey: op.idempotencyKey!, kind },
  });
}

describe("receipt confirmation of a hostless sandbox (§8.10 retained placement)", () => {
  it("the SYSTEM_DETACH kill is confirmed to the host that ran it, never another; a same-host retry dispatches", async () => {
    const placed = await dispatchedRestore();
    await report(placed.operationId, "failed", {
      error: { code: "image_unavailable", message: "fetch" },
    });
    const kill = await detachKillOf(placed);
    expect((await report(kill.id, "succeeded", { result: { state: "deleted" } })).written).toBe(
      true,
    );
    await expectOffloaded(placed);
    const target = await db.inspect.sandboxHost.findUniqueOrThrow({
      where: { id: placed.target.id },
    });
    const other = await db.inspect.sandboxHost.findUniqueOrThrow({
      where: { id: placed.target.id === placed.f.host.id ? placed.f.other.id : placed.f.host.id },
    });
    // Another host of the same owner never confirms it: not its dispatch,
    // not its placement.
    expect(await confirmFrom(kill.id, other, "sandbox.kill")).toBeNull();
    // A forged binding (another kind) stays refused on the right host.
    expect(await confirmFrom(kill.id, target, "sandbox.stop")).toBeNull();
    expect(await confirmFrom(kill.id, target, "sandbox.kill")).toMatchObject({
      type: "receipt.confirmed",
      operationId: kill.id,
      sandboxId: placed.sandboxId,
    });
    // The failed attempt itself (the same retained placement) also confirms.
    expect(await confirmFrom(placed.operationId, target, "sandbox.reconnect")).toMatchObject({
      type: "receipt.confirmed",
      operationId: placed.operationId,
    });
    expect(await confirmFrom(placed.operationId, other, "sandbox.reconnect")).toBeNull();
    // A placement on another host at or below the operation's generation is
    // no evidence for this host: move the attempt's placement off it.
    const placement = await db.inspect.sandboxPlacement.findUniqueOrThrow({
      where: { operationId: placed.operationId },
    });
    await db.inspect.sandboxPlacement.update({
      where: { id: placement.id },
      data: { originHostId: other.id },
    });
    expect(await confirmFrom(kill.id, target, "sandbox.kill")).toBeNull();
    await db.inspect.sandboxPlacement.update({
      where: { id: placement.id },
      data: { originHostId: placement.originHostId },
    });
    // The retry is admitted and dispatched (its config install on the same
    // host is the daemon's watermark rule, tested there).
    vi.mocked(manager.dispatchOperation).mockClear();
    const retry = await reconnectSandbox(
      placed.f.owner,
      { id: placed.sandboxId, idempotencyKey: randomUUID() },
      leaseNow,
    );
    await acknowledgeFixtureExecutionConfigs(db.inspect);
    const retryOp = await db.inspect.sandboxOperation.findUniqueOrThrow({
      where: { id: retry.operationId },
    });
    const config = await db.inspect.sandboxExecutionConfig.findFirstOrThrow({
      where: { sandboxId: placed.sandboxId, generation: retryOp.generation },
    });
    const host = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: config.hostId } });
    await db.inspect.sandboxExecutionConfig.update({
      where: { id: config.id },
      data: { acknowledgedEpoch: host.connectionEpoch, acknowledgedAt: new Date() },
    });
    await processSandboxOutboxBatch(clock);
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: retry.operationId } }),
    ).toMatchObject({ state: "DISPATCHED" });
    // Once the sandbox has a current host again, the ordinary current-host
    // fence applies: the old kill still confirms only on that host.
    if (host.id === target.id)
      expect(await confirmFrom(kill.id, target, "sandbox.kill")).toMatchObject({
        type: "receipt.confirmed",
      });
    expect(await confirmFrom(kill.id, other, "sandbox.kill")).toBeNull();
  });

  it("a still-active operation of a hostless sandbox is never confirmed", async () => {
    const placed = await dispatchedRestore();
    await report(placed.operationId, "failed", {
      error: { code: "image_unavailable", message: "fetch" },
    });
    const kill = await detachKillOf(placed);
    await report(kill.id, "succeeded", { result: { state: "deleted" } });
    await expectOffloaded(placed);
    // The same row, were it still active: no retained-evidence confirmation.
    await db.inspect.sandboxOperation.update({
      where: { id: kill.id },
      data: { state: "DISPATCHED", completedAt: null },
    });
    const target = await db.inspect.sandboxHost.findUniqueOrThrow({
      where: { id: placed.target.id },
    });
    expect(await confirmFrom(kill.id, target, "sandbox.kill")).toBeNull();
  });
});

describe("outbox and census restore exits (§8.7 X1, U3)", () => {
  it("outbox egress refusal at attempt 0 → no-effect detach → OFFLOADED", async () => {
    const placed = await placedRestore();
    await offGuard(placed);
    await processSandboxOutboxBatch(clock);
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
    await expectNoEffectExit(placed, "egress_guard_unavailable");
  });

  it("outbox egress refusal at a later attempt → SYSTEM_DETACH kill → OFFLOADED", async () => {
    const placed = await dispatchedRestore();
    await reconnectTarget(placed);
    await offGuard(placed);
    vi.mocked(manager.dispatchOperation).mockClear();
    await processSandboxOutboxBatch(clock);
    await expectKillPathExit(placed, "egress_guard_unavailable");
  });

  it("outbox protocol refusal at attempt 0 → no-effect detach → OFFLOADED", async () => {
    const placed = await placedRestore();
    await withUnsendableCopy(placed, () => processSandboxOutboxBatch(clock));
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
    await expectNoEffectExit(placed, "protocol_error");
  });

  it("outbox protocol refusal at a later attempt → SYSTEM_DETACH kill → OFFLOADED", async () => {
    const placed = await dispatchedRestore();
    await reconnectTarget(placed);
    vi.mocked(manager.dispatchOperation).mockClear();
    await withUnsendableCopy(placed, () => processSandboxOutboxBatch(clock));
    await expectKillPathExit(placed, "protocol_error");
  });

  it("credential refusal (revoked restoring key) at attempt 0 → no-effect detach → OFFLOADED", async () => {
    const placed = await placedRestore(true);
    await revokeKey(placed);
    await processSandboxOutboxBatch(clock);
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
    await expectNoEffectExit(placed, "credential_inactive");
  });

  it("credential refusal at a later attempt → SYSTEM_DETACH kill → OFFLOADED", async () => {
    const placed = await placedRestore(true);
    await processSandboxOutboxBatch(clock);
    await reconnectTarget(placed);
    await revokeKey(placed);
    vi.mocked(manager.dispatchOperation).mockClear();
    await processSandboxOutboxBatch(clock);
    await expectKillPathExit(placed, "credential_inactive");
  });

  it("census unissued / init not_issued with root absent → no-effect detach → OFFLOADED (U3)", async () => {
    const journalId = "a".repeat(32);
    const placed = await placedRestore();
    await db.inspect.sandboxHost.update({
      where: { id: placed.target.id },
      data: { daemonFeatures: { ...OFFLOAD_HOST_FEATURES, egressOpen: true, journalId } },
    });
    await processSandboxOutboxBatch(clock);
    // The attempt's result was lost with its session: UNKNOWN on the old epoch.
    await db.inspect.sandboxOperation.update({
      where: { id: placed.operationId },
      data: { state: "UNKNOWN_OUTCOME", errorCode: "unknown_outcome", completedAt: new Date() },
    });
    const host = await reconnectTarget(placed);
    const sandbox = await db.inspect.sandbox.findUniqueOrThrow({
      where: { id: placed.sandboxId },
    });
    expect(sandbox).toMatchObject({ state: "PROVISIONING", liveResourcesHeld: true });
    const sender = {
      userId: placed.target.userId,
      hostId: placed.target.id,
      connectionEpoch: host.connectionEpoch,
    };
    const proof = {
      connectionEpoch: host.connectionEpoch,
      barrier: 10,
      journalId,
      root: {
        storagePoolName: sandbox.storagePoolName!,
        storageMarker: sandbox.storageMarker!,
        diskGiB: sandbox.diskGiB,
      },
    };
    const entry = {
      sandboxId: sandbox.id,
      sandboxOwnerId: sandbox.userId,
      state: "absent" as const,
      root: null,
    };
    // A root proof naming another root never settles it.
    expect(
      await convergeInventoryEntry(sender, entry, clock, {
        ...proof,
        root: { ...proof.root, storageMarker: "other-marker" },
      }),
    ).toEqual({ converged: false });
    expect(await convergeInventoryEntry(sender, entry, clock, proof)).toEqual({ converged: true });
    await expectNoEffectExit(placed, "host_effect_not_issued");
  });

  it("an init refusal reported FAILED by the daemon still takes the kill path (no root proof in a result)", async () => {
    const placed = await dispatchedRestore();
    await report(placed.operationId, "failed", {
      error: { code: "host_effect_not_issued", message: "init refused" },
    });
    const kill = await detachKillOf(placed);
    await report(kill.id, "succeeded", { result: { state: "deleted" } });
    await expectOffloaded(placed);
  });
});
