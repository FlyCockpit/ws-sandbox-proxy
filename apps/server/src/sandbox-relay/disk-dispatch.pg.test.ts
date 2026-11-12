/**
 * Restore dispatch on real PostgreSQL: a restore admitted by the reconnect
 * service (`acceptRestore` → `placeRestore`) goes out through the outbox as
 * `sandbox.reconnect` + `restore` + `launchMode: new_root` + the stored
 * disk's `fetch` image, with `diskBaseFingerprint` and the template binding,
 * all derived from rows; the retained-storage gate holds it like a create;
 * and a capability downgrade at dispatch refuses it `unsupported_capability`.
 * The field builder's refusals are unit cells (`disk-dispatch.test.ts`).
 */
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "disk-dispatch-fixture",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
  consumeImageGrantBudget: async () => {},
}));
// Presigning is the only store call a fetch grant makes.
vi.mock("@wssp/api/sandbox/image-store/s3", async (importOriginal) => {
  const real = await importOriginal<typeof import("@wssp/api/sandbox/image-store/s3")>();
  const store = {
    settings: { presignTtlSeconds: 600 },
    presignGet: async (key: string) => `http://127.0.0.1:9/${key}?signed`,
  };
  return { ...real, imageStore: () => store };
});
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
// No sockets: the session manager's verdict is scripted per test; every
// durable transition is real SQL.
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

const { createSandbox, reconnectSandbox } = await import(
  "../../../../packages/api/src/sandbox/services/sandboxes"
);
const { leaseNow } = await import("@wssp/api/sandbox/lease");
const { acknowledgeFixtureExecutionConfigs } = await import(
  "../../../../packages/api/src/sandbox/testing/resource-fixtures"
);
const { OFFLOAD_HOST_FEATURES, offloadSandboxForTest } = await import(
  "../../../../packages/api/src/sandbox/testing/offload-fixtures"
);
const { poolFixture } = await import("../../../../packages/api/src/sandbox/testing/pool-fixtures");
const { processSandboxOutboxBatch } = await import("./outbox-processor.js");
const { handleImageFetchRequest } = await import("./image-handlers.js");
const { transferAuthorized, transferAuthoritySelect } = await import("./image-authority.js");
const { loadDiskObjectKey, readDiskWrapKeys } = await import("@wssp/api/sandbox/disk-offload/keys");
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

/** Both fixture hosts offload-capable, with room for new roots. */
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

/** An OFFLOADED sandbox (created on host one) whose restore is placed. */
async function placedRestore() {
  const f = await poolFixture(db);
  await capable(f);
  const created = await createSandbox(f.owner, {
    template: "base",
    sandboxHostId: f.host.id,
    idempotencyKey: randomUUID(),
  });
  // The create's own outbox event is not under test here.
  await db.inspect.outboxEvent.updateMany({
    where: { aggregateId: created.id },
    data: { processedAt: new Date() },
  });
  const stored = await db.prisma.$transaction((tx) =>
    offloadSandboxForTest(tx, {
      userId: f.id,
      sandboxId: created.id,
      hostId: f.host.id,
      keys: readDiskWrapKeys() ?? undefined,
    }),
  );
  await db.inspect.sandbox.update({
    where: { id: created.id },
    data: { cloudInitInstanceId: "iid-restored-1" },
  });
  const accepted = await reconnectSandbox(
    f.owner,
    { id: created.id, idempotencyKey: randomUUID() },
    leaseNow,
  );
  const operation = await db.inspect.sandboxOperation.findUniqueOrThrow({
    where: { id: accepted.operationId },
  });
  expect(operation).toMatchObject({ launchMode: "NEW_ROOT", restoreOffloadId: stored.offloadId });
  await acknowledgeFixtureExecutionConfigs(db.inspect);
  // The rebound config is acknowledged on the target's current epoch.
  const config = await db.inspect.sandboxExecutionConfig.findFirstOrThrow({
    where: { sandboxId: created.id },
  });
  const target = await db.inspect.sandboxHost.findUniqueOrThrow({
    where: { id: config.hostId },
  });
  await db.inspect.sandboxExecutionConfig.update({
    where: { id: config.id },
    data: { acknowledgedEpoch: target.connectionEpoch, acknowledgedAt: new Date() },
  });
  return { f, sandboxId: created.id, operationId: accepted.operationId, stored, target };
}

const restoreCalls = (operationId: string) =>
  vi
    .mocked(manager.dispatchOperation)
    .mock.calls.filter(([, input]) => input.operationId === operationId)
    .map(([, input]) => input);

describe("restore dispatch (§7, U9.1)", () => {
  it("sends sandbox.reconnect + restore + new_root + the disk's fetch image, from rows", async () => {
    const { sandboxId, operationId, stored, target } = await placedRestore();
    await processSandboxOutboxBatch(() => new Date());
    const [frame] = restoreCalls(operationId);
    expect(frame).toBeDefined();
    const disk = `sha256:${"d".repeat(64)}`;
    const placement = await db.inspect.sandboxPlacement.findFirstOrThrow({
      where: { operationId },
    });
    expect(frame).toMatchObject({
      kind: "sandbox.reconnect",
      sandboxId,
      restore: {
        offloadId: stored.offloadId,
        seq: 1,
        fingerprint: disk,
        cloudInitInstanceId: "iid-restored-1",
      },
      launchMode: "new_root",
      image: { fingerprint: disk, sizeBytes: 1024, format: "unified", source: "fetch" },
      diskBaseFingerprint: disk,
      // The template binding stays the template's digest.
      templateDigest: placement.artifact,
      incusFingerprint: placement.artifact,
    });
    expect(frame?.expectDisk).toBeUndefined();
    expect(
      (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: operationId } }))
        .dispatchedHostId,
    ).toBe(target.id);
  });

  it("the retained-storage gate holds a restore like a create (no new roots → not sent)", async () => {
    const { operationId, target } = await placedRestore();
    await db.inspect.sandboxHostStoragePool.updateMany({
      where: { sandboxHostId: target.id },
      data: { newRootsAllowed: false },
    });
    await processSandboxOutboxBatch(() => new Date());
    expect(restoreCalls(operationId)).toHaveLength(0);
    expect(
      (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: operationId } })).state,
    ).toBe("QUEUED");
  });

  it("a capability downgrade at dispatch refuses the restore unsupported_capability (U9.2)", async () => {
    const { operationId, target } = await placedRestore();
    // The host reconnected as a daemon without `diskOffload` on this epoch;
    // the session refuses the disk fields before any frame.
    await db.inspect.sandboxHost.update({
      where: { id: target.id },
      data: { daemonDiskOffload: false, admissionEpoch: target.connectionEpoch },
    });
    vi.mocked(manager.dispatchOperation).mockResolvedValue("refused_before_frame");
    await processSandboxOutboxBatch(() => new Date());
    expect(restoreCalls(operationId)).toHaveLength(1);
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: operationId } }),
    ).toMatchObject({ state: "FAILED", errorCode: "unsupported_capability" });
    // §8.7: the no-effect proof detaches it straight back to OFFLOADED, its
    // target released and its stored copy kept; no kill is sent.
    const { sandboxId, stored } = await db.inspect.sandboxOperation
      .findUniqueOrThrow({ where: { id: operationId } })
      .then(async (op) => ({
        sandboxId: op.sandboxId,
        stored: await db.inspect.sandboxDiskOffload.findFirstOrThrow({
          where: { sandboxId: op.sandboxId },
        }),
      }));
    expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } })).toMatchObject({
      state: "OFFLOADED",
      diskOffloadId: stored.id,
      sandboxHostId: null,
      liveResourcesHeld: false,
      diskReservationHeld: false,
    });
    expect(stored.state).toBe("STORED");
    expect(
      await db.inspect.sandboxOperation.count({ where: { sandboxId, kind: "KILL_SANDBOX" } }),
    ).toBe(0);
  });

  it("the RESTORE_FETCH grant: keyed on the offload, its own DEK, re-checked eligibility (T8)", async () => {
    const { f, sandboxId, operationId, stored, target } = await placedRestore();
    await processSandboxOutboxBatch(() => new Date());
    const disk = `sha256:${"d".repeat(64)}`;
    const sender = {
      hostId: target.id,
      userId: target.userId,
      connectionEpoch: target.connectionEpoch,
    };
    const replies: Record<string, unknown>[] = [];
    const ctx = {
      sender,
      reply: (frame: Record<string, unknown>) => replies.push(frame),
      sendTo: () => false,
      isHostCurrent: () => true,
      spool: {} as never,
    };
    const request = async (fingerprint = disk) =>
      handleImageFetchRequest(ctx as never, {
        type: "image.fetch.request",
        requestId: randomUUID(),
        operationId,
        sandboxId,
        generation: (await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandboxId } }))
          .generation,
        attempt: 1,
        fingerprint,
        resumeOffset: 0,
      });
    // A template-looking fingerprint never reaches the disk.
    await request(`sha256:${"e".repeat(64)}`);
    expect(replies.pop()).toMatchObject({ type: "image.fetch.refused", code: "stale_operation" });
    await request();
    const grant = replies.pop();
    const key = (
      await db.prisma.$transaction((tx) => loadDiskObjectKey(tx, stored.offloadId))
    ).toString("base64");
    expect(grant).toMatchObject({
      type: "image.fetch.grant",
      mode: "S3",
      sizeBytes: 1024,
      encryption: { scheme: "aes256gcm-r1", key },
    });
    const transfer = await db.inspect.sandboxImageTransfer.findFirstOrThrow({
      where: { operationId, purpose: "RESTORE_FETCH" },
      select: { id: true, ...transferAuthoritySelect },
    });
    expect(transfer).toMatchObject({ diskOffloadId: stored.offloadId, destHostId: target.id });
    // Restore bytes never count against the download budget.
    expect(
      (await db.inspect.sandboxImageTransfer.findUniqueOrThrow({ where: { id: transfer.id } }))
        .countedDownload,
    ).toBe(false);
    const authorized = () =>
      db.prisma.$transaction((tx) => transferAuthorized(tx, transfer, new Date()));
    expect(await authorized()).toBe(true);
    // The host stops being restore-eligible (draining): renewals and new
    // grants are refused.
    await db.inspect.sandboxHost.update({ where: { id: target.id }, data: { draining: true } });
    expect(await authorized()).toBe(false);
    await request();
    expect(replies.pop()).toMatchObject({ type: "image.fetch.refused", code: "stale_operation" });
    expect(f.id).toBeDefined();
  });
});
