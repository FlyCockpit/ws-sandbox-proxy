import { seedLaunchHost } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, afterEach, expect, it, vi } from "vitest";
import { seedTemplateRevision } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
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
    dispatchOperation: vi.fn().mockResolvedValue("sent"),
    captureHostDispatchCredential: vi.fn(),
    installExecutionConfig: vi.fn().mockResolvedValue(true),
  },
}));
const { sandboxRelaySessionManager: manager } = await import("./session-manager.js");
const { processSandboxOutboxBatch } = await import("./outbox-processor.js");
const { acknowledgeExecutionConfig } = await import("./execution-config-ack.js");
const db = await pgTestDatabase();
const { createSandbox } = await import("../../../../packages/api/src/sandbox/services/sandboxes");
const { loadExecutionConfig } = await import("@wssp/api/sandbox/execution-config");
const { requestDigestMetadata } = await import("@wssp/api/sandbox/idempotency");

afterAll(() => db.close());
const owners: string[] = [];
afterEach(async () => {
  await db.inspect.outboxEvent.updateMany({
    where: { userId: { in: owners }, processedAt: null },
    data: { processedAt: new Date() },
  });
});
const SENTINEL = "synthetic-private-config-3d";
async function seed(keyed = true) {
  const ownerId = randomUUID();
  owners.push(ownerId);
  await db.inspect.user.create({
    data: {
      id: ownerId,
      name: "Owner",
      email: `${ownerId}@example.test`,
      twoFactorEnabled: true,
      emailVerified: true,
    },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: ownerId,
      slug: "lab",
      label: "Lab",
      status: "CONNECTED",
      connectionEpoch: 1,
      egressEnforcement: true,
      ...(keyed
        ? {
            journalKeyVersion: 1,
            journalKeyId: requestDigestMetadata().requestDigestKeyId,
            journalKeyAcknowledgedEpoch: 1,
          }
        : {}),
    },
  });
  const template = await seedTemplateRevision(db.inspect, {
    data: {
      userId: ownerId,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      imageRef: "images:ubuntu/24.04/cloud",
      incusFingerprint: `sha256:${"e".repeat(64)}`,
    },
  });
  const owner = { kind: "session" as const, ownerId };
  const input = {
    template: "revision/" + template.id,
    sandboxHostId: host.id,
    idempotencyKey: randomUUID(),
    envs: { APP: SENTINEL },
  };
  return { owner, host, input };
}

it("3D dispatch waits without a claim until an exact durable config ACK, then resumes after recovery", async () => {
  const f = await seed();
  const sandbox = await createSandbox(f.owner, f.input);
  const op = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: sandbox.id },
  });
  const sender = {
    userId: f.owner.ownerId,
    hostId: f.host.id,
    connectionEpoch: 1,
    isCurrent: () => true,
  };
  await processSandboxOutboxBatch();
  expect(manager.dispatchOperation).not.toHaveBeenCalled();
  expect(manager.installExecutionConfig).toHaveBeenCalledOnce();
  const frame = vi.mocked(manager.installExecutionConfig).mock.calls[0]![3];
  expect(frame).toMatchObject({
    sandboxOwnerId: f.owner.ownerId,
    type: "private.config.install",
    env: [["APP", SENTINEL]],
  });
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: op.id } }),
  ).toMatchObject({ dispatchAttempt: 0, state: "QUEUED" });
  const ack = {
    sandboxOwnerId: f.owner.ownerId,
    type: "private.config.ack" as const,
    sandboxId: sandbox.id,
    generation: frame.generation,
    config: frame.config,
    connectionEpoch: 1,
  };
  for (const bad of [
    { ...ack, connectionEpoch: 2 },
    { ...ack, generation: 2 },
    { ...ack, sandboxId: "wrong" },
    ...["configId", "bindingKeyId", "bindingMac"].map((k) => ({
      ...ack,
      config: { ...ack.config, [k]: "wrong" },
    })),
  ])
    expect(await acknowledgeExecutionConfig(sender, bad)).toBe(false);
  expect(
    (await loadExecutionConfig(db.prisma, sandbox.id, f.owner.ownerId))?.acknowledgedEpoch,
  ).toBeNull();
  const gate = db.pauseAt("ack", { before: "$transaction.commit" });
  const pending = db.run("ack", () => acknowledgeExecutionConfig(sender, ack));
  await gate.waitReached();
  expect(
    (await loadExecutionConfig(db.inspect, sandbox.id, f.owner.ownerId))?.acknowledgedEpoch,
  ).toBeNull();
  gate.release();
  expect(await pending).toBe(true);
  vi.clearAllMocks();
  await processSandboxOutboxBatch();
  expect(manager.installExecutionConfig).not.toHaveBeenCalled();
  expect(manager.dispatchOperation).toHaveBeenCalledOnce();
  expect(vi.mocked(manager.dispatchOperation).mock.calls[0]![1]).toMatchObject({
    privateConfig: frame.config,
  });
  expect(JSON.stringify(vi.mocked(manager.dispatchOperation).mock.calls)).not.toContain(SENTINEL);
  // A reconnect invalidates config evidence even when the durable config remains.
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { connectionEpoch: 2, journalKeyAcknowledgedEpoch: 2 },
  });
  expect(await acknowledgeExecutionConfig({ ...sender, connectionEpoch: 2 }, ack)).toBe(false);
  expect(
    await acknowledgeExecutionConfig(
      { ...sender, connectionEpoch: 2 },
      { ...ack, connectionEpoch: 2 },
    ),
  ).toBe(true);
  await db.inspect.outboxEvent.updateMany({
    where: { aggregateId: sandbox.id },
    data: { processedAt: new Date() },
  });
});

it.each(["missing", "corrupt", "union", "reference"])(
  "3D %s stored config fails closed before any frame and persists only a constant",
  async (fault) => {
    vi.clearAllMocks();
    const f = await seed();
    const sandbox = await createSandbox(f.owner, f.input);
    if (fault === "missing") {
      await expect(
        db.inspect.sandboxExecutionConfig.delete({ where: { sandboxId: sandbox.id } }),
      ).rejects.toMatchObject({ code: "P2003" });
      await db.inspect.sandbox.update({
        where: { id: sandbox.id },
        data: { currentPlacementId: null },
      });
      await db.inspect.sandboxPlacement.deleteMany({ where: { sandboxId: sandbox.id } });
      await db.inspect.sandboxExecutionConfig.delete({ where: { sandboxId: sandbox.id } });
    }
    if (fault === "corrupt" || fault === "union")
      await db.inspect.sandboxExecutionConfig.update({
        where: { sandboxId: sandbox.id },
        data: {
          mergedDefaults: { APP: "changed-private-value" },
          ...(fault === "corrupt" ? { sandboxOverrides: { APP: "changed-private-value" } } : {}),
        },
      });
    if (fault === "reference") {
      const event = await db.inspect.outboxEvent.findFirstOrThrow({
        where: { aggregateId: sandbox.id },
      });
      const payload = event.payload as import("@wssp/db").Prisma.InputJsonObject;
      await db.inspect.outboxEvent.update({
        where: { id: event.id },
        data: {
          payload: {
            ...payload,
            privateConfig: {
              configId: "wrong",
              bindingScheme: "hmac-sha256-v1",
              bindingKeyId: requestDigestMetadata().requestDigestKeyId,
              bindingMac: "a".repeat(64),
            },
          },
        },
      });
    }
    await processSandboxOutboxBatch();
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
    expect(manager.installExecutionConfig).not.toHaveBeenCalled();
    const operation = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: sandbox.id },
    });
    if (fault === "missing") {
      // Removing the config also removed its Restrict-bound boot. Without
      // pinned charges cleanup must retain both claims rather than guess them.
      expect(operation).toMatchObject({ state: "QUEUED", dispatchAttempt: 0, errorCode: null });
      expect(
        await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } }),
      ).toMatchObject({
        liveResourcesHeld: true,
        diskReservationHeld: true,
      });
      return;
    }
    expect(operation).toMatchObject({
      state: "FAILED",
      dispatchAttempt: 0,
      errorCode: "protocol_error",
    });
    expect(JSON.stringify(operation)).not.toContain(SENTINEL);
    expect(operation.errorDetail).toBe("Invalid dispatch or host report.");
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
    ).toBe(0);
    await processSandboxOutboxBatch();
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
    ).toBe(0);
  },
);

it("3D config ACK commit failure rolls back epoch evidence and discards invocation details", async () => {
  const f = await seed();
  const sandbox = await createSandbox(f.owner, f.input);
  const config = await loadExecutionConfig(db.prisma, sandbox.id, f.owner.ownerId);
  if (!config) throw new Error("fixture config missing");
  const ack = {
    sandboxOwnerId: f.owner.ownerId,
    type: "private.config.ack" as const,
    sandboxId: sandbox.id,
    generation: 1,
    connectionEpoch: 1,
    config: config.reference,
  };
  const sender = { userId: f.owner.ownerId, hostId: f.host.id, connectionEpoch: 1 };
  const gate = db.pauseAt("ack-rollback", { before: "$transaction.commit" });
  const result = db
    .run("ack-rollback", () => acknowledgeExecutionConfig(sender, ack))
    .catch((error: unknown) => error);
  await gate.waitReached();
  gate.fail(new Error(`commit ${SENTINEL}`, { cause: new Error(SENTINEL) }));
  expect(String(await result)).not.toContain(SENTINEL);
  expect(
    (await loadExecutionConfig(db.prisma, sandbox.id, f.owner.ownerId))?.acknowledgedEpoch,
  ).toBeNull();
  expect(await acknowledgeExecutionConfig({ ...sender, userId: "other-owner" }, ack)).toBe(false);
  expect(await acknowledgeExecutionConfig(sender, ack)).toBe(true);
});

it("3D corrupt config after a possible prior effect retains UNKNOWN_OUTCOME and the live charge", async () => {
  const f = await seed();
  const sandbox = await createSandbox(f.owner, f.input);
  const operation = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: sandbox.id },
  });
  const event = await db.inspect.outboxEvent.findFirstOrThrow({
    where: { aggregateId: sandbox.id },
  });
  const payload = event.payload as import("@wssp/db").Prisma.InputJsonObject;
  await db.inspect.sandboxOperation.update({
    where: { id: operation.id },
    data: { dispatchAttempt: 1, dispatchedHostId: f.host.id, dispatchedConnectionEpoch: 1 },
  });
  await db.inspect.outboxEvent.update({
    where: { id: event.id },
    data: { payload: { ...payload, dispatchAttempt: 1 } },
  });
  await db.inspect.sandboxExecutionConfig.update({
    where: { sandboxId: sandbox.id },
    data: { mergedDefaults: { APP: "corrupt" } },
  });
  await processSandboxOutboxBatch();
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: operation.id } }),
  ).toMatchObject({ state: "UNKNOWN_OUTCOME", errorCode: "protocol_error" });
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
  ).toBe(1);
});

it("3D authority loss rolls back config ACK evidence in the same transaction", async () => {
  const f = await seed();
  const sandbox = await createSandbox(f.owner, f.input);
  const config = await loadExecutionConfig(db.prisma, sandbox.id, f.owner.ownerId);
  if (!config) throw new Error("fixture config missing");
  let current = true;
  const gate = db.pauseAt("ack-authority", { after: "sandboxExecutionConfig.updateMany" });
  const result = db.run("ack-authority", () =>
    acknowledgeExecutionConfig(
      { userId: f.owner.ownerId, hostId: f.host.id, connectionEpoch: 1, isCurrent: () => current },
      {
        sandboxOwnerId: f.owner.ownerId,
        type: "private.config.ack",
        sandboxId: sandbox.id,
        generation: 1,
        connectionEpoch: 1,
        config: config.reference,
      },
    ),
  );
  await gate.waitReached();
  current = false;
  gate.release();
  expect(await result).toBe(false);
  expect(
    (await loadExecutionConfig(db.prisma, sandbox.id, f.owner.ownerId))?.acknowledgedEpoch,
  ).toBeNull();
});

it("old daemon without a refusal message: pending config installs back off durably across repeated drains without self-waking", async () => {
  vi.clearAllMocks();
  const f = await seed();
  const sandbox = await createSandbox(f.owner, f.input);
  const now = new Date();
  const clock = () => now;
  const wake = vi.fn();
  const { bindSandboxDispatchWake } = await import("@wssp/api/sandbox/outbox");
  bindSandboxDispatchWake(wake);
  try {
    for (let drain = 0; drain < 5; drain++) await processSandboxOutboxBatch(clock);
    expect(manager.installExecutionConfig).toHaveBeenCalledOnce();
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
    expect(wake).not.toHaveBeenCalled();
    const event = await db.inspect.outboxEvent.findFirstOrThrow({
      where: { aggregateId: sandbox.id },
    });
    expect(event.claimToken).toMatch(/^config:/);
    expect(event.claimedAt).toEqual(now);
    expect(event.sentAt).toBeNull();
    expect(JSON.stringify(event)).not.toContain(SENTINEL);
    const operation = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: sandbox.id },
    });
    expect(operation).toMatchObject({ state: "QUEUED", dispatchAttempt: 0 });
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
    ).toMatchObject({ liveCount: 1 });

    // A later recovery pass retries, but further drains share the persisted lease.
    now.setTime(now.getTime() + 31_000);
    for (let drain = 0; drain < 5; drain++) await processSandboxOutboxBatch(clock);
    expect(manager.installExecutionConfig).toHaveBeenCalledTimes(2);
    expect(wake).not.toHaveBeenCalled();
    const frame = vi.mocked(manager.installExecutionConfig).mock.calls[1]![3];
    expect(
      await acknowledgeExecutionConfig(
        {
          userId: f.owner.ownerId,
          hostId: f.host.id,
          connectionEpoch: 1,
        },
        {
          sandboxOwnerId: f.owner.ownerId,
          type: "private.config.ack",
          sandboxId: sandbox.id,
          generation: 1,
          connectionEpoch: 1,
          config: frame.config,
        },
      ),
    ).toBe(true);
    // The exact ACK unlocks immediately, without waiting for the backoff lease.
    await processSandboxOutboxBatch(clock);
    expect(manager.installExecutionConfig).toHaveBeenCalledTimes(2);
    expect(manager.dispatchOperation).toHaveBeenCalledOnce();
  } finally {
    bindSandboxDispatchWake(null);
  }
});

it.each([false, true])(
  "known config pre-frame refusal settles once (possible prior effect: %s)",
  async (possible) => {
    vi.clearAllMocks();
    const f = await seed();
    const sandbox = await createSandbox(f.owner, f.input);
    const operation = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: sandbox.id },
    });
    // Keep another reservation on this host to catch a duplicate decrement.
    const sibling = await createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID() });
    await db.inspect.outboxEvent.updateMany({
      where: { aggregateId: sibling.id },
      data: { processedAt: new Date() },
    });
    if (possible)
      await db.inspect.sandboxOperation.update({
        where: { id: operation.id },
        data: {
          state: "DISPATCHED",
          dispatchAttempt: 1,
          dispatchedHostId: f.host.id,
          dispatchedConnectionEpoch: 1,
        },
      });
    vi.mocked(manager.installExecutionConfig).mockResolvedValueOnce("invalid_config");
    for (let drain = 0; drain < 5; drain++) await processSandboxOutboxBatch();
    expect(manager.installExecutionConfig).toHaveBeenCalledOnce();
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
    const settled = await db.inspect.sandboxOperation.findUniqueOrThrow({
      where: { id: operation.id },
    });
    expect(settled).toMatchObject({
      state: possible ? "UNKNOWN_OUTCOME" : "FAILED",
      dispatchAttempt: possible ? 1 : 0,
      errorCode: "protocol_error",
      errorDetail: "Invalid dispatch or host report.",
    });
    expect(JSON.stringify(settled)).not.toContain(SENTINEL);
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
    ).toMatchObject({ liveCount: possible ? 2 : 1 });
    const placement = await db.inspect.sandboxPlacement.findFirstOrThrow({
      where: { sandboxId: sandbox.id },
    });
    if (possible) expect(placement.endedAt).toBeNull();
    else expect(placement).toMatchObject({ endedAt: expect.any(Date), endReason: "not_issued" });
  },
);

it("not-sent config on reconnect retries immediately after reconciliation", async () => {
  vi.clearAllMocks();
  const f = await seed();
  const sandbox = await createSandbox(f.owner, f.input);
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { connectionEpoch: 2, journalKeyAcknowledgedEpoch: 2 },
  });
  vi.mocked(manager.installExecutionConfig).mockResolvedValueOnce("not_sent");
  const now = new Date();
  await processSandboxOutboxBatch(() => now);
  expect(manager.installExecutionConfig).toHaveBeenCalledOnce();
  expect(
    await db.inspect.outboxEvent.findFirstOrThrow({
      where: { aggregateId: sandbox.id },
    }),
  ).toMatchObject({ claimToken: null, claimedAt: null, sentAt: null });
  // Reconcile completes five seconds later, well inside the 30 s backoff.
  now.setTime(now.getTime() + 5_000);
  await processSandboxOutboxBatch(() => now);
  expect(manager.installExecutionConfig).toHaveBeenCalledTimes(2);
  expect(vi.mocked(manager.installExecutionConfig).mock.calls[1]![3].connectionEpoch).toBe(2);
});

it.each(["cleanup_watermark", "config_count_bound", "journal_io_before_persistence"] as const)(
  "host config refusal %s releases a proven first refused claim once",
  async (reason) => {
    vi.clearAllMocks();
    const { refuseExecutionConfig } = await import("./outbox-processor.js");
    const f = await seed();
    const sandbox = await createSandbox(f.owner, f.input);
    const sibling = await createSandbox(f.owner, { ...f.input, idempotencyKey: randomUUID() });
    await db.inspect.outboxEvent.updateMany({
      where: { aggregateId: sibling.id },
      data: { processedAt: new Date() },
    });
    await processSandboxOutboxBatch();
    const install = vi.mocked(manager.installExecutionConfig).mock.calls[0]![3];
    const sender = { hostId: f.host.id, userId: f.owner.ownerId, connectionEpoch: 1 };
    const refusal = {
      sandboxOwnerId: f.owner.ownerId,
      type: "private.config.refused" as const,
      connectionEpoch: 1,
      sandboxId: sandbox.id,
      generation: install.generation,
      configId: install.config.configId,
      refusalToken: install.refusalToken!,
      reason,
    };
    for (const patch of [
      { connectionEpoch: 2 },
      { configId: "wrong" },
      { refusalToken: "wrong" },
      { generation: 2 },
    ])
      expect(await refuseExecutionConfig(sender, { ...refusal, ...patch })).toBe(false);
    expect(await refuseExecutionConfig(sender, refusal)).toBe(true);
    for (let replay = 0; replay < 3; replay++)
      expect(await refuseExecutionConfig(sender, refusal)).toBe(false);
    await processSandboxOutboxBatch();
    const operation = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: sandbox.id },
    });
    expect(operation).toMatchObject({
      state: "FAILED",
      dispatchAttempt: 1,
      errorCode: "private_config_refused",
      errorDetail: "Private configuration refused before installation.",
    });
    const { toOperationDto } = await import("@wssp/api/sandbox/sdk-reads");
    const { operationSchema } = await import("@wssp/sandbox-contracts");
    expect(operationSchema.parse(toOperationDto(operation))).toMatchObject({
      state: "FAILED",
      outcome: "failed",
      errorCode: "host_effect_not_issued",
    });
    expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } })).toMatchObject(
      { state: "ERROR", liveResourcesHeld: false },
    );
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
    ).toMatchObject({ liveCount: 1 });
    expect(
      await db.inspect.sandboxPlacement.findFirstOrThrow({ where: { sandboxId: sandbox.id } }),
    ).toMatchObject({ endedAt: expect.any(Date), endReason: "not_issued" });
    expect(JSON.stringify(operation)).not.toContain(SENTINEL);
  },
);

it("host config refusal after a possible prior effect stays unknown and charged", async () => {
  vi.clearAllMocks();
  const { refuseExecutionConfig } = await import("./outbox-processor.js");
  const f = await seed();
  const sandbox = await createSandbox(f.owner, f.input);
  await db.inspect.sandboxOperation.updateMany({
    where: { sandboxId: sandbox.id },
    data: {
      state: "DISPATCHED",
      dispatchAttempt: 1,
      dispatchedHostId: f.host.id,
      dispatchedConnectionEpoch: 1,
    },
  });
  await processSandboxOutboxBatch();
  const install = vi.mocked(manager.installExecutionConfig).mock.calls[0]![3];
  expect(
    await refuseExecutionConfig(
      { hostId: f.host.id, userId: f.owner.ownerId, connectionEpoch: 1 },
      {
        sandboxOwnerId: f.owner.ownerId,
        type: "private.config.refused",
        connectionEpoch: 1,
        sandboxId: sandbox.id,
        generation: 1,
        configId: install.config.configId,
        refusalToken: install.refusalToken!,
        reason: "cleanup_watermark",
      },
    ),
  ).toBe(true);
  expect(
    await db.inspect.sandboxOperation.findFirstOrThrow({ where: { sandboxId: sandbox.id } }),
  ).toMatchObject({ state: "UNKNOWN_OUTCOME", dispatchAttempt: 1 });
  const { toOperationDto } = await import("@wssp/api/sandbox/sdk-reads");
  const uncertain = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: sandbox.id },
  });
  expect(toOperationDto(uncertain)).toMatchObject({
    outcome: "unknown",
    errorCode: "unknown_outcome",
  });
  expect(
    await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
  ).toMatchObject({ liveCount: 1 });
});

it("host config refusal rolls back slot release if session authority moves before commit", async () => {
  vi.clearAllMocks();
  const { refuseExecutionConfig } = await import("./outbox-processor.js");
  const f = await seed();
  const sandbox = await createSandbox(f.owner, f.input);
  await processSandboxOutboxBatch();
  const install = vi.mocked(manager.installExecutionConfig).mock.calls[0]![3];
  let current = true;
  const gate = db.pauseAt("refusal-authority", { after: "outboxEvent.updateMany" });
  const pending = db.run("refusal-authority", () =>
    refuseExecutionConfig(
      {
        hostId: f.host.id,
        userId: f.owner.ownerId,
        connectionEpoch: 1,
        isCurrent: () => current,
      },
      {
        sandboxOwnerId: f.owner.ownerId,
        type: "private.config.refused",
        connectionEpoch: 1,
        sandboxId: sandbox.id,
        generation: 1,
        configId: install.config.configId,
        refusalToken: install.refusalToken!,
        reason: "cleanup_watermark",
      },
    ),
  );
  await gate.waitReached();
  current = false;
  gate.release();
  expect(await pending).toBe(false);
  expect(
    await db.inspect.sandboxOperation.findFirstOrThrow({ where: { sandboxId: sandbox.id } }),
  ).toMatchObject({ state: "QUEUED", dispatchAttempt: 0 });
  expect(
    await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } }),
  ).toMatchObject({ liveCount: 1 });
});

it("S3c mixed creators bind config ACKs, dispatch, results and census to one authenticated foreign transport", async () => {
  vi.clearAllMocks();
  const a = await seed();
  const creatorId = randomUUID();
  owners.push(creatorId);
  await db.inspect.user.create({
    data: {
      id: creatorId,
      name: "Creator",
      email: `${creatorId}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  const pool = await db.inspect.sandboxPool.create({
    data: { userId: a.owner.ownerId, slug: "shared", label: "Shared" },
  });
  await db.inspect.sandboxPoolMember.create({
    data: {
      userId: a.owner.ownerId,
      hostOwnerId: a.owner.ownerId,
      poolId: pool.id,
      sandboxHostId: a.host.id,
    },
  });
  await db.inspect.share.create({
    data: { poolId: pool.id, ownerUserId: a.owner.ownerId, granteeUserId: creatorId },
  });
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: creatorId,
      sandboxHostId: a.host.id,
      slug: "private",
      label: "Private",
      incusFingerprint: `sha256:${"e".repeat(64)}`,
    },
  });
  const local = await createSandbox(a.owner, a.input);
  const foreign = await createSandbox(
    { kind: "session", ownerId: creatorId },
    {
      poolId: pool.id,
      template: `revision/${revision.id}`,
      idempotencyKey: randomUUID(),
      envs: { APP: "foreign-private" },
    },
  );
  const sender = { hostId: a.host.id, userId: a.owner.ownerId, connectionEpoch: 1 };
  await processSandboxOutboxBatch();
  const frames = vi.mocked(manager.installExecutionConfig).mock.calls.map((c) => c[3]);
  expect(frames).toHaveLength(2);
  const { applyOperationResult } = await import("./operation-handlers.js");
  const { InventoryCensus } = await import("./inventory-reconcile.js");
  for (const [sandbox, ownerId] of [
    [local, a.owner.ownerId],
    [foreign, creatorId],
  ] as const) {
    const frame = frames.find((f) => f.sandboxId === sandbox.id)!;
    expect(frame).toMatchObject({
      hostOwnerId: a.owner.ownerId,
      sandboxOwnerId: ownerId,
      hostId: a.host.id,
    });
    const ack = {
      type: "private.config.ack" as const,
      sandboxOwnerId: ownerId,
      sandboxId: sandbox.id,
      generation: frame.generation,
      config: frame.config,
      connectionEpoch: 1,
    };
    expect(
      await acknowledgeExecutionConfig(sender, {
        ...ack,
        sandboxOwnerId: ownerId === creatorId ? a.owner.ownerId : creatorId,
      }),
    ).toBe(false);
    expect(await acknowledgeExecutionConfig({ ...sender, connectionEpoch: 2 }, ack)).toBe(false);
    expect(await acknowledgeExecutionConfig(sender, ack)).toBe(true);
  }
  await processSandboxOutboxBatch();
  expect(manager.dispatchOperation).toHaveBeenCalledTimes(2);
  for (const [sandbox, ownerId] of [
    [local, a.owner.ownerId],
    [foreign, creatorId],
  ] as const) {
    const op = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: sandbox.id },
    });
    const event = await db.inspect.outboxEvent.findFirstOrThrow({
      where: { aggregateId: sandbox.id },
    });
    const payload = event.payload as Record<string, unknown>;
    const input = {
      sender,
      sandboxOwnerId: ownerId,
      sandboxId: sandbox.id,
      operationId: op.id,
      generation: op.generation,
      attempt: op.dispatchAttempt,
      state: "succeeded",
      result: { state: "ready", lease: payload.lease },
    };
    expect(
      await applyOperationResult({
        ...input,
        sandboxOwnerId: ownerId === creatorId ? a.owner.ownerId : creatorId,
      }),
    ).toMatchObject({ written: false });
    expect(await applyOperationResult(input)).toMatchObject({ written: true });
    expect((await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } })).state).toBe(
      "READY",
    );
  }
  const entries = [
    { sandboxId: local.id, sandboxOwnerId: a.owner.ownerId },
    { sandboxId: foreign.id, sandboxOwnerId: creatorId },
  ]
    .sort((a, b) => a.sandboxId.localeCompare(b.sandboxId))
    .map((e) => ({ ...e, state: "ready" as const, root: null }));
  expect(
    await new InventoryCensus(sender).acceptPage({
      type: "sandbox.inventory",
      page: 0,
      complete: true,
      entries,
    }),
  ).toEqual({ ok: true });
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: a.host.id } })).quarantinedAt,
  ).toBeNull();
  const p = await db.inspect.sandboxPlacement.findFirstOrThrow({
    where: { sandboxId: foreign.id },
  });
  await db.inspect.sandboxPlacement.update({
    where: { id: p.id },
    data: { hostOwnerId: creatorId },
  });
  const frame = frames.find((f) => f.sandboxId === foreign.id)!;
  expect(
    await acknowledgeExecutionConfig(sender, {
      type: "private.config.ack",
      sandboxOwnerId: creatorId,
      sandboxId: foreign.id,
      generation: frame.generation,
      config: frame.config,
      connectionEpoch: 1,
    }),
  ).toBe(false);
});
