import { requestDigestMetadata } from "@wssp/api/sandbox/idempotency";
import { vmLiveMemoryChargeMiB } from "@wssp/sandbox-contracts";
import {
  digestContextSnapshot,
  REQUEST_DIGEST_DOMAIN,
} from "../../../../packages/api/src/sandbox/digest-context";
import {
  acknowledgeFixtureExecutionConfigs,
  seedLaunchHost,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, afterEach, beforeEach, expect, it, vi } from "vitest";
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
// No sockets: relay "sends" succeed; every durable transition is real SQL.
vi.mock("./session-manager.js", () => ({
  sandboxRelaySessionManager: {
    isHostConnected: vi.fn().mockReturnValue(true),
    dispatchOperation: vi.fn().mockReturnValue("sent"),
    captureHostDispatchCredential: vi.fn(),
  },
}));

const db = await pgTestDatabase();
const { createSandboxInput } = await import("@wssp/api/sandbox/contracts");
const { createSandbox } = await import("../../../../packages/api/src/sandbox/services/sandboxes");
const { sandboxRelaySessionManager: manager } = await import("./session-manager.js");
const { processSandboxOutboxBatch: processOutboxWithInstalledConfig } = await import(
  "./outbox-processor.js"
);
async function processSandboxOutboxBatch(
  ...args: Parameters<typeof processOutboxWithInstalledConfig>
) {
  await acknowledgeFixtureExecutionConfigs(db.inspect);
  return processOutboxWithInstalledConfig(...args);
}

const fixtureOwners: string[] = [];
afterAll(() => db.close());
afterEach(async () => {
  const owners = fixtureOwners.splice(0);
  // Retire scan candidates before assertions, including deliberately corrupt C7 rows.
  await db.inspect.outboxEvent.updateMany({
    where: { userId: { in: owners }, processedAt: null },
    data: { processedAt: new Date() },
  });
  const hosts = await db.inspect.sandboxHost.findMany({
    where: { userId: { in: owners } },
    take: 256,
  });
  expect(hosts.length).toBeLessThan(256);
  for (const host of hosts) {
    const held = await db.inspect.sandbox.findMany({
      where: { userId: host.userId, sandboxHostId: host.id, liveResourcesHeld: true },
      take: 250,
      include: { CurrentPlacement: true },
    });
    expect(host.memoryReservedMiB).toBe(
      held.reduce((sum, row) => sum + row.CurrentPlacement!.chargedMemoryMiB!, 0),
    );
    expect(host.vcpuReserved).toBe(
      held.reduce((sum, row) => sum + row.CurrentPlacement!.chargedVcpu!, 0),
    );
    expect(host.liveCount).toBe(held.length);
  }
});
beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(manager.isHostConnected).mockReset().mockReturnValue(true);
  vi.mocked(manager.captureHostDispatchCredential).mockReset().mockReturnValue(undefined);
  vi.mocked(manager.dispatchOperation).mockReset().mockResolvedValue("sent");
});

const FP = `sha256:${"d".repeat(64)}`;
const clock = () => new Date();

async function seed(placement: "direct" | "pool" = "direct") {
  const ownerId = `user-${randomUUID()}`;
  fixtureOwners.push(ownerId);
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
  const pool =
    placement === "pool"
      ? await db.inspect.sandboxPool.create({
          data: {
            userId: ownerId,
            slug: "pool",
            label: "Pool",
            Members: { create: { sandboxHostId: host.id, hostOwnerId: ownerId } },
          },
        })
      : null;
  // An egress-policy create leaves exactly one pending launch intent.
  const sandbox = await createSandbox(
    { kind: "session", ownerId },
    createSandboxInput.parse({
      diskGiB: 32,
      template: "revision/" + template.id,
      ...(pool ? { poolId: pool.id } : { sandboxHostId: host.id }),
      idempotencyKey: `create-${randomUUID()}`,
      egress: { domains: ["example.com"] },
      cpuCount: 2,
      memoryMiB: 2048,
    }),
  );
  const operation = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: sandbox.id, kind: "CREATE_SANDBOX" },
  });
  expect(operation).toMatchObject({ state: "QUEUED", dispatchAttempt: 0 });
  const event = await db.inspect.outboxEvent.findFirstOrThrow({
    where: { aggregateId: sandbox.id, payload: { path: ["operationId"], equals: operation.id } },
  });
  const key = await db.inspect.sdkKey.create({
    data: {
      userId: ownerId,
      name: "dispatch",
      lookupPrefix: randomUUID(),
      secretDigest: randomUUID(),
      resourceMode: "ALL_OWNED",
      scopes: ["sandboxes:create", "sandboxes:manage", "sandboxes:destroy"],
    },
  });
  await db.inspect.sandboxOperation.update({
    where: { id: operation.id },
    data: { authorizingKeyId: key.id },
  });
  await db.inspect.outboxEvent.update({
    where: { id: event.id },
    data: {
      payload: {
        ...(event.payload as Record<string, string>),
        authorizingPrincipal: { kind: "sdkKey", keyId: key.id },
      },
    },
  });
  return {
    ownerId,
    keyId: key.id,
    hostId: host.id,
    sandboxId: sandbox.id,
    operationId: operation.id,
    eventId: event.id,
  };
}

it("VB4-T-6: corrupt owner event backs off while another owner dispatches and leases reclaim", async () => {
  const corrupt = await seed();
  const healthy = await seed();
  const expired = await seed();
  // Stable explicit order: the poison must be encountered before healthy work.
  const corruptEventId = `000-corrupt-${randomUUID()}`;
  const healthyEventId = `999-healthy-${randomUUID()}`;
  await db.inspect.outboxEvent.update({
    where: { id: corrupt.eventId },
    data: { id: corruptEventId },
  });
  await db.inspect.outboxEvent.update({
    where: { id: healthy.eventId },
    data: { id: healthyEventId },
  });
  const originalHost = await db.inspect.sandboxHost.findUniqueOrThrow({
    where: { id: corrupt.hostId },
  });
  await db.inspect.sandboxHost.update({
    where: { id: corrupt.hostId },
    data: { memoryReservedMiB: 256, egressEnforcement: false },
  });
  const before = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: corrupt.sandboxId } });
  const placement = await db.inspect.sandboxPlacement.findUniqueOrThrow({
    where: { id: before.currentPlacementId! },
  });
  // A sent, completed launch is outside the send scan; only the reclaim tail
  // can move this READY sandbox to STOPPING and enqueue its cleanup.
  await db.inspect.sandboxOperation.update({
    where: { id: expired.operationId },
    data: { state: "SUCCEEDED" },
  });
  await db.inspect.outboxEvent.update({
    where: { id: expired.eventId },
    data: { processedAt: new Date(), sentAt: new Date() },
  });
  await db.inspect.sandbox.update({
    where: { id: expired.sandboxId },
    data: { state: "READY", leaseExpiresAt: new Date(Date.now() - 60_000) },
  });
  const log = vi.spyOn(console, "error").mockImplementation(() => {});
  const now = new Date();
  const scan = (elapsed = 0) => processSandboxOutboxBatch(() => new Date(now.getTime() + elapsed));
  try {
    expect(await scan()).toBe(2);
    expect(
      await db.inspect.outboxEvent.findUniqueOrThrow({ where: { id: healthyEventId } }),
    ).toMatchObject({ sentAt: expect.any(Date) });
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: healthy.operationId } }),
    ).toMatchObject({ state: "DISPATCHED" });
    expect(
      await db.inspect.sandbox.findUniqueOrThrow({ where: { id: expired.sandboxId } }),
    ).toMatchObject({ state: "STOPPING", generation: 2 });
    expect(
      await db.inspect.outboxEvent.findUniqueOrThrow({ where: { id: corruptEventId } }),
    ).toMatchObject({
      processedAt: null,
      sentAt: null,
      claimToken: "integrity-backoff:sandbox_reservation_underflow",
      claimedAt: now,
    });
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: corrupt.operationId } }),
    ).toMatchObject({ state: "QUEUED", dispatchAttempt: 0 });
    expect(
      await db.inspect.sandbox.findUniqueOrThrow({ where: { id: corrupt.sandboxId } }),
    ).toEqual(before);
    expect(
      await db.inspect.sandboxPlacement.findUniqueOrThrow({ where: { id: placement.id } }),
    ).toEqual(placement);
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: corrupt.hostId } }),
    ).toMatchObject({ liveCount: 1, memoryReservedMiB: 256 });
    expect(manager.dispatchOperation).toHaveBeenCalledTimes(1);
    expect(log).toHaveBeenCalledTimes(1);
    expect(log).toHaveBeenCalledWith("[sandbox] integrity failure:", {
      code: "sandbox_reservation_underflow",
      errorClass: "Error",
    });
    // Recovery scans and notifier wakes must not hammer the poisoned row.
    const corruptSends = () =>
      vi
        .mocked(manager.dispatchOperation)
        .mock.calls.filter(([, dispatch]) => dispatch.operationId === corrupt.operationId);
    for (const elapsed of [0, 1, 10_000, 29_999]) await scan(elapsed);
    expect(log).toHaveBeenCalledTimes(1);
    expect(corruptSends()).toHaveLength(0);
    // A retry after expiry still fails closed, and renews the bounded cooldown.
    await scan(30_001);
    expect(log).toHaveBeenCalledTimes(2);
    expect(corruptSends()).toHaveLength(0);
    // Operator repair needs no event recreation: a later scan can dispatch it.
    await db.inspect.sandboxHost.update({
      where: { id: corrupt.hostId },
      data: { memoryReservedMiB: originalHost.memoryReservedMiB, egressEnforcement: true },
    });
    expect(await scan(60_002)).toBe(1);
    expect(corruptSends()).toHaveLength(1);
    expect(log).toHaveBeenCalledTimes(2);
  } finally {
    log.mockRestore();
    // Restore only the deliberate corruption, after proving rollback retained
    // it, so the common ledger assertion and later scans see a valid fixture.
    await db.inspect.sandboxHost.update({
      where: { id: corrupt.hostId },
      data: { memoryReservedMiB: originalHost.memoryReservedMiB },
    });
  }
});

it.each(["newer claim", "changed payload"] as const)(
  "VB4-T-6 guard: integrity backoff preserves a %s committed after rollback",
  async (change) => {
    const fixture = await seed();
    const originalHost = await db.inspect.sandboxHost.findUniqueOrThrow({
      where: { id: fixture.hostId },
    });
    await db.inspect.sandboxHost.update({
      where: { id: fixture.hostId },
      data: { memoryReservedMiB: 256, egressEnforcement: false },
    });
    const now = new Date();
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    // This refusal fails before claiming the outbox row. Its first outbox UPDATE
    // is the cooldown write, after the failing transaction has rolled back.
    const gate = db.pauseAt("poison-scan", { before: "outboxEvent.updateMany" });
    const dispatch = db.run("poison-scan", () => processSandboxOutboxBatch(() => now));
    dispatch.catch(() => undefined);
    try {
      await gate.waitReached();
      expect(log).toHaveBeenCalledTimes(1);
      const rolledBack = await db.inspect.outboxEvent.findUniqueOrThrow({
        where: { id: fixture.eventId },
      });
      expect(rolledBack).toMatchObject({ claimToken: null, claimedAt: null });
      const replacement =
        change === "newer claim"
          ? { claimToken: randomUUID(), claimedAt: now }
          : {
              payload: {
                ...(rolledBack.payload as Record<string, string>),
                repairRevision: 1,
              },
            };
      // Independent committed SQL in the rollback → backoff window. The real
      // UPDATE must recheck both the lease and whole-JSON payload equality.
      const concurrent = await db.inspect.outboxEvent.update({
        where: { id: fixture.eventId },
        data: replacement,
      });
      gate.release();
      expect(await dispatch).toBe(0);
      const after = await db.inspect.outboxEvent.findUniqueOrThrow({
        where: { id: fixture.eventId },
      });
      expect(after).toMatchObject({
        claimToken: concurrent.claimToken,
        claimedAt: concurrent.claimedAt,
        payload: concurrent.payload,
        processedAt: null,
        sentAt: null,
      });
      expect(manager.dispatchOperation).not.toHaveBeenCalled();
    } finally {
      gate.release();
      await dispatch;
      log.mockRestore();
      await db.inspect.sandboxHost.update({
        where: { id: fixture.hostId },
        data: { memoryReservedMiB: originalHost.memoryReservedMiB },
      });
    }
  },
);

it("C7: lease reclaim skips a corrupt item and advances the keyset to a healthy owner", async () => {
  const corrupt = await seed();
  const healthy = await seed();
  // Reuse the sorted existing ids so the first reclaim transaction is corrupt.
  const ordered = [corrupt, healthy].sort((a, b) => a.sandboxId.localeCompare(b.sandboxId));
  const first = ordered[0]!;
  const second = ordered[1]!;
  for (const f of ordered)
    await db.inspect.sandbox.update({
      where: { id: f.sandboxId },
      data: { leaseExpiresAt: new Date(Date.now() - 60_000) },
    });
  const originalHost = await db.inspect.sandboxHost.findUniqueOrThrow({
    where: { id: first.hostId },
  });
  await db.inspect.sandboxHost.update({
    where: { id: first.hostId },
    data: { memoryReservedMiB: 256 },
  });
  const { reclaimExpiredSandboxLeases } = await import("@wssp/api/sandbox/lease");
  const log = vi.spyOn(console, "error").mockImplementation(() => {});
  try {
    // One item per page proves corrupt first-page rows do not stall pagination.
    expect(await reclaimExpiredSandboxLeases(clock, 1)).toBe(0);
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: first.operationId } }),
    ).toMatchObject({ state: "QUEUED", dispatchAttempt: 0 });
    expect(
      await db.inspect.outboxEvent.findUniqueOrThrow({ where: { id: first.eventId } }),
    ).toMatchObject({ processedAt: null, sentAt: null, claimToken: null });
    expect(
      await db.inspect.sandbox.findUniqueOrThrow({ where: { id: first.sandboxId } }),
    ).toMatchObject({ state: "REQUESTED", liveResourcesHeld: true });
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: first.hostId } }),
    ).toMatchObject({ liveCount: 1, memoryReservedMiB: 256 });
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: second.operationId } }),
    ).toMatchObject({ state: "FAILED", errorCode: "lease_expired" });
    expect(
      await db.inspect.sandbox.findUniqueOrThrow({ where: { id: second.sandboxId } }),
    ).toMatchObject({ state: "ERROR", liveResourcesHeld: false });
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: second.hostId } }),
    ).toMatchObject({ liveCount: 0, memoryReservedMiB: 0 });
    expect(log).toHaveBeenCalledTimes(1);
    expect(log).toHaveBeenCalledWith("[sandbox] integrity failure:", {
      code: "sandbox_reservation_underflow",
      errorClass: "Error",
    });
  } finally {
    log.mockRestore();
    await db.inspect.sandboxHost.update({
      where: { id: first.hostId },
      data: { memoryReservedMiB: originalHost.memoryReservedMiB },
    });
  }
});

it("C7 fixture teardown leaves no dispatch or reclaim work for later tests", async () => {
  const relay = await import("@wssp/api/sandbox/relay-fence");
  const transactions = vi.spyOn(relay, "relayTransaction");
  try {
    expect(await processSandboxOutboxBatch(clock)).toBe(0);
    expect(transactions).not.toHaveBeenCalled();
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
  } finally {
    transactions.mockRestore();
  }
});

it("3A dispatch waits on K while H remains free", async () => {
  const f = await seed();
  const held = db.pauseAt("key-holder", { before: "$transaction.commit" });
  const holder = db.run("key-holder", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sdk_key WHERE id = ${f.keyId} FOR UPDATE`;
    }),
  );
  await held.waitReached();
  const dispatch = db.run("dispatch", () => processSandboxOutboxBatch(clock));
  try {
    expect((await db.waitUntilBlocked("dispatch", { by: "key-holder" })).query).toMatch(
      /sdk_key.*FOR SHARE/,
    );
    await db.inspect.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${f.hostId} FOR UPDATE NOWAIT`;
    });
  } finally {
    held.release();
  }
  await holder;
  expect(await dispatch).toBe(1);
});

it.each(["root-first", "dispatch-first"] as const)(
  "3A dispatch/account deletion %s has no owner lock after K/H",
  async (order) => {
    const f = await seed();
    const heldRoot = db.pauseAt("root", { before: "$transaction.commit" });
    const heldDispatch = db.pauseAt("dispatch", {
      after: /^sql:SELECT id FROM sandbox_host.*FOR UPDATE$/,
    });
    const root = () =>
      db.run("root", () =>
        db.prisma.$transaction(async (tx) => {
          await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${f.ownerId} FOR UPDATE`;
        }),
      );
    let rooting: Promise<unknown>;
    let dispatching: Promise<number>;
    if (order === "root-first") {
      rooting = root();
      await heldRoot.waitReached();
      dispatching = db.run("dispatch", () => processSandboxOutboxBatch(clock));
      // This reaches H even though the root's exclusive owner lock is held.
      await heldDispatch.waitReached();
    } else {
      dispatching = db.run("dispatch", () => processSandboxOutboxBatch(clock));
      await heldDispatch.waitReached();
      rooting = root();
      await heldRoot.waitReached();
    }
    heldDispatch.release();
    try {
      expect(await dispatching).toBe(1);
    } finally {
      heldRoot.release();
    }
    await rooting;
  },
);

it("3A SDK revoke takes K without seeking H after it", async () => {
  const { revokeSdkKey } = await import("../../../../packages/api/src/sandbox/services/sdk-keys");
  const f = await seed();
  const gate = db.pauseAt("dispatch", { after: /^sql:SELECT id FROM sandbox_host.*FOR UPDATE$/ });
  const dispatching = db.run("dispatch", () => processSandboxOutboxBatch(clock));
  await gate.waitReached();
  const revoking = db.run("revoke", () =>
    revokeSdkKey({ kind: "session", ownerId: f.ownerId }, { id: f.keyId }),
  );
  try {
    expect((await db.waitUntilBlocked("revoke", { by: "dispatch" })).query).toContain("sdk_key");
  } finally {
    gate.release();
  }
  await dispatching;
  await revoking;
  expect(
    (await db.inspect.sdkKey.findUniqueOrThrow({ where: { id: f.keyId } })).revokedAt,
  ).not.toBeNull();
});

it("3A refusal/retry dispatch stays owner-lock-free and releases a known pre-effect slot once", async () => {
  const f = await seed();
  await db.inspect.sandboxHost.update({
    where: { id: f.hostId },
    data: { egressEnforcement: false },
  });
  const held = db.pauseAt("root", { before: "$transaction.commit" });
  const root = db.run("root", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${f.ownerId} FOR UPDATE`;
    }),
  );
  await held.waitReached();
  try {
    expect(await db.run("dispatch", () => processSandboxOutboxBatch(clock))).toBe(0);
  } finally {
    held.release();
  }
  await root;
  expect(
    (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operationId } })).state,
  ).toBe("FAILED");
  expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandboxId } })).toMatchObject({
    state: "ERROR",
    liveResourcesHeld: false,
  });
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } })).liveCount,
  ).toBe(0);
  await processSandboxOutboxBatch(clock);
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } })).liveCount,
  ).toBe(0);
});

it("3A terminal env-bearing events retire before the missing-key-ACK check", async () => {
  const f = await seed();
  await db.inspect.sandboxOperation.update({
    where: { id: f.operationId },
    data: { state: "FAILED" },
  });
  const event = await db.inspect.outboxEvent.findUniqueOrThrow({ where: { id: f.eventId } });
  await db.inspect.outboxEvent.update({
    where: { id: f.eventId },
    data: {
      payload: {
        ...(event.payload as Record<string, string>),
        env: [["TOKEN", "synthetic-terminal-env-3a"]],
      },
    },
  });
  await processSandboxOutboxBatch(clock);
  expect(
    (await db.inspect.outboxEvent.findUniqueOrThrow({ where: { id: f.eventId } })).processedAt,
  ).not.toBeNull();
  expect(manager.dispatchOperation).not.toHaveBeenCalled();
});

it("3A typed deterministic dispatch errors persist only a closed constant", async () => {
  const f = await seed();
  const { SandboxRelayDispatchValidationError, isDeterministicDispatchError } = await import(
    "./protocol.js"
  );
  const { getOperationView } = await import(
    "../../../../packages/api/src/sandbox/services/operation-views"
  );
  const sentinel = "synthetic-env-stdin-dispatch-3a";
  vi.mocked(manager.dispatchOperation).mockRejectedValueOnce(
    new SandboxRelayDispatchValidationError(sentinel),
  );
  expect(await processSandboxOutboxBatch(clock)).toBe(0);
  const row = await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operationId } });
  expect(row.errorDetail).toBe("Invalid dispatch or host report.");
  expect(
    (
      await getOperationView(
        { kind: "session", ownerId: f.ownerId },
        { operationId: f.operationId },
      )
    ).errorMessage,
  ).toBe("Invalid dispatch or host report.");
  expect(JSON.stringify(row)).not.toContain(sentinel);
  expect(isDeterministicDispatchError(new Error(`refusing operation.dispatch: ${sentinel}`))).toBe(
    false,
  );
  expect(
    isDeterministicDispatchError(
      Object.assign(new Error(sentinel), { name: "SandboxRelayProtocolError" }),
    ),
  ).toBe(false);
});

it.each(["root-first", "dispatch-first"] as const)(
  "3A real account finalization %s refuses live blockers without a dispatch deadlock",
  async (order) => {
    const { requestAccountDeletion } = await import("@wssp/db/account-deletion");
    const f = await seed();
    // Session control has no SDK authority ticket; the root lock excludes owner
    // admission but dispatch only updates already-owned rows.
    await db.inspect.sandboxOperation.update({
      where: { id: f.operationId },
      data: { authorizingKeyId: null },
    });
    const event = await db.inspect.outboxEvent.findUniqueOrThrow({ where: { id: f.eventId } });
    await db.inspect.outboxEvent.update({
      where: { id: f.eventId },
      data: {
        payload: {
          ...(event.payload as Record<string, string>),
          authorizingPrincipal: { kind: "session" },
        },
      },
    });
    const rootGate = db.pauseAt("root", { after: /^sql:SELECT id FROM "user".*FOR UPDATE$/ });
    const dispatchGate = db.pauseAt("dispatch", {
      after: /^sql:SELECT id FROM sandbox_host.*FOR UPDATE$/,
    });
    const root = () =>
      db
        .run("root", () => requestAccountDeletion(f.ownerId))
        .then(
          () => {
            throw new Error("Expected live account blockers");
          },
          (error: unknown) => error,
        );
    let deleting: Promise<unknown>, sending: Promise<number>;
    if (order === "root-first") {
      deleting = root();
      await rootGate.waitReached();
      sending = db.run("dispatch", () => processSandboxOutboxBatch(clock));
      await dispatchGate.waitReached();
    } else {
      sending = db.run("dispatch", () => processSandboxOutboxBatch(clock));
      await dispatchGate.waitReached();
      deleting = root();
      await rootGate.waitReached();
    }
    dispatchGate.release();
    try {
      expect(await sending).toBe(0);
    } finally {
      rootGate.release();
    }
    expect(await deleting).toMatchObject({
      kinds: expect.arrayContaining(["hosts", "sandboxes", "operations"]),
    });
    expect(await db.inspect.user.findUnique({ where: { id: f.ownerId } })).not.toBeNull();
    expect(await processSandboxOutboxBatch(clock)).toBe(1);
  },
);

it.each(["direct", "pool"] as const)(
  "host_revoke_after_placement_before_send on %s create sends nothing and releases once",
  async (placement) => {
    const f = await seed(placement);
    const { revalidateSandboxHostIdentity } = await import("@wssp/api/lib/host-token-access");
    const { revokeHostToken } = await import("../../../../packages/api/src/sandbox/services/hosts");
    const token = await db.inspect.hostToken.create({
      data: {
        userId: f.ownerId,
        sandboxHostId: f.hostId,
        name: "host",
        lookupPrefix: randomUUID(),
        secretDigest: randomUUID(),
      },
    });
    const identity = {
      credentialKind: "hostToken" as const,
      tokenId: token.id,
      hostId: f.hostId,
      userId: f.ownerId,
      expiresAt: null,
    };
    expect((await revalidateSandboxHostIdentity(identity)).status).toBe("active");
    vi.mocked(manager.captureHostDispatchCredential).mockReturnValue(async (epoch, client) => {
      if (epoch !== 1) return "indeterminate";
      const status = (await revalidateSandboxHostIdentity(identity, new Date(), client)).status;
      return status === "active" || status === "inactive" ? status : "indeterminate";
    });
    const sent = vi.fn();
    vi.mocked(manager.dispatchOperation).mockImplementationOnce(async () => {
      // The send claim committed, but socket authorization has not permitted IO.
      await revokeHostToken({ kind: "session", ownerId: f.ownerId }, { id: token.id });
      const status = (await revalidateSandboxHostIdentity(identity)).status;
      if (status !== "active") return "refused_before_frame";
      sent();
      return "sent";
    });
    expect(await processSandboxOutboxBatch(clock)).toBe(0);
    expect(sent).not.toHaveBeenCalled();
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operationId } }),
    ).toMatchObject({ state: "FAILED", dispatchAttempt: 1, errorCode: "credential_inactive" });
    expect(
      await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandboxId } }),
    ).toMatchObject({
      state: "ERROR",
      liveResourcesHeld: false,
      lastErrorCode: "credential_inactive",
      lastErrorDetail: "Accepted dispatch authority is inactive.",
    });
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } })).liveCount,
    ).toBe(0);
    await processSandboxOutboxBatch(clock);
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } })).liveCount,
    ).toBe(0);
  },
);

it.each(["stop", "kill"] as const)(
  "R1-3 inactive host credential requeues %s instead of failing until next-epoch cleanup settles",
  async (kind) => {
    const f = await seed();
    const { applyOperationResult } = await import("./operation-handlers.js");
    const { stopSandbox, killSandbox } = await import(
      "../../../../packages/api/src/sandbox/services/sandboxes"
    );
    await processSandboxOutboxBatch(clock);
    const createPayload = (
      await db.inspect.outboxEvent.findUniqueOrThrow({ where: { id: f.eventId } })
    ).payload as Record<string, unknown>;
    expect(
      await applyOperationResult({
        sender: { userId: f.ownerId, hostId: f.hostId, connectionEpoch: 1 },
        operationId: f.operationId,
        sandboxId: f.sandboxId,
        generation: 1,
        attempt: 1,
        state: "succeeded",
        result: { state: "ready", lease: createPayload.lease },
      }),
    ).toEqual({ written: true });
    await (kind === "stop" ? stopSandbox : killSandbox)(
      { kind: "session", ownerId: f.ownerId },
      { id: f.sandboxId, idempotencyKey: `cleanup-${kind}` },
    );
    const cleanup = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: f.sandboxId, kind: kind === "stop" ? "STOP_SANDBOX" : "KILL_SANDBOX" },
    });
    expect(cleanup.authorizingKeyId).toBeNull();
    vi.mocked(manager.captureHostDispatchCredential).mockReturnValue(async () => "inactive");
    vi.mocked(manager.dispatchOperation).mockResolvedValueOnce("refused_before_frame");
    expect(await processSandboxOutboxBatch(clock)).toBe(0);
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: cleanup.id } }),
    ).toMatchObject({ state: "QUEUED", dispatchAttempt: 0, dispatchedConnectionEpoch: null });
    expect(
      await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandboxId } }),
    ).toMatchObject({ state: "STOPPING", liveResourcesHeld: true });
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } })).liveCount,
    ).toBe(1);
    expect(
      await db.inspect.outboxEvent.findFirstOrThrow({
        where: { aggregateId: f.sandboxId, payload: { path: ["operationId"], equals: cleanup.id } },
      }),
    ).toMatchObject({ processedAt: null, sentAt: null, claimToken: null });

    await db.inspect.sandboxHost.update({ where: { id: f.hostId }, data: { connectionEpoch: 2 } });
    vi.mocked(manager.captureHostDispatchCredential).mockReturnValue(async () => "active");
    expect(await processSandboxOutboxBatch(clock)).toBe(1);
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: cleanup.id } }),
    ).toMatchObject({ state: "DISPATCHED", dispatchAttempt: 1, dispatchedConnectionEpoch: 2 });
    expect(
      await applyOperationResult({
        sender: { userId: f.ownerId, hostId: f.hostId, connectionEpoch: 2 },
        operationId: cleanup.id,
        sandboxId: f.sandboxId,
        generation: cleanup.generation,
        attempt: 1,
        state: "succeeded",
        result: { state: kind === "stop" ? "stopped" : "deleted" },
      }),
    ).toEqual({ written: true });
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: cleanup.id } }),
    ).toMatchObject({ state: "SUCCEEDED" });
    expect(
      await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandboxId } }),
    ).toMatchObject({ state: kind === "stop" ? "STOPPED" : "DELETED", liveResourcesHeld: false });
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } })).liveCount,
    ).toBe(0);
  },
);

it.each(
  (["direct", "pool"] as const).flatMap((placement) =>
    (["indeterminate", "prior-attempt", "possible-frame"] as const).map(
      (mode) => [placement, mode] as const,
    ),
  ),
)("host credential %s/%s cannot release uncertain capacity", async (placement, mode) => {
  const f = await seed(placement);
  if (mode === "prior-attempt") {
    await db.inspect.sandboxOperation.update({
      where: { id: f.operationId },
      data: {
        state: "DISPATCHED",
        dispatchAttempt: 1,
        dispatchedHostId: f.hostId,
        dispatchedConnectionEpoch: 1,
      },
    });
    await db.inspect.sandboxHost.update({
      where: { id: f.hostId },
      data: { connectionEpoch: 2, journalKeyAcknowledgedEpoch: 2 },
    });
    await db.inspect.sandboxHostStoragePool.updateMany({
      where: { sandboxHostId: f.hostId },
      data: { connectionEpoch: 2, reportedAt: new Date() },
    });
  }
  vi.mocked(manager.captureHostDispatchCredential).mockReturnValue(async () =>
    mode === "indeterminate" ? "indeterminate" : "inactive",
  );
  vi.mocked(manager.dispatchOperation).mockImplementationOnce(async (_hostId, input) => {
    if (mode === "possible-frame") input.onPossibleDispatchFrame?.();
    return "refused_before_frame";
  });
  expect(await processSandboxOutboxBatch(clock)).toBe(0);
  expect(
    (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operationId } })).state,
  ).toBe(
    mode === "indeterminate"
      ? "QUEUED"
      : mode === "prior-attempt"
        ? "UNKNOWN_OUTCOME"
        : "DISPATCHED",
  );
  expect(
    (await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandboxId } })).liveResourcesHeld,
  ).toBe(true);
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } })).liveCount,
  ).toBe(1);
});

it("3A deterministic cleanup waits on K while H remains free", async () => {
  const f = await seed();
  const { SandboxRelayDispatchValidationError } = await import("./protocol.js");
  const held = db.pauseAt("key-holder", { before: "$transaction.commit" });
  let holder: Promise<unknown> | undefined;
  vi.mocked(manager.dispatchOperation).mockImplementationOnce(async () => {
    holder = db.run("key-holder", () =>
      db.prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT id FROM sdk_key WHERE id = ${f.keyId} FOR UPDATE`;
      }),
    );
    await held.waitReached();
    throw new SandboxRelayDispatchValidationError("synthetic-env-deterministic-3a");
  });
  const dispatching = db.run("dispatch", () => processSandboxOutboxBatch(clock));
  await held.waitReached();
  try {
    expect((await db.waitUntilBlocked("dispatch", { by: "key-holder" })).query).toMatch(
      /sdk_key.*FOR SHARE/,
    );
    await db.inspect.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${f.hostId} FOR UPDATE NOWAIT`;
    });
  } finally {
    held.release();
  }
  await holder;
  expect(await dispatching).toBe(0);
  expect(
    (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operationId } })).state,
  ).toBe("FAILED");
});

it.each([false, true])(
  "3A expired provisioning hands off to owner admission with K/H free (possible effect: %s)",
  async (possible) => {
    const f = await seed();
    await db.inspect.sandbox.update({
      where: { id: f.sandboxId },
      data: { leaseExpiresAt: new Date(Date.now() - 60_000) },
    });
    if (possible) {
      await db.inspect.sandboxOperation.update({
        where: { id: f.operationId },
        data: {
          state: "DISPATCHED",
          dispatchAttempt: 1,
          dispatchedHostId: f.hostId,
          dispatchedConnectionEpoch: 1,
        },
      });
      await db.inspect.sandboxHost.update({
        where: { id: f.hostId },
        data: { connectionEpoch: 2, journalKeyAcknowledgedEpoch: 2 },
      });
    }
    const gate = db.pauseAt("root", { before: "$transaction.commit" });
    const root = db.run("root", () =>
      db.prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${f.ownerId} FOR UPDATE`;
      }),
    );
    await gate.waitReached();
    const expiry = db.run("expiry", () => processSandboxOutboxBatch(clock));
    try {
      expect((await db.waitUntilBlocked("expiry", { by: "root" })).query).toMatch(
        /FROM "user".*FOR SHARE/,
      );
      await db.inspect.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT id FROM sdk_key WHERE id = ${f.keyId} FOR UPDATE NOWAIT`;
        await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${f.hostId} FOR UPDATE NOWAIT`;
      });
    } finally {
      gate.release();
    }
    await root;
    expect(await expiry).toBe(possible ? 1 : 0);
    expect(manager.dispatchOperation).not.toHaveBeenCalled();
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operationId } }),
    ).toMatchObject({ state: "FAILED", errorCode: "lease_expired" });
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } })).liveCount,
    ).toBe(possible ? 1 : 0);
    expect(
      await db.inspect.sandboxOperation.count({
        where: { userId: f.ownerId, kind: "KILL_SANDBOX" },
      }),
    ).toBe(possible ? 1 : 0);
  },
);

it("3A host refusal revalidation reads through the held transaction", async () => {
  const f = await seed();
  const { revalidateSandboxHostIdentity } = await import("@wssp/api/lib/host-token-access");
  const token = await db.inspect.hostToken.create({
    data: {
      userId: f.ownerId,
      sandboxHostId: f.hostId,
      name: "transaction",
      lookupPrefix: randomUUID(),
      secretDigest: randomUUID(),
    },
  });
  const identity = {
    credentialKind: "hostToken" as const,
    tokenId: token.id,
    hostId: f.hostId,
    userId: f.ownerId,
    expiresAt: null,
  };
  expect((await revalidateSandboxHostIdentity(identity)).status).toBe("active");
  const status = await db.prisma.$transaction(async (tx) => {
    await tx.hostToken.update({ where: { id: token.id }, data: { revokedAt: new Date() } });
    // A global connection would still see active; only this transaction sees
    // its uncommitted revoke, without needing an extra pool permit.
    return revalidateSandboxHostIdentity(identity, new Date(), tx);
  });
  // The revoke is an explicit verdict the daemon stops its VMs on.
  expect(status).toEqual({ status: "inactive", reason: "credential_revoked" });
});

it("3A SDK revoke waits for owner while K remains free", async () => {
  const { revokeSdkKey } = await import("../../../../packages/api/src/sandbox/services/sdk-keys");
  const f = await seed();
  const held = db.pauseAt("root", { before: "$transaction.commit" });
  const root = db.run("root", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${f.ownerId} FOR UPDATE`;
    }),
  );
  await held.waitReached();
  const revoking = db.run("revoke", () =>
    revokeSdkKey({ kind: "session", ownerId: f.ownerId }, { id: f.keyId }),
  );
  try {
    expect((await db.waitUntilBlocked("revoke", { by: "root" })).query).toMatch(
      /FROM "user".*FOR SHARE/,
    );
    await db.inspect.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sdk_key WHERE id = ${f.keyId} FOR UPDATE NOWAIT`;
    });
  } finally {
    held.release();
  }
  await root;
  await revoking;
  expect(
    (await db.inspect.sdkKey.findUniqueOrThrow({ where: { id: f.keyId } })).revokedAt,
  ).not.toBeNull();
});

it("R1-1 expiry opens only one transaction despite many historical stopped/failed creates", async () => {
  const f = await seed();
  const base = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandboxId } });
  const past = new Date(Date.now() - 60_000);
  const states = ["STOPPED", "REQUESTED", "SCHEDULED", "PROVISIONING"] as const;
  const history = Array.from({ length: 96 }, (_, i) => ({
    hostOwnerId: base.hostOwnerId,
    userId: base.userId,
    sandboxHostId: base.sandboxHostId,
    templateId: base.templateId,
    templateRevisionId: base.templateRevisionId,
    originalSelector: base.originalSelector,
    originPoolId: null,
    originHostId: base.originHostId,
    generation: base.generation,
    id: `000-history-${i}-${randomUUID()}`,
    state: states[i % states.length]!,
    liveResourcesHeld: false,
    leaseExpiresAt: past,
  }));
  await db.inspect.sandbox.createMany({ data: history });
  await db.inspect.sandboxOperation.createMany({
    data: history.map((row) => ({
      userId: f.ownerId,
      sandboxId: row.id,
      kind: "CREATE_SANDBOX",
      state: "FAILED",
      generation: row.generation,
      idempotencyKey: `failed-${row.id}`,
      ...requestDigestMetadata(),
      digestContext: digestContextSnapshot(
        { domain: REQUEST_DIGEST_DOMAIN },
        { generation: row.generation },
      ),
      requestBodyHash: "a".repeat(64),
    })),
  });
  await db.inspect.sandboxOperation.update({
    where: { id: f.operationId },
    data: { state: "SUCCEEDED" },
  });
  await db.inspect.outboxEvent.update({
    where: { id: f.eventId },
    data: { processedAt: new Date() },
  });
  await db.inspect.sandbox.update({
    where: { id: f.sandboxId },
    data: { state: "READY", leaseExpiresAt: past },
  });
  const { reclaimExpiredSandboxLeases } = await import("@wssp/api/sandbox/lease");
  const relay = await import("@wssp/api/sandbox/relay-fence");
  // Transparent counter: every selected candidate still runs its real PG
  // transaction, including owner/H/S locks; no transaction is stubbed out.
  const transactions = vi.spyOn(relay, "relayTransaction");
  try {
    expect(await reclaimExpiredSandboxLeases(clock, 8)).toBe(1);
    expect(transactions).toHaveBeenCalledTimes(1);
    expect(
      await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandboxId } }),
    ).toMatchObject({ state: "STOPPING", generation: base.generation + 1 });
    transactions.mockClear();
    expect(await reclaimExpiredSandboxLeases(clock, 8)).toBe(0);
    expect(transactions).not.toHaveBeenCalled();
  } finally {
    transactions.mockRestore();
  }
});

it.each(["old-generation", "sent", "processed"] as const)(
  "R1-1 expiry skips provisioning whose outbox is %s without opening a transaction",
  async (mode) => {
    const f = await seed();
    await db.inspect.sandbox.update({
      where: { id: f.sandboxId },
      data: {
        leaseExpiresAt: new Date(Date.now() - 60_000),
        generation: mode === "old-generation" ? 2 : 1,
      },
    });
    await db.inspect.outboxEvent.update({
      where: { id: f.eventId },
      data: {
        ...(mode === "sent" ? { sentAt: new Date() } : {}),
        ...(mode === "processed" ? { processedAt: new Date() } : {}),
      },
    });
    const { reclaimExpiredSandboxLeases } = await import("@wssp/api/sandbox/lease");
    const relay = await import("@wssp/api/sandbox/relay-fence");
    const transactions = vi.spyOn(relay, "relayTransaction");
    try {
      expect(await reclaimExpiredSandboxLeases(clock, 8)).toBe(0);
      expect(transactions).not.toHaveBeenCalled();
      expect(
        await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandboxId } }),
      ).toMatchObject({ state: "REQUESTED", liveResourcesHeld: true });
    } finally {
      transactions.mockRestore();
    }
  },
);

it.each([
  { kind: "RECONNECT_SANDBOX", state: "QUEUED" },
  { kind: "RECONNECT_SANDBOX", state: "DISPATCHED" },
  { kind: "CREATE_SANDBOX", state: "UNKNOWN_OUTCOME" },
  { kind: "RECONNECT_SANDBOX", state: "UNKNOWN_OUTCOME" },
] as const)("R1-1 reaper preserves pending $kind expiry from $state", async ({ kind, state }) => {
  const f = await seed();
  const possible = state !== "QUEUED";
  await db.inspect.sandboxOperation.update({
    where: { id: f.operationId },
    data: {
      kind,
      state,
      ...(possible
        ? { dispatchAttempt: 1, dispatchedHostId: f.hostId, dispatchedConnectionEpoch: 1 }
        : {}),
    },
  });
  await db.inspect.sandbox.update({
    where: { id: f.sandboxId },
    data: {
      ...(kind === "RECONNECT_SANDBOX" ? { state: "STOPPED" } : {}),
      leaseExpiresAt: new Date(Date.now() - 60_000),
    },
  });
  const { reclaimExpiredSandboxLeases } = await import("@wssp/api/sandbox/lease");
  expect(await reclaimExpiredSandboxLeases(clock)).toBe(possible ? 1 : 0);
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operationId } }),
  ).toMatchObject({ state: "FAILED", errorCode: "lease_expired" });
  expect(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandboxId } })).toMatchObject({
    state: possible ? "STOPPING" : "STOPPED",
    liveResourcesHeld: possible,
  });
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } })).liveCount,
  ).toBe(possible ? 1 : 0);
  expect(
    await db.inspect.sandboxOperation.count({ where: { userId: f.ownerId, kind: "KILL_SANDBOX" } }),
  ).toBe(possible ? 1 : 0);
});

it.each(["missing", "restored"] as const)(
  "creating key dispatch survives %s future selected pool grant",
  async (grant) => {
    const f = await seed("pool");
    const sandbox = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandboxId } });
    await db.inspect.sdkKey.update({
      where: { id: f.keyId },
      data: {
        resourceMode: "ALLOWLIST",
        HostAllowlist: { create: { sandboxHostId: f.hostId } },
        RevisionAllowlist: { create: { templateRevisionId: sandbox.templateRevisionId } },
      },
    });
    if (grant === "restored")
      await db.inspect.sdkKeyPoolAllowlist.create({
        data: {
          poolOwnerId: f.ownerId,
          userId: f.ownerId,
          sdkKeyId: f.keyId,
          poolId: sandbox.originPoolId!,
        },
      });
    const sent = await processSandboxOutboxBatch(clock);
    expect(sent).toBe(1);
    expect(manager.dispatchOperation).toHaveBeenCalledTimes(1);
    const operation = await db.inspect.sandboxOperation.findUniqueOrThrow({
      where: { id: f.operationId },
    });
    expect(operation.state).toBe("DISPATCHED");
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } })).liveCount,
    ).toBe(1);
  },
);

it("pool disconnect after acceptance keeps the allocation and slot pending without rerouting", async () => {
  const f = await seed("pool");
  const before = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandboxId } });
  vi.mocked(manager.isHostConnected).mockReturnValueOnce(false);
  expect(await processSandboxOutboxBatch(clock)).toBe(0);
  expect(manager.dispatchOperation).not.toHaveBeenCalled();
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operationId } }),
  ).toMatchObject({ state: "QUEUED", dispatchAttempt: 0 });
  const after = await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandboxId } });
  expect(after).toMatchObject({
    sandboxHostId: before.sandboxHostId,
    originPoolId: before.originPoolId,
    currentPlacementId: before.currentPlacementId,
    liveResourcesHeld: true,
  });
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } })).liveCount,
  ).toBe(1);
  expect(await processSandboxOutboxBatch(clock)).toBe(1);
});

it("B5 corrupt allocation permits lease cleanup without starving another owner's dispatch", async () => {
  const fixtures = [await seed(), await seed()].sort((a, b) =>
    a.sandboxId.localeCompare(b.sandboxId),
  );
  const corrupt = fixtures[0]!;
  const healthy = fixtures[1]!;
  for (const f of fixtures) {
    await db.inspect.sandboxOperation.update({
      where: { id: f.operationId },
      data: { state: "SUCCEEDED" },
    });
    await db.inspect.outboxEvent.update({
      where: { id: f.eventId },
      data: { processedAt: new Date() },
    });
    await db.inspect.sandbox.update({
      where: { id: f.sandboxId },
      data: {
        state: "READY",
        leaseExpiresAt: new Date(Date.now() - 60_000),
        leaseExpireAction: "STOP",
      },
    });
  }
  await db.inspect.sandboxPlacement.updateMany({
    where: { sandboxId: corrupt.sandboxId },
    data: { memoryMiB: 1024 },
  });
  const { reclaimExpiredSandboxLeases } = await import("@wssp/api/sandbox/lease");
  // Cleanup needs the pinned identity, not the corrupt size. Both owners progress
  // with a one-item page, and neither hold can be freed before a host result.
  expect(await reclaimExpiredSandboxLeases(clock, 1)).toBe(2);
  for (const f of fixtures) {
    expect(
      await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandboxId } }),
    ).toMatchObject({
      state: "STOPPING",
      liveResourcesHeld: true,
      generation: 2,
    });
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } }),
    ).toMatchObject({
      liveCount: 1,
      memoryReservedMiB: vmLiveMemoryChargeMiB(2048),
    });
  }
  expect(await processSandboxOutboxBatch(clock)).toBe(2);
  expect(
    await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: healthy.sandboxId, kind: "STOP_SANDBOX" },
    }),
  ).toMatchObject({ state: "DISPATCHED" });
  const payload = (
    await db.inspect.outboxEvent.findFirstOrThrow({
      where: { aggregateId: corrupt.sandboxId, eventType: "sandbox.stop_requested" },
    })
  ).payload;
  expect(payload).not.toHaveProperty("memoryMiB");
  expect(payload).not.toHaveProperty("cpuCount");
});

it.each(["stop", "destroy"] as const)(
  "B5 owner can %s a corrupt allocation without launching or releasing it",
  async (action) => {
    const f = await seed();
    await db.inspect.sandboxOperation.update({
      where: { id: f.operationId },
      data: { state: "SUCCEEDED" },
    });
    await db.inspect.outboxEvent.update({
      where: { id: f.eventId },
      data: { processedAt: new Date() },
    });
    await db.inspect.sandbox.update({ where: { id: f.sandboxId }, data: { state: "READY" } });
    await db.inspect.sandboxPlacement.updateMany({
      where: { sandboxId: f.sandboxId },
      data: { memoryMiB: 1024 },
    });
    const { stopSandbox, killSandbox } = await import("@wssp/api/sandbox/services/sandboxes");
    const receipt = await (action === "stop" ? stopSandbox : killSandbox)(
      { kind: "session", ownerId: f.ownerId },
      { id: f.sandboxId, idempotencyKey: randomUUID() },
    );
    expect(receipt).toMatchObject({ state: action === "stop" ? "QUEUED" : "STOPPING" });
    expect(await processSandboxOutboxBatch(clock)).toBe(1);
    expect(
      await db.inspect.sandboxOperation.findFirstOrThrow({
        where: {
          sandboxId: f.sandboxId,
          kind: action === "stop" ? "STOP_SANDBOX" : "KILL_SANDBOX",
        },
      }),
    ).toMatchObject({ state: "DISPATCHED" });
    expect(
      await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandboxId } }),
    ).toMatchObject({ state: "STOPPING", liveResourcesHeld: true });
  },
);

it.each(["10.6", "10.7"])(
  "B5 create refused by %s stores unsupported_capability on the sandbox",
  async (version) => {
    const f = await seed();
    await db.inspect.sandboxHost.update({
      where: { id: f.hostId },
      data: {
        relayProtocolVersion: version,
        relayProtocolEpoch: 1,
      },
    });
    vi.mocked(manager.dispatchOperation).mockResolvedValueOnce("refused_before_frame");
    expect(await processSandboxOutboxBatch(clock)).toBe(0);
    const operation = await db.inspect.sandboxOperation.findUniqueOrThrow({
      where: { id: f.operationId },
    });
    expect(operation).toMatchObject({ state: "FAILED", errorCode: "unsupported_capability" });
    expect(
      await db.inspect.sandbox.findUniqueOrThrow({ where: { id: f.sandboxId } }),
    ).toMatchObject({
      state: "ERROR",
      liveResourcesHeld: false,
      lastErrorCode: operation.errorCode,
      lastErrorDetail: operation.errorDetail,
    });
    expect(
      await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.hostId } }),
    ).toMatchObject({ liveCount: 0, memoryReservedMiB: 0 });
  },
);
