import { sandboxDiskSelect } from "../../../../packages/api/src/sandbox/disk-offload/disk-view";
import {
  acknowledgeFixtureExecutionConfigs,
  seedAcceptedOperation,
  seedLaunchHost,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, afterEach, expect, it, vi } from "vitest";
import { seedTemplateRevision } from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

const settings = vi.hoisted(() => ({ max: 86_400_000 }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    get SANDBOX_MAX_TIMEOUT_MS() {
      return settings.max;
    },
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("./session-manager.js", () => ({
  sandboxRelaySessionManager: {
    isHostConnected: vi.fn().mockReturnValue(true),
    dispatchOperation: vi.fn().mockResolvedValue("sent"),
    captureHostDispatchCredential: vi.fn(),
  },
}));

const db = await pgTestDatabase();
const { createSandbox, killSandbox, reconnectSandbox, setSandboxTimeout, stopSandbox } =
  await import("../../../../packages/api/src/sandbox/services/sandboxes");
const { reclaimExpiredSandboxLeases } = await import("@wssp/api/sandbox/lease");
const { leaseWireSchema } = await import("@wssp/api/sandbox/lease-wire");
const { toOperationDto, toSandboxDto } = await import("@wssp/api/sandbox/sdk-reads");
const { processSandboxOutboxBatch: processOutboxWithInstalledConfig } = await import(
  "./outbox-processor.js"
);
async function processSandboxOutboxBatch(
  ...args: Parameters<typeof processOutboxWithInstalledConfig>
) {
  await acknowledgeFixtureExecutionConfigs(db.inspect);
  return processOutboxWithInstalledConfig(...args);
}

const { applyOperationResult, applyOperationProgress, finishHostReconciliation } = await import(
  "./operation-handlers.js"
);
const { convergeInventoryEntry } = await import("./inventory-reconcile.js");
const owners: string[] = [];
const FP = `sha256:${"e".repeat(64)}`;

afterAll(() => db.close());
afterEach(async () => {
  settings.max = 86_400_000;
  await db.inspect.outboxEvent.updateMany({
    where: { userId: { in: owners }, processedAt: null },
    data: { processedAt: new Date() },
  });
});

async function fixture(options: { timeoutMs?: number; onTimeout?: "kill" | "stop" } = {}) {
  const ownerId = `lease-${randomUUID()}`;
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
  const owner = { kind: "session" as const, ownerId };
  let now = Date.now();
  const clock = () => new Date(now);
  const input = {
    template: "revision/" + template.id,
    sandboxHostId: host.id,
    idempotencyKey: `create-${randomUUID()}`,
    ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
    ...(options.onTimeout !== undefined ? { lifecycle: { onTimeout: options.onTimeout } } : {}),
  };
  const sandbox = await createSandbox(owner, input, clock);
  const operation = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: sandbox.id, kind: "CREATE_SANDBOX" },
  });
  // With the disk facts the public projection reads (disk-view.ts).
  const row = async () => ({
    ...(await db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } })),
    ...(await db.inspect.sandbox.findUniqueOrThrow({
      where: { id: sandbox.id },
      select: sandboxDiskSelect,
    })),
  });
  return {
    owner,
    host,
    template,
    input,
    sandbox,
    operation,
    clock,
    row,
    advance(ms: number) {
      now += ms;
    },
  };
}
type Fixture = Awaited<ReturnType<typeof fixture>>;
async function ack(f: Fixture, id = f.operation.id) {
  const op = await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id } });
  const event = await db.inspect.outboxEvent.findFirstOrThrow({
    where: { userId: f.owner.ownerId, payload: { path: ["operationId"], equals: id } },
  });
  const payload = event.payload as Record<string, unknown>;
  const lease = leaseWireSchema.safeParse(payload.lease);
  return {
    sender: { userId: f.owner.ownerId, hostId: f.host.id, connectionEpoch: 1 },
    operationId: id,
    sandboxId: f.sandbox.id,
    generation: op.generation,
    attempt: op.dispatchAttempt,
    state: "succeeded",
    receipt: {
      bodyHash: op.requestBodyHash,
      idempotencyKey: op.idempotencyKey,
      kind: String(payload.kind),
    },
    result: {
      state:
        op.kind === "STOP_SANDBOX" ? "stopped" : op.kind === "KILL_SANDBOX" ? "deleted" : "ready",
      ...(lease.success ? { lease: lease.data } : {}),
    },
  };
}
async function dispatch(f: Fixture, id = f.operation.id) {
  // This lease-focused fixture starts with the separately tested durable config ACK.
  await db.inspect.sandboxExecutionConfig.updateMany({
    where: { sandboxId: f.sandbox.id, userId: f.owner.ownerId },
    data: { acknowledgedEpoch: 1, acknowledgedAt: new Date() },
  });
  await processSandboxOutboxBatch(f.clock);
  return ack(f, id);
}
async function ready(f: Fixture) {
  expect(await applyOperationResult(await dispatch(f), f.clock)).toEqual({ written: true });
}

it.each(["REQUESTED", "SCHEDULED", "PROVISIONING", "RECOVERED", "READY"] as const)(
  "D2 stop from %s fences create, holds UNKNOWN capacity and releases once on stopped proof",
  async (state) => {
    const f = await fixture();
    const staleCreate = await dispatch(f);
    if (state === "READY") await applyOperationResult(staleCreate, f.clock);
    else await db.inspect.sandbox.update({ where: { id: f.sandbox.id }, data: { state } });
    const stop = await stopSandbox(f.owner, { id: f.sandbox.id, idempotencyKey: "boot-stop" });
    const row = await f.row();
    expect(row).toMatchObject({
      state: "STOPPING",
      generation: f.sandbox.generation + 1,
      liveResourcesHeld: true,
    });
    expect(
      await stopSandbox(f.owner, { id: f.sandbox.id, idempotencyKey: "boot-stop" }),
    ).toMatchObject({ operationId: stop.operationId });
    expect(await applyOperationResult(staleCreate, f.clock)).toEqual({ written: false });
    const result = await dispatch(f, stop.operationId);
    expect(
      await applyOperationResult(
        {
          ...result,
          state: "unknown_outcome",
          result: undefined,
          error: { code: "unknown_outcome", message: "boot stop uncertain" },
        },
        f.clock,
      ),
    ).toEqual({ written: true });
    expect(await f.row()).toMatchObject({
      state: "STOPPING",
      liveResourcesHeld: true,
      generation: row.generation,
    });
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
    ).toBe(1);
    expect(await applyOperationResult(result, f.clock)).toEqual({ written: true });
    expect(await applyOperationResult(result, f.clock)).toEqual({ written: false });
    expect(await f.row()).toMatchObject({
      state: "STOPPED",
      liveResourcesHeld: false,
      sandboxHostId: f.host.id,
    });
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
    ).toBe(0);
    await reconnectSandbox(
      f.owner,
      { id: f.sandbox.id, mode: "cold", idempotencyKey: "start-original" },
      f.clock,
    );
    expect(await f.row()).toMatchObject({
      state: "STOPPED",
      liveResourcesHeld: true,
      generation: row.generation + 1,
    });
  },
);

it("D2 stop before init releases live once but retains the root claim", async () => {
  const f = await fixture();
  const staleCreate = await dispatch(f);
  const stop = await stopSandbox(f.owner, { id: f.sandbox.id, idempotencyKey: "no-instance" });
  const result = await dispatch(f, stop.operationId);
  const absent = { ...result, result: { ...result.result, state: "absent" } };
  expect(await applyOperationResult(absent, f.clock)).toEqual({ written: true });
  expect(await applyOperationResult(absent, f.clock)).toEqual({ written: false });
  expect(await applyOperationResult(staleCreate, f.clock)).toEqual({ written: false });
  expect(await f.row()).toMatchObject({
    state: "STOPPED",
    liveResourcesHeld: false,
    sandboxHostId: f.host.id,
    diskReservationHeld: true,
  });
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
  ).toBe(0);
});

it.each(["receipt", "inventory"])(
  "D2 lease-expiry Stop before init retains the root via %s and releases live once",
  async (source) => {
    const f = await fixture({ timeoutMs: 1_000, onTimeout: "stop" });
    const createResult = await dispatch(f);
    f.advance(1_000);
    expect(
      await applyOperationResult(
        {
          ...createResult,
          state: "failed",
          result: undefined,
          error: { code: "host_effect_not_issued", message: "not initialized" },
        },
        f.clock,
      ),
    ).toEqual({ written: true });
    const cleanup = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: f.sandbox.id, kind: "STOP_SANDBOX" },
    });
    expect(await f.row()).toMatchObject({ state: "STOPPING", liveResourcesHeld: true });
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
    ).toBe(1);
    if (source === "receipt") {
      const result = await dispatch(f, cleanup.id);
      const absent = { ...result, result: { ...result.result, state: "absent" } };
      expect(await applyOperationResult(absent, f.clock)).toEqual({ written: true });
      expect(await applyOperationResult(absent, f.clock)).toEqual({ written: false });
    } else {
      const sender = { userId: f.owner.ownerId, hostId: f.host.id, connectionEpoch: 1 };
      const entry = {
        sandboxOwnerId: f.owner.ownerId,
        root: null,
        sandboxId: f.sandbox.id,
        state: "absent" as const,
      };
      expect(await convergeInventoryEntry(sender, entry, f.clock)).toEqual({ converged: true });
    }
    expect(await f.row()).toMatchObject({ state: "STOPPED", liveResourcesHeld: false });
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
    ).toBe(0);
    expect(await reclaimExpiredSandboxLeases(f.clock)).toBe(0);
  },
);

it("D2 inventory absence settles stop before init while retaining the unobserved root", async () => {
  const f = await fixture();
  await stopSandbox(f.owner, { id: f.sandbox.id, idempotencyKey: "inventory-no-instance" });
  const sender = { userId: f.owner.ownerId, hostId: f.host.id, connectionEpoch: 1 };
  const entry = {
    sandboxOwnerId: f.owner.ownerId,
    root: null,
    sandboxId: f.sandbox.id,
    state: "absent" as const,
  };
  expect(await convergeInventoryEntry(sender, entry, f.clock)).toEqual({ converged: true });
  expect(await f.row()).toMatchObject({
    state: "STOPPED",
    liveResourcesHeld: false,
    sandboxHostId: f.host.id,
    diskReservationHeld: true,
  });
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
  ).toBe(0);
  await convergeInventoryEntry(sender, entry, f.clock);
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
  ).toBe(0);
});

it.each(["stop", "kill"] as const)(
  "D2 %s-then-other under row-lock contention always preserves destroy intent",
  async (firstKind) => {
    const f = await fixture();
    const firstMutation = firstKind === "stop" ? stopSandbox : killSandbox;
    const secondMutation = firstKind === "stop" ? killSandbox : stopSandbox;
    const gate = db.pauseAt("first-teardown", { before: "$transaction.commit" });
    const first = db.run("first-teardown", async () => {
      await firstMutation(f.owner, { id: f.sandbox.id, idempotencyKey: "race-first" });
    });
    await gate.waitReached();
    const second = db
      .run("second-teardown", async () => {
        await secondMutation(f.owner, { id: f.sandbox.id, idempotencyKey: "race-second" });
      })
      .then(
        (value) => ({ value, error: null }),
        (error: unknown) => ({ value: null, error }),
      );
    try {
      expect(
        (await db.waitUntilBlocked("second-teardown", { by: "first-teardown" })).query,
      ).toMatch(/sandbox_host/);
    } finally {
      gate.release();
    }
    await first;
    const secondResult = await second;
    if (firstKind === "kill")
      expect(secondResult.error).toMatchObject({ data: { code: "sandbox.state_conflict" } });
    else expect(secondResult.error).toBeNull();
    const kill = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: f.sandbox.id, kind: "KILL_SANDBOX" },
    });
    expect(await f.row()).toMatchObject({
      state: "STOPPING",
      generation: kill.generation,
      liveResourcesHeld: true,
    });
    if (firstKind === "stop") {
      const firstReceipt = await db.inspect.sandboxOperation.findFirstOrThrow({
        where: { sandboxId: f.sandbox.id, idempotencyKey: "race-first" },
      });
      const stale = await ack(f, firstReceipt.id);
      expect(await applyOperationResult(stale, f.clock)).toEqual({ written: false });
    }
    expect(await applyOperationResult(await dispatch(f, kill.id), f.clock)).toEqual({
      written: true,
    });
    expect(await f.row()).toMatchObject({ state: "DELETED", liveResourcesHeld: false });
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
    ).toBe(0);
  },
);

it.each(["REQUESTED", "SCHEDULED", "PROVISIONING", "READY"] as const)(
  "E-43 unknown kill from %s keeps its slot until a retried kill proves deletion once",
  async (state) => {
    const f = await fixture();
    if (state === "READY") await ready(f);
    else await db.inspect.sandbox.update({ where: { id: f.sandbox.id }, data: { state } });
    await killSandbox(f.owner, { id: f.sandbox.id, idempotencyKey: "kill-first" });
    const first = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: f.sandbox.id, kind: "KILL_SANDBOX" },
    });
    const initial = await dispatch(f, first.id);
    await expect(
      killSandbox(f.owner, { id: f.sandbox.id, idempotencyKey: "still-running" }),
    ).rejects.toMatchObject({ data: { code: "sandbox.state_conflict" } });
    expect(
      await applyOperationResult(
        {
          ...initial,
          state: "unknown_outcome",
          result: undefined,
          error: { code: "unknown_outcome", message: "uncertain teardown" },
        },
        f.clock,
      ),
    ).toEqual({ written: true });
    expect(await f.row()).toMatchObject({ state: "STOPPING", liveResourcesHeld: true });
    const host = () => db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } });
    expect((await host()).liveCount).toBe(1);

    // Competing new idempotency keys serialize at the real owner/host locks.
    // Only one may supersede the UNKNOWN generation; its queued successor
    // must keep the other retry from revoking freshly admitted work.
    const retries = await Promise.allSettled(
      ["retry-a", "retry-b"].map((idempotencyKey) =>
        killSandbox(f.owner, { id: f.sandbox.id, idempotencyKey }),
      ),
    );
    expect(retries.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(retries.filter((r) => r.status === "rejected")).toHaveLength(1);
    const next = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: f.sandbox.id, kind: "KILL_SANDBOX", generation: first.generation + 1 },
    });
    expect(next.state).toBe("QUEUED");
    expect(await f.row()).toMatchObject({
      state: "STOPPING",
      liveResourcesHeld: true,
      generation: next.generation,
    });
    expect((await host()).liveCount).toBe(1);
    // A stale completion must never release the new generation's slot.
    expect(await applyOperationResult(initial, f.clock)).toEqual({ written: false });
    expect((await host()).liveCount).toBe(1);
    const completion = await dispatch(f, next.id);
    expect(await applyOperationResult(completion, f.clock)).toEqual({ written: true });
    expect(await f.row()).toMatchObject({ state: "DELETED", liveResourcesHeld: false });
    expect((await host()).liveCount).toBe(0);
    expect(await applyOperationResult(completion, f.clock)).toEqual({ written: false });
    await killSandbox(f.owner, { id: f.sandbox.id, idempotencyKey: next.idempotencyKey });
    expect((await host()).liveCount).toBe(0);
  },
);

it("an UNKNOWN kill cannot be superseded by stop and still recovers as a kill", async () => {
  const f = await fixture();
  await ready(f);
  await killSandbox(f.owner, { id: f.sandbox.id, idempotencyKey: "destroy-first" });
  const initial = await dispatch(
    f,
    (
      await db.inspect.sandboxOperation.findFirstOrThrow({
        where: { sandboxId: f.sandbox.id, idempotencyKey: "destroy-first" },
      })
    ).id,
  );
  await applyOperationResult(
    {
      ...initial,
      state: "unknown_outcome",
      result: undefined,
      error: { code: "unknown_outcome", message: "uncertain destroy" },
    },
    f.clock,
  );
  const before = await f.row();
  await expect(
    stopSandbox(f.owner, { id: f.sandbox.id, idempotencyKey: "unsafe-stop" }),
  ).rejects.toMatchObject({ data: { code: "sandbox.state_conflict" } });
  expect(await f.row()).toMatchObject({
    state: "STOPPING",
    generation: before.generation,
    liveResourcesHeld: true,
  });
  expect(
    await db.inspect.sandboxOperation.count({
      where: { sandboxId: f.sandbox.id, kind: "STOP_SANDBOX" },
    }),
  ).toBe(0);
  await killSandbox(f.owner, { id: f.sandbox.id, idempotencyKey: "destroy-retry" });
  expect(
    await applyOperationResult(
      await dispatch(
        f,
        (
          await db.inspect.sandboxOperation.findFirstOrThrow({
            where: { sandboxId: f.sandbox.id, idempotencyKey: "destroy-retry" },
          })
        ).id,
      ),
      f.clock,
    ),
  ).toEqual({
    written: true,
  });
  expect(await f.row()).toMatchObject({ state: "DELETED", liveResourcesHeld: false });
});

it.each(["stop", "kill"] as const)("E-43 an unknown stop can be recovered by %s", async (retry) => {
  const f = await fixture();
  await ready(f);
  const first = await stopSandbox(f.owner, { id: f.sandbox.id, idempotencyKey: "stop-first" });
  const initial = await dispatch(f, first.operationId);
  await applyOperationResult(
    {
      ...initial,
      state: "unknown_outcome",
      result: undefined,
      error: { code: "unknown_outcome", message: "uncertain stop" },
    },
    f.clock,
  );
  expect(await f.row()).toMatchObject({ state: "STOPPING", liveResourcesHeld: true });
  if (retry === "stop") await stopSandbox(f.owner, { id: f.sandbox.id, idempotencyKey: "retry" });
  else await killSandbox(f.owner, { id: f.sandbox.id, idempotencyKey: "retry" });
  const next = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: f.sandbox.id, idempotencyKey: "retry" },
  });
  const completion = await dispatch(f, next.id);
  expect(await applyOperationResult(completion, f.clock)).toEqual({ written: true });
  expect(await f.row()).toMatchObject({
    state: retry === "stop" ? "STOPPED" : "DELETED",
    liveResourcesHeld: false,
  });
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
  ).toBe(0);
  expect(await applyOperationResult(completion, f.clock)).toEqual({ written: false });
});

it("3C1 create defaults are 300000/kill; public endAt stays null until exact durable ACK", async () => {
  const f = await fixture();
  expect(f.sandbox).toMatchObject({
    leaseExpireAction: "DESTROY",
    leaseExpiresAt: new Date(f.clock().getTime() + 300000),
    leaseExpiresAtEffective: null,
  });
  expect(toSandboxDto(await f.row())).toMatchObject({
    endAt: null,
    startedAt: null,
    readyAt: null,
    lifecycle: { onTimeout: "kill", autoResume: false },
    sandboxDomain: null,
    portExposure: null,
  });
  expect(f.operation).toMatchObject({
    leaseAcceptedAt: f.clock(),
    leaseTimeoutMs: 300000,
    leaseRevisionAccepted: 1,
    leaseAcknowledgedAt: null,
  });
  const result = await dispatch(f);
  expect(await applyOperationProgress({ ...result, state: "running" })).toEqual({ written: true });
  // Operation RUNNING is worker progress, not a VM running-transition timestamp.
  expect((await f.row()).startedAt).toBeNull();
  expect(await applyOperationResult(result, f.clock)).toEqual({ written: true });
  const row = await f.row();
  expect(row.readyAt).toEqual(f.clock());
  expect(toSandboxDto(row).endAt).toBe(f.operation.leaseExpiresAtAccepted?.toISOString());
  const operation = await db.inspect.sandboxOperation.findUniqueOrThrow({
    where: { id: f.operation.id },
  });
  expect(toOperationDto(operation).leaseIntent).toMatchObject({
    acknowledgedAt: f.clock().toISOString(),
    acknowledgedAttempt: 1,
    acknowledgedEpoch: 1,
    onTimeout: "kill",
  });
});

it.each([
  "generation",
  "attempt",
  "epoch",
  "bodyHash",
  "revision",
  "deadline",
  "action",
  "state",
] as const)(
  "3C1 exact ACK refuses mismatched %s without effective lease or durable ACK",
  async (field) => {
    const f = await fixture();
    const good = await dispatch(f);
    const bad = structuredClone(good);
    if (field === "generation") bad.generation += 1;
    if (field === "attempt") bad.attempt += 1;
    if (field === "epoch") bad.sender.connectionEpoch += 1;
    if (field === "bodyHash") bad.receipt.bodyHash = "f".repeat(64);
    if (!bad.result.lease) throw new Error("fixture missing lease");
    if (field === "revision") bad.result.lease.revision += 1;
    if (field === "deadline") bad.result.lease.deadlineUnixMs += 1;
    if (field === "action") bad.result.lease.action = "stop";
    if (field === "state") bad.result.state = "stopped";
    // Another attempt, generation, epoch or request is not this receipt: it
    // is refused and the real one still applies. Evidence that contradicts
    // the immutable request (WP0) can never apply, so the exact receipt takes
    // the server's verdict: an uncertain create (FAILED, teardown queued).
    const binding = ["generation", "attempt", "epoch", "bodyHash"].includes(field);
    expect(await applyOperationResult(bad, f.clock)).toEqual({ written: !binding });
    expect((await f.row()).leaseExpiresAtEffective).toBeNull();
    const operation = await db.inspect.sandboxOperation.findUniqueOrThrow({
      where: { id: f.operation.id },
    });
    expect(operation.leaseAcknowledgedAt).toBeNull();
    if (binding) expect(await applyOperationResult(good, f.clock)).toEqual({ written: true });
    else {
      expect(operation).toMatchObject({ state: "FAILED", errorCode: "unknown_outcome" });
      expect(await applyOperationResult(good, f.clock)).toEqual({ written: false });
    }
  },
);

it("3C1 READY connect is extend-only, keeps generation/slot/timing and ACKs a no-op extension", async () => {
  const f = await fixture({ timeoutMs: 600000, onTimeout: "stop" });
  await ready(f);
  const before = await f.row();
  const warm = await reconnectSandbox(
    f.owner,
    { id: before.id, timeoutMs: 1, idempotencyKey: "warm" },
    f.clock,
  );
  expect(await f.row()).toMatchObject({
    generation: before.generation,
    leaseRevision: 2,
    leaseExpiresAt: before.leaseExpiresAt,
    leaseExpiresAtEffective: before.leaseExpiresAtEffective,
    liveResourcesHeld: true,
    readyAt: before.readyAt,
  });
  expect(await applyOperationResult(await dispatch(f, warm.operationId), f.clock)).toEqual({
    written: true,
  });
  expect(await f.row()).toMatchObject({ readyAt: before.readyAt, leaseRevisionEffective: 2 });
  expect(
    (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
  ).toBe(1);
});

it("3C1 relative setTimeout shortens; reversed ACKs preserve latest effective lease and each exact intent ACK", async () => {
  const f = await fixture({ onTimeout: "stop" });
  await ready(f);
  const a = await reconnectSandbox(
    f.owner,
    { id: f.sandbox.id, timeoutMs: 600000, idempotencyKey: "extend" },
    f.clock,
  );
  const b = await setSandboxTimeout(
    f.owner,
    { id: f.sandbox.id, timeoutMs: 1000, idempotencyKey: "shorten" },
    f.clock,
  );
  expect(b.leaseExpiresAt).toEqual(new Date(f.clock().getTime() + 1000));
  await processSandboxOutboxBatch(f.clock);
  const newer = await db.inspect.sandboxOperation.findUniqueOrThrow({
    where: { userId_idempotencyKey: { userId: f.owner.ownerId, idempotencyKey: "shorten" } },
  });
  expect(await applyOperationResult(await ack(f, newer.id), f.clock)).toEqual({ written: true });
  expect(await applyOperationResult(await ack(f, a.operationId), f.clock)).toEqual({
    written: true,
  });
  expect(await f.row()).toMatchObject({
    leaseRevisionEffective: 3,
    leaseExpiresAtEffective: b.leaseExpiresAt,
    leaseExpireAction: "STOP",
  });
  expect(
    (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: a.operationId } }))
      .leaseAcknowledgedAt,
  ).not.toBeNull();
  f.advance(1000);
  expect(await reclaimExpiredSandboxLeases(f.clock)).toBe(1);
  expect((await f.row()).state).toBe("STOPPING");
  // D5: the expiry writer stores the indexed operationId column.
  const stop = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: f.sandbox.id, kind: "STOP_SANDBOX" },
    orderBy: { createdAt: "desc" },
  });
  expect(
    await db.inspect.outboxEvent.findMany({
      where: { aggregateId: f.sandbox.id, operationId: stop.id },
      select: { eventType: true },
    }),
  ).toEqual([{ eventType: "sandbox.stop_requested" }]);
});

it.each(["connect", "setTimeout"] as const)(
  "3C1 expired effective lease refuses %s without recording a new intent",
  async (action) => {
    const f = await fixture({ timeoutMs: 10 });
    await ready(f);
    f.advance(10);
    const input = { id: f.sandbox.id, timeoutMs: 300000, idempotencyKey: "expired" };
    await expect(
      action === "connect"
        ? reconnectSandbox(f.owner, input, f.clock)
        : setSandboxTimeout(f.owner, input, f.clock),
    ).rejects.toMatchObject({ code: "CONFLICT" });
    expect(await db.inspect.sandboxOperation.count({ where: { userId: f.owner.ownerId } })).toBe(1);
    expect((await f.row()).leaseRevision).toBe(1);
  },
);

it("3C1 accepted-once duration replays after time and a lowered deployment max; changed body conflicts", async () => {
  const f = await fixture({ timeoutMs: 600000 });
  f.advance(3_600_000);
  expect((await createSandbox(f.owner, f.input, f.clock)).id).toBe(f.sandbox.id);
  const prior = await db.inspect.sandboxOperation.findUniqueOrThrow({
    where: { id: f.operation.id },
  });
  expect(prior.leaseExpiresAtAccepted).toEqual(f.operation.leaseExpiresAtAccepted);
  expect(prior.leaseAcceptedAt).toEqual(f.operation.leaseAcceptedAt);
  settings.max = 300000;
  expect((await createSandbox(f.owner, f.input, f.clock)).id).toBe(f.sandbox.id);
  await expect(
    createSandbox(f.owner, { ...f.input, timeoutMs: 600001 }, f.clock),
  ).rejects.toMatchObject({ code: "CONFLICT" });
  await expect(
    createSandbox(f.owner, { ...f.input, idempotencyKey: "new" }, f.clock),
  ).rejects.toMatchObject({ code: "BAD_REQUEST" });
  expect(await db.inspect.sandboxOperation.count({ where: { userId: f.owner.ownerId } })).toBe(1);
});

it("3C1 STOPPED connect boots retained disk on original host with a new generation and fresh timings", async () => {
  const f = await fixture({ onTimeout: "stop" });
  await ready(f);
  const stop = await stopSandbox(f.owner, { id: f.sandbox.id, idempotencyKey: "stop" });
  expect(await applyOperationResult(await dispatch(f, stop.operationId), f.clock)).toEqual({
    written: true,
  });
  // Retirement and cached-image removal are not cold-boot scheduling vetoes.
  await db.inspect.sandboxTemplateRevision.update({
    where: { id: f.template.id },
    data: { retiredAt: f.clock() },
  });
  await expect(
    reconnectSandbox(f.owner, { id: f.sandbox.id, mode: "warm", idempotencyKey: "wrong" }, f.clock),
  ).rejects.toMatchObject({ code: "CONFLICT" });
  f.advance(2000);
  const cold = await reconnectSandbox(
    f.owner,
    { id: f.sandbox.id, idempotencyKey: "cold" },
    f.clock,
  );
  expect(await f.row()).toMatchObject({
    sandboxHostId: f.host.id,
    generation: 3,
    startedAt: null,
    readyAt: null,
    leaseExpiresAtEffective: null,
    leaseExpireAction: "STOP",
    liveResourcesHeld: true,
  });
  expect(await applyOperationResult(await dispatch(f, cold.operationId), f.clock)).toEqual({
    written: true,
  });
  expect((await f.row()).readyAt).toEqual(f.clock());
});

it("3C1 connect waits on H before S and computes its deadline only after the lock wait", async () => {
  const f = await fixture();
  await ready(f);
  const held = db.pauseAt("holder", { before: "$transaction.commit" });
  const holder = db.run("holder", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${f.host.id} FOR UPDATE`;
    }),
  );
  await held.waitReached();
  const connecting = db.run("connect", () =>
    reconnectSandbox(
      f.owner,
      { id: f.sandbox.id, timeoutMs: 600000, idempotencyKey: "blocked" },
      f.clock,
    ),
  );
  try {
    expect((await db.waitUntilBlocked("connect", { by: "holder" })).query).toMatch(/sandbox_host/);
    await db.inspect.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_instance WHERE id = ${f.sandbox.id} FOR UPDATE NOWAIT`;
    });
    f.advance(1000);
  } finally {
    held.release();
  }
  await holder;
  const result = await connecting;
  const op = await db.inspect.sandboxOperation.findUniqueOrThrow({
    where: { id: result.operationId },
  });
  expect(op.leaseAcceptedAt).toEqual(f.clock());
  expect(op.leaseExpiresAtAccepted).toEqual(new Date(f.clock().getTime() + 600000));
});

it("3C1 concurrent connect/shorten serialize under H/S and persist operation, lease and outbox in one transaction", async () => {
  const f = await fixture();
  await ready(f);
  const held = db.pauseAt("shorten", { before: "$transaction.commit" });
  const shortening = db.run("shorten", () =>
    setSandboxTimeout(
      f.owner,
      { id: f.sandbox.id, timeoutMs: 1000, idempotencyKey: "short" },
      f.clock,
    ),
  );
  await held.waitReached();
  const connecting = db.run("connect", () =>
    reconnectSandbox(
      f.owner,
      { id: f.sandbox.id, timeoutMs: 500, idempotencyKey: "after-short" },
      f.clock,
    ),
  );
  try {
    expect((await db.waitUntilBlocked("connect", { by: "shorten" })).query).toMatch(/sandbox_host/);
    expect((await f.row()).leaseRevision).toBe(1);
    expect(
      await db.inspect.sandboxOperation.count({
        where: { userId: f.owner.ownerId, idempotencyKey: "short" },
      }),
    ).toBe(0);
    expect(
      await db.inspect.outboxEvent.count({
        where: { userId: f.owner.ownerId, payload: { path: ["idempotencyKey"], equals: "short" } },
      }),
    ).toBe(0);
  } finally {
    held.release();
  }
  await shortening;
  await connecting;
  // The previously effective five-minute lease bounds extend-only connect,
  // even though a newer shortening is requested and still unacknowledged.
  expect(await f.row()).toMatchObject({
    leaseRevision: 3,
    leaseExpiresAt: f.operation.leaseExpiresAtAccepted,
  });
});

it.each([
  { lifecycle: { onTimeout: "pause" as const } },
  { lifecycle: { autoResume: true } },
  { network: { ingress: {} } },
])("3C1 unsupported capability creates no idempotency or receipt rows: %j", async (unsupported) => {
  const f = await fixture();
  await expect(
    createSandbox(f.owner, { ...f.input, idempotencyKey: "unsupported", ...unsupported }, f.clock),
  ).rejects.toMatchObject({ data: { code: "UNSUPPORTED_CAPABILITY" } });
  expect(await db.inspect.sandbox.count({ where: { userId: f.owner.ownerId } })).toBe(1);
  expect(
    await db.inspect.sandboxOperation.count({
      where: { userId: f.owner.ownerId, idempotencyKey: "unsupported" },
    }),
  ).toBe(0);
  expect(await db.inspect.sandboxActionReceipt.count({ where: { userId: f.owner.ownerId } })).toBe(
    0,
  );
  expect(await db.inspect.outboxEvent.count({ where: { userId: f.owner.ownerId } })).toBe(1);
});

it("3C1 inventory cannot promote an unsent lease intent to host-effective or ACK an operation", async () => {
  const f = await fixture();
  const { convergeInventoryEntry } = await import("./inventory-reconcile.js");
  const event = await db.inspect.outboxEvent.findFirstOrThrow({
    where: { aggregateId: f.sandbox.id },
  });
  const lease = leaseWireSchema.parse((event.payload as Record<string, unknown>).lease);
  await convergeInventoryEntry(
    { userId: f.owner.ownerId, hostId: f.host.id, connectionEpoch: 1 },
    {
      sandboxOwnerId: f.owner.ownerId,
      root: null,
      sandboxId: f.sandbox.id,
      state: "ready",
      lease: { generation: 1, lease, expired: false, expiryComplete: false, timerExpired: false },
    },
    f.clock,
  );
  expect((await f.row()).leaseExpiresAtEffective).toBeNull();
  expect(
    (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operation.id } }))
      .leaseAcknowledgedAt,
  ).toBeNull();
});

it("3C1 connect and setTimeout replay accepted-once durations after time, shortening, expiry and max changes", async () => {
  const f = await fixture({ onTimeout: "stop" });
  await ready(f);
  const connect = { id: f.sandbox.id, timeoutMs: 600000, idempotencyKey: "saved-connect" };
  const warm = await reconnectSandbox(f.owner, connect, f.clock);
  const renewal = { id: f.sandbox.id, timeoutMs: 600001, idempotencyKey: "saved-timeout" };
  await setSandboxTimeout(f.owner, renewal, f.clock);
  const before = await db.inspect.sandboxOperation.findMany({
    where: { userId: f.owner.ownerId },
    orderBy: { id: "asc" },
  });
  f.advance(3_600_000);
  settings.max = 300000;
  expect((await reconnectSandbox(f.owner, connect, f.clock)).operationId).toBe(warm.operationId);
  await setSandboxTimeout(f.owner, renewal, f.clock);
  expect(
    await db.inspect.sandboxOperation.findMany({
      where: { userId: f.owner.ownerId },
      orderBy: { id: "asc" },
    }),
  ).toEqual(before);
  await expect(
    reconnectSandbox(f.owner, { ...connect, timeoutMs: 600001 }, f.clock),
  ).rejects.toMatchObject({ code: "CONFLICT" });
  await expect(
    setSandboxTimeout(f.owner, { ...renewal, timeoutMs: 600002 }, f.clock),
  ).rejects.toMatchObject({ code: "CONFLICT" });
});

it.each(["connect", "setTimeout"] as const)(
  "3C1 failed %s outbox insertion rolls back accepted intent, lease revision and capacity",
  async (action) => {
    const f = await fixture({ onTimeout: "stop" });
    await ready(f);
    const before = await f.row();
    const gate = db.pauseAt("accept", { after: "outboxEvent.create" });
    const input = { id: f.sandbox.id, timeoutMs: 1000, idempotencyKey: "rolled-back" };
    const accepting = db.run("accept", async () => {
      if (action === "connect") await reconnectSandbox(f.owner, input, f.clock);
      else await setSandboxTimeout(f.owner, input, f.clock);
    });
    const rejected = expect(accepting).rejects.toThrow();
    await gate.waitReached();
    // Both writes are uncommitted together while the real transaction is parked.
    expect((await f.row()).leaseRevision).toBe(before.leaseRevision);
    expect(
      await db.inspect.sandboxOperation.count({
        where: { userId: f.owner.ownerId, idempotencyKey: input.idempotencyKey },
      }),
    ).toBe(0);
    gate.fail(new Error("fixture outbox rollback"));
    await rejected;
    expect(await f.row()).toEqual(before);
    expect(
      await db.inspect.outboxEvent.count({
        where: {
          userId: f.owner.ownerId,
          payload: { path: ["idempotencyKey"], equals: input.idempotencyKey },
        },
      }),
    ).toBe(0);
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
    ).toBe(1);
  },
);

it("3C1 default acceptance and ACK timestamps use the database clock despite application clock skew", async () => {
  const f = await fixture({ onTimeout: "stop" });
  await ready(f);
  const [before] = await db.inspect.$queryRaw<{ now: Date }[]>`SELECT clock_timestamp() AS now`;
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date("2000-01-01T00:00:00.000Z"));
  try {
    const created = await createSandbox(f.owner, { ...f.input, idempotencyKey: "db-create" });
    const connected = await reconnectSandbox(f.owner, {
      id: f.sandbox.id,
      idempotencyKey: "db-connect",
    });
    await setSandboxTimeout(f.owner, {
      id: f.sandbox.id,
      timeoutMs: 600000,
      idempotencyKey: "db-renew",
    });
    const operations = await db.inspect.sandboxOperation.findMany({
      where: {
        userId: f.owner.ownerId,
        idempotencyKey: { in: ["db-create", "db-connect", "db-renew"] },
      },
    });
    const [after] = await db.inspect.$queryRaw<{ now: Date }[]>`SELECT clock_timestamp() AS now`;
    expect(operations).toHaveLength(3);
    for (const op of operations) {
      expect(op.leaseAcceptedAt?.getTime()).toBeGreaterThanOrEqual(before!.now.getTime());
      expect(op.leaseAcceptedAt?.getTime()).toBeLessThanOrEqual(after!.now.getTime());
      expect(op.leaseExpiresAtAccepted?.getTime()).toBeGreaterThanOrEqual(
        (op.leaseAcceptedAt?.getTime() ?? 0) + (op.leaseTimeoutMs ?? 0),
      );
    }
    await processSandboxOutboxBatch(f.clock);
    const result = await ack(f, connected.operationId);
    expect(await applyOperationResult(result)).toEqual({ written: true });
    const confirmed = await db.inspect.sandboxOperation.findUniqueOrThrow({
      where: { id: connected.operationId },
    });
    expect(confirmed.leaseAcknowledgedAt?.getTime()).toBeGreaterThanOrEqual(before!.now.getTime());
    // Different create, same old host-bound shape; all three acceptance paths
    // share the database clock while preserving the explicit test-clock seam.
    expect(created.sandboxHostId).toBe(f.host.id);
  } finally {
    vi.useRealTimers();
  }
});

it("3C1 expiry rechecks the database clock after H/S despite an application clock ahead", async () => {
  const f = await fixture({ onTimeout: "stop" });
  await ready(f);
  const before = await f.row();
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date(before.leaseExpiresAt!.getTime() + 60_000));
  try {
    // The skewed scan finds this row, but the locked decision must refuse expiry.
    expect(await reclaimExpiredSandboxLeases()).toBe(0);
    expect(await f.row()).toMatchObject({
      state: "READY",
      generation: before.generation,
      leaseRevision: before.leaseRevision,
    });
    expect(
      await db.inspect.sandboxOperation.count({
        where: { sandboxId: f.sandbox.id, kind: "STOP_SANDBOX" },
      }),
    ).toBe(0);

    // An actually elapsed DB deadline still queues cleanup exactly once.
    await db.inspect.sandbox.update({
      where: { id: f.sandbox.id },
      data: { leaseExpiresAt: new Date("2000-01-01T00:00:00.000Z") },
    });
    expect(await reclaimExpiredSandboxLeases()).toBe(1);
    expect(await reclaimExpiredSandboxLeases()).toBe(0);
    expect(await f.row()).toMatchObject({ state: "STOPPING", generation: before.generation + 1 });
    expect(
      await db.inspect.sandboxOperation.count({
        where: { sandboxId: f.sandbox.id, kind: "STOP_SANDBOX" },
      }),
    ).toBe(1);
  } finally {
    vi.useRealTimers();
  }
});

// WP0 guard: a permanent verdict for an exact lifecycle receipt is never host
// evidence. It never releases the live hold a READY/effect-issued report
// claims (only absence proof does), and never adds a second, different
// terminal completion event.
it.each(["create", "cold reconnect", "warm reconnect", "stop", "kill"] as const)(
  "WP0 a permanent verdict for a %s receipt retains capacity and settles once",
  async (kind) => {
    const f = await fixture({ timeoutMs: 600000, onTimeout: "stop" });
    let operationId = f.operation.id;
    if (kind !== "create") {
      await ready(f);
      if (kind === "cold reconnect") {
        const stop = await stopSandbox(f.owner, { id: f.sandbox.id, idempotencyKey: "stop" });
        expect(await applyOperationResult(await dispatch(f, stop.operationId), f.clock)).toEqual({
          written: true,
        });
        f.advance(2000);
        operationId = (
          await reconnectSandbox(f.owner, { id: f.sandbox.id, idempotencyKey: "cold" }, f.clock)
        ).operationId;
      } else if (kind === "warm reconnect")
        operationId = (
          await reconnectSandbox(
            f.owner,
            { id: f.sandbox.id, timeoutMs: 900000, idempotencyKey: "warm" },
            f.clock,
          )
        ).operationId;
      else if (kind === "stop")
        operationId = (await stopSandbox(f.owner, { id: f.sandbox.id, idempotencyKey: kind }))
          .operationId;
      else {
        await killSandbox(f.owner, { id: f.sandbox.id, idempotencyKey: kind });
        operationId = (
          await db.inspect.sandboxOperation.findFirstOrThrow({
            where: { sandboxId: f.sandbox.id, kind: "KILL_SANDBOX" },
          })
        ).id;
      }
    }
    const exact = await dispatch(f, operationId);
    const before = await f.row();
    const host = () => db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } });
    const liveCount = (await host()).liveCount;
    expect(before.liveResourcesHeld).toBe(true);
    // Contradicts the request permanently: the wrong end state for the kind.
    const contradictory = {
      ...exact,
      result: { ...exact.result, state: kind === "stop" || kind === "kill" ? "ready" : "stopped" },
    };
    expect(await applyOperationResult(contradictory, f.clock)).toEqual({ written: true });
    const op = await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: operationId } });
    expect(op.state).toBe("FAILED");
    expect(op.errorCode).toBe(kind === "create" ? "unknown_outcome" : "protocol_error");
    const after = await f.row();
    expect(after.state).not.toBe(kind === "stop" ? "STOPPED" : "DELETED");
    expect(after.liveResourcesHeld).toBe(true);
    expect((await host()).liveCount).toBe(liveCount);
    // A replay changes nothing; the row is settled and confirmable.
    expect(await applyOperationResult(contradictory, f.clock)).toEqual({ written: false });
    expect(
      await db.inspect.webhookEvent.count({
        where: { operationId, type: "operation.completed" },
      }),
    ).toBeLessThanOrEqual(1);
    // Every verdict hold has a resolver. A warm re-arm stays READY under
    // lease reclaim; a create is torn down and a cold start stopped, and only
    // that teardown's proof releases the hold.
    if (kind === "warm reconnect") expect(after.state).toBe("READY");
    if (kind === "create" || kind === "cold reconnect") {
      const teardown = await db.inspect.sandboxOperation.findFirstOrThrow({
        where: {
          sandboxId: f.sandbox.id,
          kind: kind === "create" ? "KILL_SANDBOX" : "STOP_SANDBOX",
          generation: { gt: op.generation },
        },
      });
      expect(await applyOperationResult(await dispatch(f, teardown.id), f.clock)).toEqual({
        written: true,
      });
      expect((await f.row()).liveResourcesHeld).toBe(false);
      expect((await host()).liveCount).toBe(liveCount - 1);
    }
    // A stop/kill verdict is retried as a system teardown of the same kind at
    // the next generation; only that retry's proof releases the hold.
    if (kind === "stop" || kind === "kill") {
      expect(after).toMatchObject({ state: "STOPPING", generation: op.generation + 1 });
      const retry = await db.inspect.sandboxOperation.findFirstOrThrow({
        where: {
          sandboxId: f.sandbox.id,
          kind: kind === "stop" ? "STOP_SANDBOX" : "KILL_SANDBOX",
          generation: op.generation + 1,
        },
      });
      expect(retry).toMatchObject({ state: "QUEUED", teardownPriorState: "ERROR" });
      expect(await applyOperationResult(await dispatch(f, retry.id), f.clock)).toEqual({
        written: true,
      });
      expect(await f.row()).toMatchObject({
        state: kind === "stop" ? "STOPPED" : "DELETED",
        liveResourcesHeld: false,
      });
      expect((await host()).liveCount).toBe(liveCount - 1);
    }
  },
);

// Stop/kill resolver: a host-reported failed teardown leaves the VM possibly
// running and its live hold kept (ERROR). The server retries the same
// teardown as a bounded system operation; a retry's proof releases the hold,
// and a teardown that keeps failing stops retrying after TEARDOWN_RETRY_MAX.
it.each(["stop", "kill"] as const)(
  "a host-reported failed %s is retried at most twice, and a retry's proof releases the hold",
  async (kind) => {
    const f = await fixture({ timeoutMs: 600000, onTimeout: "stop" });
    await ready(f);
    const host = () => db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } });
    const liveCount = (await host()).liveCount;
    const teardownKind = kind === "stop" ? "STOP_SANDBOX" : "KILL_SANDBOX";
    if (kind === "stop") await stopSandbox(f.owner, { id: f.sandbox.id, idempotencyKey: kind });
    else await killSandbox(f.owner, { id: f.sandbox.id, idempotencyKey: kind });
    const fail = async () => {
      const pending = await db.inspect.sandboxOperation.findFirstOrThrow({
        where: { sandboxId: f.sandbox.id, kind: teardownKind, state: "QUEUED" },
        orderBy: { generation: "desc" },
      });
      const exact = await dispatch(f, pending.id);
      expect(
        await applyOperationResult(
          {
            ...exact,
            state: "failed",
            result: undefined,
            error: { code: "internal", message: "incus stop failed" },
          },
          f.clock,
        ),
      ).toEqual({ written: true });
      return pending;
    };
    const first = await fail();
    const teardowns = () =>
      db.inspect.sandboxOperation.findMany({
        where: { sandboxId: f.sandbox.id, kind: teardownKind },
        orderBy: { generation: "asc" },
      });
    // Failure 1 queued retry 1; retry 1 failing queued retry 2.
    await fail();
    expect((await teardowns()).map((op) => [op.state, op.idempotencyKey])).toEqual([
      ["FAILED", kind],
      ["FAILED", `teardown-retry:${f.sandbox.id}:${first.generation + 1}:1`],
      ["QUEUED", `teardown-retry:${f.sandbox.id}:${first.generation + 2}:2`],
    ]);
    if (kind === "kill") {
      // Retry 2 proves the VM deleted: the hold is released once.
      const last = (await teardowns()).at(-1)!;
      expect(await applyOperationResult(await dispatch(f, last.id), f.clock)).toEqual({
        written: true,
      });
      expect(await f.row()).toMatchObject({ state: "DELETED", liveResourcesHeld: false });
      expect((await host()).liveCount).toBe(liveCount - 1);
      return;
    }
    // Retry 2 failing too ends the chain: ERROR keeps the hold for the
    // reconnect census or a user kill, and nothing further is queued.
    await fail();
    expect(await teardowns()).toHaveLength(3);
    expect(await f.row()).toMatchObject({ state: "ERROR", liveResourcesHeld: true });
    expect((await host()).liveCount).toBe(liveCount);
    // A user's new teardown starts a new chain: its failure is retried again.
    await killSandbox(f.owner, { id: f.sandbox.id, idempotencyKey: "user-kill" });
    const kill = await db.inspect.sandboxOperation.findFirstOrThrow({
      where: { sandboxId: f.sandbox.id, kind: "KILL_SANDBOX" },
    });
    const exact = await dispatch(f, kill.id);
    await applyOperationResult(
      { ...exact, state: "failed", result: undefined, error: { code: "internal", message: "x" } },
      f.clock,
    );
    expect(
      await db.inspect.sandboxOperation.findFirst({
        where: { sandboxId: f.sandbox.id, kind: "KILL_SANDBOX", state: "QUEUED" },
      }),
    ).toMatchObject({ idempotencyKey: `teardown-retry:${f.sandbox.id}:${kill.generation + 1}:1` });
  },
);

// WP0: a recorded capture's finalizer owns its one terminal write. A user stop
// during finalization (real stop service: retire, then the stop's settlement)
// and the reconnect that follows must neither retire nor settle it.
it("WP0 a stop and reconnect during capture finalization leave the capture to its finalizer", async () => {
  const f = await fixture({ onTimeout: "stop" });
  await ready(f);
  const row = await f.row();
  const capture = await seedAcceptedOperation(db.inspect, {
    data: {
      userId: f.owner.ownerId,
      sandboxId: f.sandbox.id,
      kind: "CAPTURE_TEMPLATE",
      state: "RUNNING",
      generation: row.generation,
      idempotencyKey: "capture",
      requestBodyHash: "c".repeat(64),
      dispatchedHostId: f.host.id,
      dispatchedConnectionEpoch: 1,
      dispatchAttempt: 1,
    },
  });
  const revision = await db.inspect.sandboxTemplateRevision.findUniqueOrThrow({
    where: { id: f.template.id },
  });
  await db.inspect.sandboxTemplateCapture.create({
    data: {
      operationId: capture.id,
      userId: f.owner.ownerId,
      sandboxId: f.sandbox.id,
      templateId: revision.templateId,
      tag: "latest",
      hostId: f.host.id,
      hostOwnerId: f.owner.ownerId,
      state: "PENDING",
      architecture: "x86_64",
    },
  });
  const sender = { userId: f.owner.ownerId, hostId: f.host.id, connectionEpoch: 1 };
  expect(
    await applyOperationResult(
      {
        sender,
        operationId: capture.id,
        sandboxId: f.sandbox.id,
        generation: row.generation,
        attempt: 1,
        state: "succeeded",
        result: {
          fingerprint: `sha256:${"d".repeat(64)}`,
          sizeBytes: 4096,
          architecture: "x86_64",
        },
      },
      f.clock,
    ),
  ).toEqual({ written: true });
  const stop = await stopSandbox(f.owner, { id: f.sandbox.id, idempotencyKey: "stop" });
  expect(await applyOperationResult(await dispatch(f, stop.operationId), f.clock)).toEqual({
    written: true,
  });
  await db.inspect.sandboxHost.update({ where: { id: f.host.id }, data: { connectionEpoch: 2 } });
  expect(await finishHostReconciliation({ ...sender, connectionEpoch: 2 }, f.clock)).toBe(true);
  expect(
    await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: capture.id } }),
  ).toMatchObject({ state: "RUNNING", completedAt: null });
  expect(
    await db.inspect.webhookEvent.count({
      where: { operationId: capture.id, type: "operation.completed" },
    }),
  ).toBe(0);
  expect((await f.row()).state).toBe("STOPPED");
});
