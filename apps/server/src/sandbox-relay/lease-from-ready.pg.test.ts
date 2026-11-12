import { sandboxDiskSelect } from "../../../../packages/api/src/sandbox/disk-offload/disk-view";
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
const { createSandbox } = await import("../../../../packages/api/src/sandbox/services/sandboxes");
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

const { applyOperationResult } = await import("./operation-handlers.js");
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

async function fixture(
  options: { timeoutMs?: number; onTimeout?: "kill" | "stop"; imageCache?: boolean } = {},
) {
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
      ...(options.timeoutMs === 0 ? { daemonMaxLeaseMs: null } : {}),
      ...(options.imageCache === false
        ? {}
        : {
            daemonFeatures: {
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
            },
          }),
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
  const row = () => db.inspect.sandbox.findUniqueOrThrow({ where: { id: sandbox.id } });
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

const PROVISION_MAX_MS = 7_200_000;
const SKEW_MS = 60_000;

async function readyAck(f: Fixture, hostSkewMs: number) {
  const result = await dispatch(f);
  const lease = result.result.lease as { fromReadyMs?: number; deadlineUnixMs: number };
  expect(lease.fromReadyMs).toBeDefined();
  // The host settles deadline = readyAt + timeout on its own (skewed) clock.
  return {
    ...result,
    result: {
      ...result.result,
      lease: {
        ...lease,
        deadlineUnixMs: f.clock().getTime() + hostSkewMs + (lease.fromReadyMs ?? 0),
      },
    },
  };
}

it("M7 a lease-from-READY host gets a provisional backstop and no public deadline until its ACK", async () => {
  const f = await fixture({ timeoutMs: 600_000 });
  const row = await f.row();
  expect(row.leasePendingReady).toBe(true);
  expect(row.leaseExpiresAt?.getTime()).toBe(
    f.operation.leaseAcceptedAt!.getTime() + 600_000 + PROVISION_MAX_MS,
  );
  // The public DTO reads the disk facts too (offload C8: `sandboxDiskSelect`).
  const disk = await db.inspect.sandbox.findUniqueOrThrow({
    where: { id: row.id },
    select: sandboxDiskSelect,
  });
  expect(
    toSandboxDto({ ...row, ...disk, acceptedGraceSeconds: 0 } as never).lease.expiresAt,
  ).toBeNull();
  const op = await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operation.id } });
  expect(op.leaseFromReady).toBe(true);
  expect(toOperationDto(op).leaseIntent).toBeNull();
});

it.each([
  ["host clock 30 s fast", 30_000, true],
  ["host clock 30 s slow", -30_000, true],
  ["host clock 5 min fast", 5 * 60_000, false],
  ["host clock 5 min slow", -5 * 60_000, false],
] as const)(
  "M7 the READY-based ACK window tolerates %s within the skew",
  async (_name, skew, ok) => {
    const f = await fixture({ timeoutMs: 600_000 });
    const ack = await readyAck(f, skew);
    const outcome = await applyOperationResult(ack, f.clock);
    const row = await f.row();
    if (ok) {
      expect(outcome).toEqual({ written: true });
      expect(row.leasePendingReady).toBe(false);
      expect(row.leaseExpiresAt?.getTime()).toBe(ack.result.lease.deadlineUnixMs);
      expect(row.leaseExpiresAtEffective?.getTime()).toBe(ack.result.lease.deadlineUnixMs);
      const op = await db.inspect.sandboxOperation.findUniqueOrThrow({
        where: { id: f.operation.id },
      });
      expect(toOperationDto(op).leaseIntent?.endAt).toBe(
        new Date(ack.result.lease.deadlineUnixMs).toISOString(),
      );
    } else if (skew > 0) {
      // Ahead of the server clock: the window's upper edge reaches it later,
      // so the ACK is a pending observation, refused for now.
      expect(outcome).toEqual({ written: false });
      expect(row.leasePendingReady).toBe(true);
    } else {
      // Behind the fixed lower edge: it can never apply. The exact receipt
      // takes the uncertain-create verdict (WP0) instead of replaying.
      expect(outcome).toEqual({ written: true });
      expect(row.leaseExpiresAtEffective).toBeNull();
      expect(
        await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operation.id } }),
      ).toMatchObject({ state: "FAILED", errorCode: "unknown_outcome" });
    }
    expect(Math.abs(skew) <= SKEW_MS).toBe(ok);
  },
);

it("unlimited leases and runtimes without lease-from-ready retain the accepted deadline", async () => {
  settings.max = null as never;
  const unlimited = await fixture({ timeoutMs: 0 });
  expect((await unlimited.row()).leasePendingReady).toBe(false);
  settings.max = 86_400_000;
  const withoutImage = await fixture({ timeoutMs: 600_000, imageCache: false });
  const row = await withoutImage.row();
  expect(row.leasePendingReady).toBe(false);
  expect(row.leaseExpiresAt?.getTime()).toBe(
    withoutImage.operation.leaseAcceptedAt!.getTime() + 600_000,
  );
  const result = await dispatch(withoutImage);
  expect((result.result.lease as { fromReadyMs?: number }).fromReadyMs).toBeUndefined();
  expect(await applyOperationResult(result, withoutImage.clock)).toEqual({ written: true });
});
