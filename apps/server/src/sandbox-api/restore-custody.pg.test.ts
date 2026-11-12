/**
 * Full-boundary custody after a dashboard restore through another pool, on
 * real PostgreSQL and the real `/v1` routes: a key
 * minted ALL_OWNED with `poolMode = SELECTED {P}` creates through P; the
 * owner restores the offloaded sandbox through pool Q with the override.
 * The key then loses use (exec, files, processes, reconnect) at request time
 * and its pre-move exec is refused at dispatch revalidation, while history
 * reads and cleanup are retained. An ALL_OWNED + ALL_USABLE key keeps access
 * after the same move (control), with every same request accepted (202).
 * Terminal tickets are browser-session only (`mintTerminalTicket`), so no
 * SDK key can request one on this plane.
 */
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "restore-custody-fixture",
    RATE_LIMIT_RPC_POINTS: 10_000,
    RATE_LIMIT_RPC_WINDOW_SECONDS: 60,
    RATE_LIMIT_SDK_IP_POINTS: 30_000,
    RATE_LIMIT_SDK_KEY_POINTS: 10_000,
    RATE_LIMIT_SDK_OWNER_POINTS: 30_000,
    SANDBOX_MAX_TIMEOUT_MS: 86_400_000,
    TRANSFER_MAX_BYTES: 1_073_741_824,
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
vi.mock("rate-limiter-flexible", async (original) => {
  const actual = await original<typeof import("rate-limiter-flexible")>();
  return { ...actual, RateLimiterRedis: actual.RateLimiterMemory };
});
vi.mock("@hono/node-server/conninfo", () => ({
  getConnInfo: () => ({ remote: { address: "198.51.100.31" } }),
}));
vi.mock("../sandbox-relay/session-manager.js", () => ({
  sandboxRelaySessionManager: {
    isHostConnected: vi.fn().mockReturnValue(true),
    dispatchOperation: vi.fn().mockResolvedValue("sent"),
  },
}));

import { randomBytes, randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { mutationReceiptSchema, sdkErrorEnvelopeSchema } from "@wssp/sandbox-contracts";
import { Hono } from "hono";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const db = await pgTestDatabase();
afterAll(() => db.close());

const { createSandboxApi } = await import("./middleware");
const { checkAcceptedDispatchAuthority } = await import("@wssp/api/lib/sdk-key-access");
const { SERVICE_SCOPES } = await import("@wssp/api/lib/service-scopes");
const { reconnectSandbox } = await import(
  "../../../../packages/api/src/sandbox/services/sandboxes"
);
const { createSdkKey } = await import("../../../../packages/api/src/sandbox/services/sdk-keys");
const { leaseNow } = await import("@wssp/api/sandbox/lease");
const { readDiskWrapKeys } = await import("@wssp/api/sandbox/disk-offload/keys");
const { acknowledgeFixtureExecutionConfigs } = await import(
  "../../../../packages/api/src/sandbox/testing/resource-fixtures"
);
const { OFFLOAD_HOST_FEATURES, offloadSandboxForTest } = await import(
  "../../../../packages/api/src/sandbox/testing/offload-fixtures"
);
const { poolFixture } = await import("../../../../packages/api/src/sandbox/testing/pool-fixtures");
const { processSandboxOutboxBatch } = await import("../sandbox-relay/outbox-processor.js");

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

const app = new Hono().route("/v1", createSandboxApi());
const clock = () => new Date();

type Mode = "selected" | "allUsable";

/**
 * Pool P holds host one, pool Q host two (both offload-capable, owned by the
 * fixture owner). `selected` mints K2: ALL_OWNED with `poolMode = SELECTED
 * {P}`; `allUsable` mints the ALL_OWNED + ALL_USABLE control key.
 */
async function fixture(mode: Mode) {
  const f = await poolFixture(db);
  for (const host of [f.host, f.other]) {
    await db.inspect.sandboxHost.update({
      where: { id: host.id },
      data: {
        daemonFeatures: { ...OFFLOAD_HOST_FEATURES, egressOpen: true },
        daemonDiskOffload: true,
        relayProtocolVersion: "1.0",
        relayProtocolEpoch: 1,
      },
    });
    await db.inspect.sandboxHostStoragePool.updateMany({
      where: { sandboxHostId: host.id },
      data: { newRootsAllowed: true },
    });
  }
  await db.inspect.sandboxPoolMember.deleteMany({
    where: { poolId: f.pool.id, sandboxHostId: f.other.id },
  });
  const q = await db.inspect.sandboxPool.create({
    data: { userId: f.id, slug: "pool-q", label: "Pool Q" },
  });
  await db.inspect.sandboxPoolMember.create({
    data: { userId: f.id, hostOwnerId: f.id, poolId: q.id, sandboxHostId: f.other.id },
  });
  const key = await createSdkKey(f.owner, {
    name: mode === "selected" ? "k2-selected-pool" : "control-all-usable",
    resourceMode: "ALL_OWNED",
    ...(mode === "selected" ? { poolMode: "SELECTED" as const, poolIds: [f.pool.id] } : {}),
    hostIds: [],
    templateRevisionIds: [],
    // webhooks:write needs ALL_OWNED + ALL_USABLE; not under test here.
    scopes: SERVICE_SCOPES.filter((scope) => scope !== "webhooks:write"),
  });
  const keyRow = await db.inspect.sdkKey.findUniqueOrThrow({
    where: { id: key.key.id },
    select: { id: true, poolMode: true, resourceMode: true },
  });
  expect(keyRow).toMatchObject({
    resourceMode: "ALL_OWNED",
    poolMode: mode === "selected" ? "SELECTED" : "ALL_USABLE",
  });
  const request = (method: "GET" | "POST" | "DELETE", path: string, body?: unknown) =>
    app.request(`/v1${path}`, {
      method,
      headers: {
        authorization: `Bearer ${key.secret}`,
        ...(method === "GET"
          ? {}
          : { "content-type": "application/json", "idempotency-key": randomUUID() }),
      },
      ...(method === "GET" ? {} : { body: JSON.stringify(body ?? {}) }),
    });
  return { f, q, keyId: keyRow.id, request };
}

type Fixture = Awaited<ReturnType<typeof fixture>>;

const row = (id: string) => db.inspect.sandbox.findUniqueOrThrow({ where: { id } });
const op = (id: string) => db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id } });

async function receipt(response: Response) {
  expect(response.status, await response.clone().text()).toBe(202);
  return mutationReceiptSchema.parse(await response.json());
}

async function errorCode(response: Response): Promise<string | null> {
  if (response.status < 400) return null;
  return sdkErrorEnvelopeSchema.parse(await response.clone().json()).error.code;
}

async function expectForbidden(name: string, response: Response) {
  const text = `${name}: ${await response.clone().text()}`;
  expect(response.status, text).toBe(403);
  expect(await errorCode(response), text).toBe("FORBIDDEN");
}

/** Accepted (202): the same request the custody gate refuses K2 is
 * otherwise admissible, so K2's 403 is authorization, not state. */
async function expectAccepted(name: string, response: Response) {
  const text = `${name}: ${response.status} ${await response.clone().text()}`;
  expect(response.status, text).toBe(202);
  expect(await errorCode(response), text).toBeNull();
}

/** Marks every pending outbox event of `sandboxId` processed (fixture only). */
const settleOutbox = (sandboxId: string, except: string[] = []) =>
  db.inspect.outboxEvent.updateMany({
    where: { aggregateId: sandboxId, processedAt: null, id: { notIn: except } },
    data: { processedAt: new Date() },
  });

/** The `operationId`'s launch ran: the sandbox is READY on its bound host. */
async function markReady(sandboxId: string, operationId: string) {
  await db.inspect.sandboxOperation.update({
    where: { id: operationId },
    data: { state: "SUCCEEDED", completedAt: new Date(), result: { state: "ready" } },
  });
  await db.inspect.sandbox.update({
    where: { id: sandboxId },
    // A restore that reached READY no longer parks a stored disk.
    data: { state: "READY", diskOffloadId: null, leaseExpiresAt: new Date(Date.now() + 3_600_000) },
  });
  await acknowledgeFixtureExecutionConfigs(db.inspect);
  const config = await db.inspect.sandboxExecutionConfig.findFirstOrThrow({
    where: { sandboxId },
    orderBy: { generation: "desc" },
  });
  const target = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: config.hostId } });
  await db.inspect.sandboxExecutionConfig.update({
    where: { id: config.id },
    data: { acknowledgedEpoch: target.connectionEpoch, acknowledgedAt: new Date() },
  });
}

/**
 * The key creates through P over `/v1`; the sandbox runs; the key queues an
 * exec (left QUEUED, its outbox event unprocessed); the sandbox stops and is
 * offloaded; the owner restores it from the dashboard through Q with the
 * override; the restore's launch completes READY on host two.
 */
async function movedThroughQ(fx: Fixture) {
  const { f, q, keyId, request } = fx;
  const created = await receipt(
    await request("POST", "/sandboxes", { template: "base", poolId: f.pool.id }),
  );
  const createOp = await op(created.operationId);
  const sandboxId = createOp.sandboxId!;
  expect(createOp.authorizingKeyId).toBe(keyId);
  expect(await row(sandboxId)).toMatchObject({
    sandboxHostId: f.host.id,
    usagePoolId: f.pool.id,
    originPoolId: f.pool.id,
  });
  await settleOutbox(sandboxId);
  await markReady(sandboxId, created.operationId);

  const queued = await receipt(
    await request("POST", `/sandboxes/${sandboxId}/commands`, { argv: ["true"] }),
  );
  expect(await op(queued.operationId)).toMatchObject({
    kind: "RUN_COMMAND",
    state: "QUEUED",
    authorizingKeyId: keyId,
  });
  const execEvent = await db.inspect.outboxEvent.findFirstOrThrow({
    where: { aggregateId: sandboxId, processedAt: null },
    select: { id: true },
  });
  const before = await row(sandboxId);
  const dispatch = () =>
    db.prisma.$transaction((tx) =>
      checkAcceptedDispatchAuthority(
        {
          ownerId: f.id,
          principal: { kind: "sdkKey", keyId },
          context: {
            sandboxId,
            sandboxHostId: before.originHostId,
            templateRevisionId: before.templateRevisionId,
            originPoolId: before.originPoolId,
          },
        },
        tx,
      ),
    );
  expect(await dispatch()).toBe("active");

  // Stop + detach released host one's holds before the offload.
  await db.inspect.sandboxHost.updateMany({
    where: { id: f.host.id },
    data: { liveCount: 0, rootCount: 0, memoryReservedMiB: 0, vcpuReserved: 0 },
  });
  await db.inspect.sandbox.update({ where: { id: sandboxId }, data: { state: "STOPPED" } });
  await db.prisma.$transaction((tx) =>
    offloadSandboxForTest(tx, {
      userId: f.id,
      sandboxId,
      hostId: f.host.id,
      keys: readDiskWrapKeys() ?? undefined,
    }),
  );
  const restored = await reconnectSandbox(
    f.owner,
    { id: sandboxId, idempotencyKey: randomUUID(), poolId: q.id, overrideCreatorAllowlist: true },
    leaseNow,
  );
  expect(await row(sandboxId)).toMatchObject({
    state: "PROVISIONING",
    sandboxHostId: f.other.id,
    usagePoolId: q.id,
  });
  await settleOutbox(sandboxId, [execEvent.id]);
  await markReady(sandboxId, restored.operationId);
  return { sandboxId, execOperationId: queued.operationId, dispatch };
}

/** Guest use over `/v1` (exec, file read and stat, process list, reconnect). */
const guestUseRequests = (request: Fixture["request"], id: string) =>
  [
    ["exec", () => request("POST", `/sandboxes/${id}/commands`, { argv: ["true"] })],
    ["file read", () => request("POST", `/sandboxes/${id}/files/download`, { path: "/etc/hosts" })],
    ["file stat", () => request("POST", `/sandboxes/${id}/files/stat`, { path: "/etc" })],
    ["process list", () => request("POST", `/sandboxes/${id}/processes/list`, {})],
    ["reconnect", () => request("POST", `/sandboxes/${id}/reconnect`, { mode: "warm" })],
  ] as const;

describe("restore through another pool ends a SELECTED-pool key's use (§5a W1)", () => {
  it("K2 (ALL_OWNED, poolMode SELECTED {P}): use forbidden, history and cleanup kept", async () => {
    const fx = await fixture("selected");
    const { sandboxId, execOperationId, dispatch } = await movedThroughQ(fx);

    // Dispatch revalidation: the exec K2 queued before the move is refused.
    // (The restore's generation also supersedes it, so the real processor
    // never launches it either; the authority check is asserted directly.)
    expect(await dispatch()).toBe("inactive");
    await processSandboxOutboxBatch(clock);
    expect(await op(execOperationId)).toMatchObject({
      errorCode: "superseded",
      dispatchAttempt: 0,
      dispatchedHostId: null,
    });

    // Request time: every guest use is forbidden.
    for (const [name, send] of guestUseRequests(fx.request, sandboxId))
      await expectForbidden(name, await send());
    expect(
      await db.inspect.sandboxOperation.count({
        where: { sandboxId, kind: "RUN_COMMAND", authorizingKeyId: fx.keyId },
      }),
    ).toBe(1);

    // Retained: history reads, then stop and destroy.
    const read = await fx.request("GET", `/sandboxes/${sandboxId}`);
    expect(read.status, await read.clone().text()).toBe(200);
    const history = await fx.request("GET", `/operations/${execOperationId}`);
    expect(history.status, await history.clone().text()).toBe(200);
    await expectAccepted("stop", await fx.request("POST", `/sandboxes/${sandboxId}/stop`, {}));
    await expectAccepted("destroy", await fx.request("DELETE", `/sandboxes/${sandboxId}`, {}));
  });

  it("control: an ALL_OWNED + ALL_USABLE key keeps use after the same move", async () => {
    const fx = await fixture("allUsable");
    const { sandboxId, execOperationId, dispatch } = await movedThroughQ(fx);
    expect(await dispatch()).toBe("active");
    await processSandboxOutboxBatch(clock);
    expect((await op(execOperationId)).errorCode).toBe("superseded");
    for (const [name, send] of guestUseRequests(fx.request, sandboxId))
      await expectAccepted(name, await send());
  });
});
