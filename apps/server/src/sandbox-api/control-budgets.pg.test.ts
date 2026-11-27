import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { Hono } from "hono";
import { afterAll, expect, it, vi } from "vitest";
import {
  seedAcceptedOperation,
  seedLaunchHost,
  seedMintSession,
  seedSandboxInstance,
  seedTemplateRevision,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "cd".repeat(32),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "b5-http-fixture",
    RATE_LIMIT_RPC_POINTS: 100,
    RATE_LIMIT_RPC_WINDOW_SECONDS: 60,
    RATE_LIMIT_SDK_IP_POINTS: 300,
    RATE_LIMIT_SDK_KEY_POINTS: 2,
    RATE_LIMIT_SDK_OWNER_POINTS: 300,
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@hono/node-server/conninfo", () => ({
  getConnInfo: () => ({ remote: { address: "198.51.100.25" } }),
}));
// Production accounting and family scaling; Redis alone is an in-memory double.
vi.mock("rate-limiter-flexible", async (original) => {
  const actual = await original<typeof import("rate-limiter-flexible")>();
  return { ...actual, RateLimiterRedis: actual.RateLimiterMemory };
});
const db = await pgTestDatabase();
const { createSandboxApi } = await import("./middleware.js");
const { createSdkKey } = await import("../../../../packages/api/src/sandbox/services/sdk-keys");
const { consumeSandboxWriteBudget } = await import("@wssp/api/sandbox/budgets");
const { requestDigestMetadata } = await import("@wssp/api/sandbox/idempotency");
const app = new Hono().route("/v1", createSandboxApi());
afterAll(() => db.close());

async function seed() {
  const userId = randomUUID();
  await db.inspect.user.create({
    data: { id: userId, email: `${userId}@example.test`, name: "Owner", twoFactorEnabled: true },
  });
  const owner = await seedMintSession(db.inspect, { kind: "session" as const, ownerId: userId });
  const host = await seedLaunchHost(db.inspect, {
    data: { userId, slug: "lab", label: "Lab", status: "CONNECTED", connectionEpoch: 1 },
  });
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId,
      templateId: revision.id,
      originHostId: host.id,
      sandboxHostId: host.id,
      state: "READY",
      liveResourcesHeld: true,
    },
  });
  const operation = await seedAcceptedOperation(db.inspect, {
    data: {
      userId,
      sandboxId: sandbox.id,
      generation: 1,
      kind: "RUN_COMMAND",
      state: "RUNNING",
      dispatchAttempt: 1,
      acceptedAttempt: 1,
      dispatchedHostId: host.id,
      dispatchedConnectionEpoch: 1,
      idempotencyKey: randomUUID(),
      requestBodyHash: "a".repeat(64),
      ...requestDigestMetadata(),
    },
  });
  const key = await createSdkKey(owner, {
    name: "controller",
    hostIds: [],
    templateRevisionIds: [],
    resourceMode: "ALL_OWNED",
    scopes: ["commands:execute", "operations:cancel", "operations:read", "files:read"],
  });
  const request = (path: string, body: unknown = {}, idempotencyKey = randomUUID()) =>
    app.request(`/v1/${path}`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${key.secret}`,
        "content-type": "application/json",
        "idempotency-key": idempotencyKey,
      },
      body: JSON.stringify(body),
    });
  return { owner, sandbox, operation, request };
}

it("B5 saturated ordinary/stdin/content capacity admits native command cancel while its HTTP/termination budgets have room", async () => {
  const f = await seed();
  for (let i = 0; i < 100; i++) await consumeSandboxWriteBudget(f.owner.ownerId, "ordinary");
  for (let i = 0; i < 600; i++) await consumeSandboxWriteBudget(f.owner.ownerId, "stdin");
  const observation = await seedAcceptedOperation(db.inspect, {
    data: {
      userId: f.owner.ownerId,
      sandboxId: f.sandbox.id,
      kind: "STAT_PATH",
      generation: 1,
      state: "QUEUED",
      idempotencyKey: randomUUID(),
      requestBodyHash: "b".repeat(64),
    },
  });
  await db.inspect.sandboxOperationResult.create({
    data: {
      operationId: observation.id,
      sandboxId: f.sandbox.id,
      userId: f.owner.ownerId,
      generation: 1,
      attempt: 0,
      version: 1,
      reservationBytes: 33_554_432,
      expiresAt: new Date(Date.now() + 60_000),
    },
  });
  await expect(consumeSandboxWriteBudget(f.owner.ownerId, "ordinary")).rejects.toMatchObject({
    code: "TOO_MANY_REQUESTS",
  });
  await expect(consumeSandboxWriteBudget(f.owner.ownerId, "stdin")).rejects.toMatchObject({
    code: "TOO_MANY_REQUESTS",
  });
  const key = randomUUID();
  const first = await f.request(`operations/${f.operation.id}/cancel`, {}, key);
  expect(first.status).toBe(202);
  const receipt = await first.json();
  expect(await (await f.request(`operations/${f.operation.id}/cancel`, {}, key)).json()).toEqual(
    receipt,
  );
  expect(await db.inspect.sandboxActionReceipt.count({ where: { userId: f.owner.ownerId } })).toBe(
    1,
  );
  expect(
    await db.inspect.outboxEvent.count({
      where: { userId: f.owner.ownerId, eventType: "sandbox.operation_cancel_requested" },
    }),
  ).toBe(1);
});

it("B5 a saturated HTTP key budget returns 429 for kill/cancel despite unused termination capacity", async () => {
  const f = await seed();
  for (let i = 0; i < 2; i++) {
    const result = await f.request(`operations/${f.operation.id}/stdin`, {
      contentBase64: Buffer.from("input").toString("base64"),
    });
    expect(result.status).toBe(202);
    expect(await result.json()).toMatchObject({ state: "SUCCEEDED" });
  }
  const result = await f.request(`operations/${f.operation.id}/cancel`);
  expect(result.status).toBe(429);
  expect(result.headers.get("retry-after")).not.toBeNull();
  expect(await result.json()).toMatchObject({ error: { code: "TOO_MANY_REQUESTS" } });
  expect(
    await db.inspect.sandboxActionReceipt.count({
      where: { userId: f.owner.ownerId, action: "operations.cancel" },
    }),
  ).toBe(0);
  expect(
    await db.inspect.outboxEvent.count({
      where: { userId: f.owner.ownerId, eventType: "sandbox.operation_cancel_requested" },
    }),
  ).toBe(0);
  expect(
    (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: f.operation.id } })).state,
  ).toBe("RUNNING");
});
