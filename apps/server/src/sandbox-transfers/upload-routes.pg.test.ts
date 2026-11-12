import { createHash, randomUUID } from "node:crypto";
import { once } from "node:events";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { serve } from "@hono/node-server";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import {
  TRANSFER_MAX_BYTES as CAP,
  TRANSFER_CHUNK_BYTES as CHUNK,
  mutationReceiptSchema,
} from "@wssp/sandbox-contracts";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { afterAll, afterEach, beforeEach, expect, it, vi } from "vitest";
import {
  seedLaunchHost,
  seedSandboxInstance,
  seedTemplateRevision,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";
import type { TransferStore } from "./store.js";

const state = vi.hoisted(() => ({
  store: undefined as TransferStore | undefined,
  getSession: vi.fn(),
}));
vi.mock("./runtime.js", () => ({
  transferStore: () => {
    if (!state.store) throw new Error("fixture unavailable");
    return state.store;
  },
}));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_SECRET: "c29-pg-test",
    BETTER_AUTH_URL: "https://wssp.example",
    CORS_ORIGIN: "https://wssp.example",
    RATE_LIMIT_RPC_POINTS: 100000,
    RATE_LIMIT_RPC_WINDOW_SECONDS: 60,
    RATE_LIMIT_SDK_IP_POINTS: 300_000,
    RATE_LIMIT_SDK_KEY_POINTS: 100_000,
    RATE_LIMIT_SDK_OWNER_POINTS: 300_000,
    RATE_LIMIT_AUTH_POINTS: 30,
    RATE_LIMIT_AUTH_WINDOW_SECONDS: 60,
    RATE_LIMIT_EMAIL_POINTS: 3,
    RATE_LIMIT_EMAIL_WINDOW_SECONDS: 3600,
    TRANSFER_GLOBAL_ACTIVE: 16,
    TRANSFER_OWNER_ACTIVE: 4,
  },
  ADMIN_EMAILS: new Set(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/auth", () => ({ auth: { api: { getSession: state.getSession } } }));
vi.mock("@hono/node-server/conninfo", () => ({
  getConnInfo: () => ({ remote: { address: "127.0.0.1" } }),
}));
vi.mock("rate-limiter-flexible", async (original) => {
  const actual = await original<typeof import("rate-limiter-flexible")>();
  return { ...actual, RateLimiterRedis: actual.RateLimiterMemory };
});
const db = await pgTestDatabase();
const { TransferStore: Store } = await import("./store.js");
const { createSandboxApi } = await import("../sandbox-api/middleware.js");
const { createDashboardTransferApi } = await import("./dashboard-routes.js");
const { createSdkKey } = await import("../../../../packages/api/src/sandbox/services/sdk-keys");
const { authenticateSdkKeySecret } = await import("@wssp/api/lib/sdk-key-access");
const { invalidateForceTwoFactorSettingsCache } = await import("@wssp/api/lib/two-factor-policy");
const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
let root: string;
let app: Hono;
let server: ReturnType<typeof serve> | undefined;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "wssp-c29-"));
  state.store = new Store(root, {
    maxBytes: CAP,
    diskBytes: 10 * CAP,
    globalActive: 16,
    ownerActive: 4,
    idleMs: 900000,
    absoluteMs: 3600000,
  });
  await state.store.start();
  state.getSession.mockReset();
  await db.inspect.appSetting.upsert({
    where: { key: "force2faPublicUsers" },
    create: { key: "force2faPublicUsers", value: "true" },
    update: { value: "true" },
  });
  invalidateForceTwoFactorSettingsCache();
  app = new Hono()
    .route("/v1", createSandboxApi())
    .route("/api/dashboard", createDashboardTransferApi());
  // Models a proxy's JSON-body middleware: binary routes must terminate first.
  app.use("*", bodyLimit({ maxSize: 16 }));
  app.all("*", (c) => c.json({ fallback: true }));
});
afterEach(async () => {
  if (server) {
    const closing = once(server, "close");
    server.close();
    if ("closeAllConnections" in server) server.closeAllConnections();
    await closing;
    server = undefined;
  }
  await state.store?.close();
  await rm(root, { recursive: true, force: true });
});
afterAll(() => db.close());
async function browserSession(userId: string) {
  const session = await db.inspect.session.create({
    data: { userId, token: randomUUID(), expiresAt: new Date(Date.now() + 3600000) },
  });
  const snapshot = { user: { id: userId }, session };
  state.getSession.mockResolvedValue(snapshot);
  return snapshot;
}
async function seed(scopes: ("files:write" | "files:read")[] = ["files:write"]) {
  const userId = randomUUID();
  await db.inspect.user.create({
    data: {
      id: userId,
      name: "owner",
      email: `${userId}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
      createdAt: new Date(0),
    },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: { userId, slug: "host", label: "host" },
  });
  const template = await seedTemplateRevision(db.inspect, {
    data: {
      userId,
      sandboxHostId: host.id,
      slug: "base",
      label: "base",
      imageRef: "base",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId,
      sandboxHostId: host.id,
      originHostId: host.id,
      templateId: template.id,
      originPoolId: null,
      state: "READY",
    },
  });
  const key = await createSdkKey(
    { kind: "session", ownerId: userId },
    {
      name: "upload",
      scopes,
      resourceMode: "ALL_OWNED",
      hostIds: [],
      templateRevisionIds: [],
      expiresAt: null,
    },
  );
  return {
    userId,
    sandbox,
    key,
    headers: { authorization: `Bearer ${key.secret}` },
    body: { sandboxId: sandbox.id, guestPath: "/tmp/data", totalBytes: 3 },
  };
}
async function create(f: Awaited<ReturnType<typeof seed>>, totalBytes = 3, base = "/v1") {
  const response = await app.request(`${base}/transfers`, {
    method: "POST",
    headers: {
      ...f.headers,
      origin: "https://wssp.example",
      "content-type": "application/json",
      "idempotency-key": randomUUID(),
    },
    body: JSON.stringify({ ...f.body, totalBytes }),
  });
  expect(response.status, await response.clone().text()).toBe(201);
  return (await response.json()) as { id: string };
}
function put(
  f: Awaited<ReturnType<typeof seed>>,
  id: string,
  bytes = new Uint8Array([0, 255, 13]),
  base = "/v1",
  signal?: AbortSignal,
  body?: ReadableStream<Uint8Array>,
) {
  return app.request(
    new Request(`https://wssp.example${base}/transfers/${id}`, {
      method: "PUT",
      headers: {
        ...f.headers,
        origin: "https://wssp.example",
        "content-type": "application/octet-stream",
        "content-range": `bytes 0-${bytes.length - 1}/${bytes.length}`,
      },
      body: body ?? bytes,
      duplex: "half",
      signal,
    } as RequestInit),
  );
}
async function commit(
  f: Awaited<ReturnType<typeof seed>>,
  id: string,
  key = "commit",
  sha256 = hash(new Uint8Array([0, 255, 13])),
) {
  return app.request(`/v1/transfers/${id}/commit`, {
    method: "POST",
    headers: { ...f.headers, "content-type": "application/json", "idempotency-key": key },
    body: JSON.stringify({ sha256 }),
  });
}
it("commits binary bytes once with durable outbox and replays after generation change", async () => {
  const f = await seed(),
    row = await create(f);
  expect((await put(f, row.id)).status).toBe(200);
  expect((await put(f, row.id)).status).toBe(200);
  expect((await put(f, row.id, new Uint8Array([1, 2, 3]))).status).toBe(409);
  expect((await commit(f, row.id, "commit", "a".repeat(64))).status).toBe(400);
  const res = await commit(f, row.id);
  expect(res.status).toBe(202);
  const receipt = mutationReceiptSchema.parse(await res.json());
  const stored = await db.inspect.sandboxOperation.findUniqueOrThrow({
    where: { id: receipt.operationId },
  });
  expect(stored).toMatchObject({
    kind: "PUT_FILE",
    state: "QUEUED",
    generation: 1,
  });
  // No operation column can hold payload bytes (C30 removed payloadBytes).
  expect(Object.keys(stored)).not.toContain("payloadBytes");
  expect(await db.inspect.outboxEvent.count({ where: { userId: f.userId } })).toBe(1);
  expect((await commit(f, row.id, "different")).status).toBe(409);
  const source = await state.store!.uploadSource(row.id, receipt.operationId);
  expect(source.size).toBe(3);
  expect(await source.read(0, 3)).toEqual(Buffer.from([0, 255, 13]));
  expect(
    (await app.request(`/v1/transfers/${row.id}`, { method: "DELETE", headers: f.headers })).status,
  ).toBe(409);
  await db.inspect.sandbox.update({
    where: { id: f.sandbox.id },
    data: { generation: 2, state: "STOPPED" },
  });
  expect(await (await commit(f, row.id)).json()).toEqual(receipt);
  expect((await commit(f, row.id, "different")).status).toBe(409);
  expect(
    await db.inspect.sandboxOperation.count({
      where: { NOT: { idempotencyKey: { startsWith: "fixture-boot:" } }, userId: f.userId },
    }),
  ).toBe(1);
});
it("serializes concurrent commit and abort without a second operation or released source", async () => {
  const f = await seed(),
    row = await create(f);
  await put(f, row.id);
  const barrier = db.pauseAt("commit", {
    before: "sql:SELECT id FROM sdk_key WHERE id = ? FOR SHARE",
  });
  const pending = db.run("commit", () => commit(f, row.id));
  await barrier.waitReached();
  try {
    expect((await commit(f, row.id)).status).toBe(409);
    expect(
      (await app.request(`/v1/transfers/${row.id}`, { method: "DELETE", headers: f.headers }))
        .status,
    ).toBe(409);
  } finally {
    barrier.release();
  }
  expect((await pending).status).toBe(202);
  expect((await commit(f, row.id)).status).toBe(202);
  expect(
    await db.inspect.sandboxOperation.count({
      where: { NOT: { idempotencyKey: { startsWith: "fixture-boot:" } }, userId: f.userId },
    }),
  ).toBe(1);
  expect(await readFile(join(root, `${row.id}.spool`))).toEqual(Buffer.from([0, 255, 13]));
});
it("reauthorizes a slow chunk after revocation and denies every foreign key and owner", async () => {
  const f = await seed(),
    row = await create(f),
    foreign = await seed();
  for (const path of [`/v1/transfers/${row.id}`, `/v1/transfers/${row.id}/commit`]) {
    const response = await app.request(path, {
      method: path.endsWith("commit") ? "POST" : "GET",
      headers: foreign.headers,
    });
    expect(response.status).toBe(404);
  }
  const before = await authenticateSdkKeySecret(f.key.secret);
  expect(before).not.toBeNull();
  let release!: () => void;
  let reached!: () => void;
  const entered = new Promise<void>((r) => {
    reached = r;
  });
  const body = new ReadableStream<Uint8Array>(
    {
      start(c) {
        release = () => {
          c.enqueue(new Uint8Array([0, 255, 13]));
          c.close();
        };
      },
      pull() {
        reached();
      },
    },
    { highWaterMark: 0 },
  );
  const pending = put(f, row.id, undefined, undefined, undefined, body);
  await entered;
  await db.inspect.sdkKey.update({ where: { id: before!.keyId }, data: { revokedAt: new Date() } });
  release();
  expect((await pending).status).toBe(403);
  expect(
    (await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: row.id } })).receivedBytes,
  ).toBe(0n);
  expect((await put(f, row.id)).status).toBe(401);
});
it("enforces cookie-only same-origin mutations and current required two-factor policy", async () => {
  const f = await seed();
  const snapshot = await browserSession(f.userId);
  state.getSession.mockImplementation(async ({ headers }: { headers: Headers }) => {
    expect(headers.has("authorization")).toBe(false);
    return snapshot;
  });
  const row = await create(f, 3, "/api/dashboard");
  for (const origin of ["https://evil.example", "null", "https://sibling.wssp.example", ""]) {
    const response = await app.request(`/api/dashboard/transfers/${row.id}`, {
      method: "DELETE",
      headers: origin ? { origin } : {},
    });
    expect(response.status).toBe(403);
  }
  expect((await put(f, row.id, undefined, "/api/dashboard")).status).toBe(200);
  expect((await app.request(`/v1/transfers/${row.id}`, { headers: f.headers })).status).toBe(404);
  await db.inspect.user.update({ where: { id: f.userId }, data: { twoFactorEnabled: false } });
  expect((await put(f, row.id, undefined, "/api/dashboard")).status).toBe(403);
  state.getSession.mockResolvedValue(null);
  expect((await put(f, row.id, undefined, "/api/dashboard")).status).toBe(401);
});
it("resumes a real HTTP socket disconnect without acknowledging a partial chunk", async () => {
  const f = await seed(),
    row = await create(f);
  server = serve({ fetch: app.fetch, port: 0, hostname: "127.0.0.1" });
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("no port");
  const observed = vi.spyOn(state.store!, "status");
  let entered!: () => void;
  const ready = new Promise<void>((r) => {
    entered = r;
  });
  observed.mockImplementationOnce(async (...args) => {
    const value = await Store.prototype.status.apply(state.store!, args);
    entered();
    return value;
  });
  const req = request({
    host: "127.0.0.1",
    port: address.port,
    path: `/v1/transfers/${row.id}`,
    method: "PUT",
    headers: {
      ...f.headers,
      "content-type": "application/octet-stream",
      "content-range": "bytes 0-2/3",
      "content-length": "3",
    },
  });
  req.on("error", () => {});
  req.write(Buffer.from([0]));
  await ready;
  const closed = new Promise<void>((resolve) => req.once("close", resolve));
  req.destroy();
  await closed;
  observed.mockRestore();
  const resumed = await put(f, row.id);
  expect(resumed.status).toBe(200);
  expect(await readFile(join(root, `${row.id}.spool`))).toEqual(Buffer.from([0, 255, 13]));
});
it("accepts zero and default-cap reservations and rejects cap plus one before allocation", async () => {
  const f = await seed();
  const empty = await create(f, 0);
  expect((await commit(f, empty.id, "empty", hash(new Uint8Array()))).status).toBe(202);
  const maximum = await create(f, CAP);
  expect(
    (await app.request(`/v1/transfers/${maximum.id}`, { method: "DELETE", headers: f.headers }))
      .status,
  ).toBe(200);
  const response = await app.request("/v1/transfers", {
    method: "POST",
    headers: { ...f.headers, "content-type": "application/json", "idempotency-key": "oversize" },
    body: JSON.stringify({ ...f.body, totalBytes: CAP + 1 }),
  });
  expect(response.status).toBe(413);
  expect(await db.inspect.sandboxTransfer.count({ where: { userId: f.userId } })).toBe(2);
});

it("stores a 33 MiB binary HTTP upload without inline database bytes", async () => {
  const f = await seed(),
    total = 33 * CHUNK + 3,
    row = await create(f, total);
  const whole = createHash("sha256");
  for (let offset = 0; offset < total; ) {
    const bytes = new Uint8Array(Math.min(CHUNK, total - offset)).fill(211);
    whole.update(bytes);
    const response = await app.request(`/v1/transfers/${row.id}`, {
      method: "PUT",
      headers: {
        ...f.headers,
        "content-type": "application/octet-stream",
        "content-range": `bytes ${offset}-${offset + bytes.length - 1}/${total}`,
      },
      body: bytes,
    });
    expect(response.status).toBe(200);
    offset += bytes.length;
  }
  const response = await commit(f, row.id, "large", whole.digest("hex"));
  expect(response.status).toBe(202);
  const accepted = mutationReceiptSchema.parse(await response.json());
  const source = await state.store!.uploadSource(row.id, accepted.operationId);
  expect(source.size).toBe(total);
  expect(await source.read(total - 3, 3)).toEqual(Buffer.from([211, 211, 211]));
});

it("applies the live scope grant and originating key to every upload endpoint", async () => {
  const f = await seed(),
    row = await create(f);
  const principal = await authenticateSdkKeySecret(f.key.secret);
  if (!principal) throw new Error("missing key");
  const sibling = await createSdkKey(
    { kind: "session", ownerId: f.userId },
    {
      name: "sibling",
      scopes: ["files:write"],
      resourceMode: "ALL_OWNED",
      hostIds: [],
      templateRevisionIds: [],
      expiresAt: null,
    },
  );
  const requests = () => [
    () =>
      app.request("/v1/transfers", {
        method: "POST",
        headers: {
          ...f.headers,
          "content-type": "application/json",
          "idempotency-key": randomUUID(),
        },
        body: JSON.stringify(f.body),
      }),
    () => app.request(`/v1/transfers/${row.id}`, { headers: f.headers }),
    () => put(f, row.id),
    () => commit(f, row.id),
    () => app.request(`/v1/transfers/${row.id}`, { method: "DELETE", headers: f.headers }),
  ];
  for (const data of [
    { scopes: ["files:read"] },
    { scopes: ["files:write"], resourceMode: "ALLOWLIST" as const },
  ]) {
    await db.inspect.sdkKey.update({ where: { id: principal.keyId }, data });
    for (const send of requests()) expect((await send()).status).toBe(403);
  }
  f.headers.authorization = `Bearer ${sibling.secret}`;
  for (const send of requests().slice(1)) expect((await send()).status).toBe(404);
  expect(
    (await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: row.id } })).receivedBytes,
  ).toBe(0n);
});

it("rejects a lifecycle change between hashing and commit without publishing intent", async () => {
  const f = await seed(),
    row = await create(f);
  await put(f, row.id);
  const barrier = db.pauseAt("commit", {
    before: "sql:SELECT id FROM sdk_key WHERE id = ? FOR SHARE",
  });
  const pending = db.run("commit", () => commit(f, row.id));
  await barrier.waitReached();
  try {
    await db.inspect.sandbox.update({ where: { id: f.sandbox.id }, data: { generation: 2 } });
  } finally {
    barrier.release();
  }
  expect((await pending).status).toBe(409);
  expect(
    await db.inspect.sandboxOperation.count({
      where: { NOT: { idempotencyKey: { startsWith: "fixture-boot:" } }, userId: f.userId },
    }),
  ).toBe(0);
  expect(await db.inspect.outboxEvent.count({ where: { userId: f.userId } })).toBe(0);
});

it("rolls back a failed commit and recovers the same accepted operation after restart", async () => {
  const f = await seed(),
    row = await create(f);
  await put(f, row.id);
  const barrier = db.pauseAt("commit", { after: "sandboxOperation.create" });
  const pending = db.run("commit", () => commit(f, row.id));
  await barrier.waitReached();
  barrier.fail(new Error("injected rollback"));
  expect((await pending).status).toBe(500);
  expect(
    await db.inspect.sandboxOperation.count({
      where: { NOT: { idempotencyKey: { startsWith: "fixture-boot:" } }, userId: f.userId },
    }),
  ).toBe(0);
  expect(await db.inspect.outboxEvent.count({ where: { userId: f.userId } })).toBe(0);
  expect(
    (await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: row.id } })).state,
  ).toBe("OPEN");
  const accepted = mutationReceiptSchema.parse(await (await commit(f, row.id)).json());
  await state.store!.close();
  state.store = new Store(root, {
    maxBytes: CAP,
    diskBytes: 10 * CAP,
    globalActive: 16,
    ownerActive: 4,
    idleMs: 900000,
    absoluteMs: 3600000,
  });
  await state.store.start();
  expect(await (await commit(f, row.id)).json()).toEqual(accepted);
  expect(await (await state.store.uploadSource(row.id, accepted.operationId)).read(0, 3)).toEqual(
    Buffer.from([0, 255, 13]),
  );
});

/** What the relay does with a committed upload: stream it, then settle its PUT_FILE. */
async function settle(
  id: string,
  operationId: string,
  outcome: "SUCCEEDED" | "FAILED" | "CANCELLED" | "UNKNOWN_OUTCOME",
) {
  const source = await state.store!.uploadSource(id, operationId);
  await source.read(0, source.size);
  await db.inspect.sandboxOperation.update({
    where: { id: operationId },
    data: { state: outcome, completedAt: new Date() },
  });
}
async function sequentialUpload(f: Awaited<ReturnType<typeof seed>>) {
  const row = await create(f);
  expect((await put(f, row.id)).status).toBe(200);
  const res = await commit(f, row.id, randomUUID());
  expect(res.status).toBe(202);
  return { id: row.id, operationId: mutationReceiptSchema.parse(await res.json()).operationId };
}

it("E-17 the 5th, 10th and 20th sequential upload each succeed once their PUT_FILE settles", async () => {
  const f = await seed();
  const settledAs = ["SUCCEEDED", "FAILED", "CANCELLED"] as const;
  for (let n = 1; n <= 20; n++) {
    // Each create reserves a slot (4 per owner); it must never stay held by
    // an upload whose guest operation already settled.
    const upload = await sequentialUpload(f);
    await settle(upload.id, upload.operationId, settledAs[n % 3]!);
    if ([5, 10, 20].includes(n))
      expect(
        await db.inspect.sandboxOperation.count({
          where: {
            NOT: { idempotencyKey: { startsWith: "fixture-boot:" } },
            userId: f.userId,
            kind: "PUT_FILE",
          },
        }),
      ).toBe(n);
  }
  // Admission reaps settled uploads' spools too: at most the latest still holds disk.
  expect(
    await db.inspect.sandboxTransfer.count({ where: { userId: f.userId, reservationHeld: true } }),
  ).toBeLessThanOrEqual(1);
});

it("E-17 unsettled or uncertain uploads keep their slots; the 5th waits with Retry-After", async () => {
  const f = await seed();
  const uploads = [];
  for (let n = 0; n < 4; n++) uploads.push(await sequentialUpload(f));
  // QUEUED, RUNNING, CANCEL_REQUESTED and UNKNOWN_OUTCOME all keep the slot (C55).
  for (const [i, state] of (["RUNNING", "CANCEL_REQUESTED", "UNKNOWN_OUTCOME"] as const).entries())
    await db.inspect.sandboxOperation.update({
      where: { id: uploads[i + 1]!.operationId },
      data: { state },
    });
  const full = await app.request("/v1/transfers", {
    method: "POST",
    headers: { ...f.headers, "content-type": "application/json", "idempotency-key": randomUUID() },
    body: JSON.stringify(f.body),
  });
  expect(full.status).toBe(429);
  expect(full.headers.get("retry-after")).toBe("5");
  expect(await full.json()).toMatchObject({
    error: { code: "TRANSFER_QUOTA", retryAfterSeconds: 5 },
  });
  // Settling one (the QUEUED one succeeds) frees exactly one slot.
  await settle(uploads[0]!.id, uploads[0]!.operationId, "SUCCEEDED");
  await create(f);
  const again = await app.request("/v1/transfers", {
    method: "POST",
    headers: { ...f.headers, "content-type": "application/json", "idempotency-key": randomUUID() },
    body: JSON.stringify(f.body),
  });
  expect(again.status).toBe(429);
});

it("E-17 a retired committed upload still replays its commit and reports its receipt", async () => {
  const f = await seed();
  const row = await create(f);
  expect((await put(f, row.id)).status).toBe(200);
  const first = await commit(f, row.id, "commit-replay");
  const receipt = mutationReceiptSchema.parse(await first.json());
  await settle(row.id, receipt.operationId, "SUCCEEDED");
  await create(f); // admission reaps the settled spool
  expect(
    await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: row.id } }),
  ).toMatchObject({ state: "EXPIRED", reservationHeld: false });
  // SDK recovery (files.upload retried under the same key) depends on this.
  const replay = await commit(f, row.id, "commit-replay");
  expect(replay.status).toBe(202);
  expect(await replay.json()).toEqual({ ...receipt, state: "SUCCEEDED" });
  const status = await app.request(`/v1/transfers/${row.id}`, { headers: f.headers });
  expect(await status.json()).toMatchObject({ state: "EXPIRED", receivedBytes: 3 });
  // A settled upload's source never yields bytes again.
  await expect(state.store!.uploadSource(row.id, receipt.operationId)).rejects.toMatchObject({
    status: 410,
  });
});

it("E-27/E-28 a guest path the guest would refuse is a 400 before any reservation", async () => {
  const f = await seed();
  await browserSession(f.userId);
  for (const guestPath of [
    "/home/user/../user/ui/trav.txt",
    "/tmp/..",
    "../etc/passwd",
    "trav.txt",
    // E-28: the guest file helper refuses `.` components and a bare root.
    "/home/user/./dot.txt",
    "/tmp/.",
    "/",
    "/a\ud800b",
    // G4R1-1: refused, never trimmed to another file.
    "/data/report ",
    "\t/data/report",
    "\n/data/report",
  ])
    for (const base of ["/v1", "/api/dashboard"]) {
      const response = await app.request(`${base}/transfers`, {
        method: "POST",
        headers: {
          ...(base === "/v1" ? f.headers : {}),
          origin: "https://wssp.example",
          "content-type": "application/json",
          "idempotency-key": randomUUID(),
        },
        body: JSON.stringify({ ...f.body, guestPath }),
      });
      expect(response.status, `${base} ${guestPath}`).toBe(400);
      expect(await response.json()).toMatchObject({ error: { code: "BAD_REQUEST" } });
    }
  expect(await db.inspect.sandboxTransfer.count({ where: { userId: f.userId } })).toBe(0);
  // Dots inside a name are an ordinary file name.
  await create({ ...f, body: { ...f.body, guestPath: "/tmp/a..b/..c/.hidden" } });
  // Internal spaces are kept exactly.
  await create({ ...f, body: { ...f.body, guestPath: "/tmp/my report.txt" } });
  expect(
    (await db.inspect.sandboxTransfer.findMany({ where: { userId: f.userId } })).map(
      (row) => row.guestPath,
    ),
  ).toEqual(expect.arrayContaining(["/tmp/a..b/..c/.hidden", "/tmp/my report.txt"]));
});

it.each(["body", "failed body"])(
  "S0 durable revoke during %s prevents upload writes and hides errors",
  async (boundary) => {
    const f = await seed();
    const snapshot = await browserSession(f.userId);
    const row = await create(f, 3, "/api/dashboard");
    let entered!: () => void;
    const reading = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let controller!: ReadableStreamDefaultController<Uint8Array>;
    const body = new ReadableStream<Uint8Array>(
      {
        start(c) {
          controller = c;
        },
        pull() {
          entered();
        },
      },
      { highWaterMark: 0 },
    );
    const pending = put(f, row.id, undefined, "/api/dashboard", undefined, body);
    await reading;
    await db.inspect.session.delete({ where: { id: snapshot.session.id } });
    if (boundary === "body") {
      controller.enqueue(new Uint8Array([0, 255, 13]));
      controller.close();
    } else controller.error(new Error("PRIVATE-BODY-ERROR"));
    const response = await pending;
    expect(response.status).toBe(401);
    expect(response.headers.get("Location")).toBeNull();
    expect(await response.text()).not.toContain("PRIVATE");
    expect(
      (await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: row.id } })).receivedBytes,
    ).toBe(0n);
    const { transferSlotsInUse } = await import("./http-admission.js");
    expect(transferSlotsInUse()).toBe(0);
  },
);

it.each([false, true])(
  "S0 post-commit upload exit denial conceals response (error=%s) and preserves receipt",
  async (rejected) => {
    const f = await seed();
    const snapshot = await browserSession(f.userId);
    const row = await create(f, 3, "/api/dashboard");
    expect((await put(f, row.id, undefined, "/api/dashboard")).status).toBe(200);
    const original = state.store!.commit.bind(state.store);
    const spy = vi.spyOn(state.store!, "commit").mockImplementation(async (...args) => {
      const receipt = await original(...args);
      await db.inspect.session.delete({ where: { id: snapshot.session.id } });
      if (rejected) throw new Error("PRIVATE-COMMIT-ERROR");
      return receipt;
    });
    try {
      const response = await app.request(`/api/dashboard/transfers/${row.id}/commit`, {
        method: "POST",
        headers: {
          origin: "https://wssp.example",
          "content-type": "application/json",
          "idempotency-key": "original",
        },
        body: JSON.stringify({ sha256: hash(new Uint8Array([0, 255, 13])) }),
      });
      expect(response.status).toBe(401);
      expect(response.headers.get("Location")).toBeNull();
      expect(await response.text()).not.toContain("PRIVATE");
    } finally {
      spy.mockRestore();
    }
    const stored = await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: row.id } });
    expect(stored.operationId).not.toBeNull();
    expect(
      await db.inspect.sandboxOperation.count({ where: { userId: f.userId, kind: "PUT_FILE" } }),
    ).toBe(1);
    await browserSession(f.userId);
    const replay = await state.store!.commit(
      { kind: "session", ownerId: f.userId },
      row.id,
      "original",
      hash(new Uint8Array([0, 255, 13])),
    );
    expect(replay.operationId).toBe(stored.operationId);
    const { transferSlotsInUse } = await import("./http-admission.js");
    expect(transferSlotsInUse()).toBe(0);
  },
);

it("S0 body revocation at the time cadence stops before a second body read", async () => {
  const f = await seed();
  const snapshot = await browserSession(f.userId);
  const row = await create(f, 3, "/api/dashboard");
  let now = Date.now();
  const clock = vi.spyOn(Date, "now").mockImplementation(() => now);
  let reads = 0;
  const body = new ReadableStream<Uint8Array>(
    {
      async pull(c) {
        reads++;
        if (reads === 1) {
          await db.inspect.session.delete({ where: { id: snapshot.session.id } });
          now += 1000;
          c.enqueue(new Uint8Array([0]));
        } else {
          c.enqueue(new Uint8Array([255, 13]));
          c.close();
        }
      },
    },
    { highWaterMark: 0 },
  );
  try {
    expect((await put(f, row.id, undefined, "/api/dashboard", undefined, body)).status).toBe(401);
  } finally {
    clock.mockRestore();
  }
  expect(reads).toBe(1);
  expect(
    (await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: row.id } })).receivedBytes,
  ).toBe(0n);
});

it("S0 a bodyless mutation rechecks authority before effect", async () => {
  const f = await seed();
  const snapshot = await browserSession(f.userId);
  const row = await create(f, 3, "/api/dashboard");
  const original = state.store!.status.bind(state.store);
  const spy = vi.spyOn(state.store!, "status").mockImplementation(async (...args) => {
    const result = await original(...args);
    await db.inspect.session.delete({ where: { id: snapshot.session.id } });
    return result;
  });
  try {
    expect(
      (
        await app.request(`/api/dashboard/transfers/${row.id}`, {
          method: "DELETE",
          headers: { origin: "https://wssp.example" },
        })
      ).status,
    ).toBe(401);
    expect(
      (await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: row.id } })).state,
    ).toBe("OPEN");
  } finally {
    spy.mockRestore();
  }
});
