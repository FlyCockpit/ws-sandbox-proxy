import type { SessionPrincipal } from "../../../../packages/api/src/sandbox/contracts";
import {
  seedLaunchHost,
  seedMintSession,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { once } from "node:events";
import { access, mkdtemp, rm } from "node:fs/promises";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { serve } from "@hono/node-server";
import type { ServiceScope } from "@wssp/api/lib/service-scopes";
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
    BETTER_AUTH_SECRET: "c30-pg-test",
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
const { transferSlotsInUse } = await import("./http-admission.js");
const { invalidateForceTwoFactorSettingsCache } = await import("@wssp/api/lib/two-factor-policy");
const { createSdkKey } = await import("../../../../packages/api/src/sandbox/services/sdk-keys");
const { readFile: requestCapture } = await import(
  "../../../../packages/api/src/sandbox/services/sandboxes"
);
const sha = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const limits = {
  maxBytes: CAP,
  diskBytes: 10 * CAP,
  globalActive: 16,
  ownerActive: 4,
  idleMs: 900000,
  absoluteMs: 3600000,
  // Short delivery grace so retirement is observable; TQ-F1 tests set their own.
  deliveredGraceMs: 50,
};
let root: string;
let app: Hono;
let server: ReturnType<typeof serve> | undefined;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "wssp-c30-"));
  state.store = new Store(root, limits);
  await state.store.start();
  state.getSession.mockReset();
  app = new Hono()
    .route("/v1", createSandboxApi())
    .route("/api/dashboard", createDashboardTransferApi());
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
  await db.inspect.sandboxTransfer.updateMany({
    where: { reservationHeld: true },
    data: { state: "EXPIRED", reservationHeld: false },
  });
  await rm(root, { recursive: true, force: true });
});
afterAll(() => db.close());

type Fixture = Awaited<ReturnType<typeof seed>>;
async function browserSession(userId: string) {
  const session = await db.inspect.session.create({
    data: { userId, token: randomUUID(), expiresAt: new Date(Date.now() + 3600000) },
  });
  const snapshot = { user: { id: userId }, session };
  state.getSession.mockResolvedValue(snapshot);
  return snapshot;
}
async function seed(scopes: ServiceScope[] = ["files:read", "operations:read", "files:write"]) {
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
  const owner = await seedMintSession(db.inspect, { kind: "session" as const, ownerId: userId });
  const key = await mintKey(owner, scopes);
  return {
    userId,
    owner,
    hostId: host.id,
    sandbox,
    key,
    headers: { authorization: `Bearer ${key.secret}` } as Record<string, string>,
  };
}
function mintKey(owner: SessionPrincipal, scopes: ServiceScope[]) {
  return createSdkKey(owner, {
    name: "download",
    scopes,
    resourceMode: "ALL_OWNED",
    hostIds: [],
    templateRevisionIds: [],
    expiresAt: null,
  });
}
/** `POST /v1/sandboxes/{id}/files/download`: the public capture request. */
async function requestDownload(f: Fixture, path = "/home/user/out.bin") {
  const response = await app.request(`/v1/sandboxes/${f.sandbox.id}/files/download`, {
    method: "POST",
    headers: {
      ...f.headers,
      "content-type": "application/json",
      "idempotency-key": randomUUID(),
    },
    body: JSON.stringify({ path }),
  });
  expect(response.status, await response.clone().text()).toBe(202);
  return mutationReceiptSchema.parse(await response.json()).operationId;
}
/** What the relay does for one GET_FILE attempt: capture every chunk into the
 * store inside a transaction, then record the success result it verified. */
async function capture(
  f: Fixture,
  operationId: string,
  bytes: Uint8Array | { size: number; at: (offset: number, length: number) => Promise<Uint8Array> },
) {
  const source =
    bytes instanceof Uint8Array
      ? { size: bytes.length, at: async (o: number, n: number) => bytes.subarray(o, o + n) }
      : bytes;
  const op = await db.inspect.sandboxOperation.update({
    where: { id: operationId },
    data: { state: "RUNNING", dispatchAttempt: 1, dispatchedHostId: f.hostId },
  });
  const owner = {
    userId: f.userId,
    keyId: op.authorizingKeyId,
    sandboxId: op.sandboxId,
    generation: op.generation,
    guestPath: "/home/user/out.bin",
  };
  for (let sequence = 0, offset = 0; ; sequence++) {
    const body = await source.at(offset, Math.min(CHUNK, source.size - offset));
    const ended = offset + body.length >= source.size;
    const store = state.store!;
    const publish = await db.prisma.$transaction((tx) =>
      store.admitCapture(tx, owner, { operationId, attempt: 1, sequence, offset, body, ended }),
    );
    await publish?.();
    offset += body.length;
    if (ended) break;
  }
  const done = await state.store!.completedCapture(operationId, 1);
  if (!done) throw new Error("capture not sealed");
  await db.inspect.sandboxOperation.update({
    where: { id: operationId },
    data: {
      state: "SUCCEEDED",
      completedAt: new Date(),
      result: { path: owner.guestPath, ...done },
    },
  });
  return done;
}
function get(f: Fixture, operationId: string, headers: Record<string, string> = {}, base = "/v1") {
  return app.request(`${base}/operations/${operationId}/content`, {
    headers: { ...f.headers, ...headers },
  });
}
async function errorCode(response: Response) {
  return ((await response.json()) as { error: { code: string } }).error.code;
}

it("streams a requested capture whole and by one range with matching length, hash and ETag", async () => {
  const f = await seed();
  const operationId = await requestDownload(f);
  const early = await get(f, operationId);
  expect(early.status).toBe(409);
  expect(await errorCode(early)).toBe("TRANSFER_NOT_READY");
  const bytes = randomBytes(2 * CHUNK + CHUNK / 2);
  bytes[0] = 0;
  bytes[bytes.length - 1] = 255;
  const done = await capture(f, operationId, bytes);
  const etag = `"${sha(bytes)}"`;

  // Ranges, HEAD and refusals first: a whole delivery retires the capture (E-17).
  const head = await app.request(`/v1/operations/${operationId}/content`, {
    method: "HEAD",
    headers: f.headers,
  });
  expect(head.status).toBe(200);
  expect(head.headers.get("content-length")).toBe(String(bytes.length));
  expect(head.headers.get("etag")).toBe(etag);
  expect((await head.arrayBuffer()).byteLength).toBe(0);

  for (const [range, start, end] of [
    [`bytes=${CHUNK - 1}-${2 * CHUNK}`, CHUNK - 1, 2 * CHUNK],
    [`bytes=${2 * CHUNK}-`, 2 * CHUNK, bytes.length - 1],
    ["bytes=-7", bytes.length - 7, bytes.length - 1],
    [`bytes=5-${10 * CHUNK}`, 5, bytes.length - 1],
    ["bytes=0-0", 0, 0],
  ] as const) {
    const part = await get(f, operationId, { range });
    expect(part.status, range).toBe(206);
    expect(part.headers.get("content-range")).toBe(`bytes ${start}-${end}/${bytes.length}`);
    expect(part.headers.get("content-length")).toBe(String(end - start + 1));
    expect(part.headers.get("etag")).toBe(etag);
    // Buffer.equals: vitest's deep equality is far too slow for megabytes.
    expect(Buffer.from(await part.arrayBuffer()).equals(bytes.subarray(start, end + 1))).toBe(true);
  }
  const matched = await get(f, operationId, { range: "bytes=3-4", "if-range": etag });
  expect(matched.status).toBe(206);
  expect(Buffer.from(await matched.arrayBuffer())).toEqual(bytes.subarray(3, 5));
  for (const validator of [`"${"0".repeat(64)}"`, `W/${etag}`, "Sat, 26 Sep 2026 00:00:00 GMT"]) {
    // HEAD answers exactly what the GET would select, without delivering it.
    const stale = await app.request(`/v1/operations/${operationId}/content`, {
      method: "HEAD",
      headers: { ...f.headers, range: "bytes=3-4", "if-range": validator },
    });
    expect(stale.status, validator).toBe(200);
    expect(stale.headers.get("content-range")).toBeNull();
    expect(stale.headers.get("content-length")).toBe(String(bytes.length));
  }
  for (const range of [
    `bytes=${bytes.length}-`,
    "bytes=0-1,4-5",
    "bytes=9-3",
    "bytes=-0",
    "items=0-1",
    "bytes=abc",
    "bytes=0-99999999999999999",
  ]) {
    const refused = await get(f, operationId, { range });
    expect(refused.status, range).toBe(416);
    expect(refused.headers.get("content-range")).toBe(`bytes */${bytes.length}`);
    expect(await errorCode(refused)).toBe("RANGE_NOT_SATISFIABLE");
  }
  // Status and output polling never expose the capture's content or identity.
  const status = await app.request(`/v1/operations/${operationId}`, { headers: f.headers });
  expect(status.status).toBe(200);
  const statusText = await status.text();
  expect(JSON.parse(statusText)).toMatchObject({ kind: "GET_FILE", state: "SUCCEEDED" });
  for (const secret of [done.transferId, done.sha256, "out.bin", "result"])
    expect(statusText).not.toContain(secret);
  const reader = await mintKey(f.owner, ["operations:read", "commands:read"]);
  const output = await app.request(`/v1/operations/${operationId}/output`, {
    headers: { authorization: `Bearer ${reader.secret}` },
  });
  expect(output.status).toBe(409);
  expect(await output.text()).not.toContain(done.sha256);
  // Partial ranges never completed the capture: it still holds its slot.
  expect(
    await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: done.transferId } }),
  ).toMatchObject({ state: "SEALED", reservationHeld: true });

  const whole = await get(f, operationId);
  expect(whole.status).toBe(200);
  expect(Object.fromEntries(whole.headers)).toMatchObject({
    "content-type": "application/octet-stream",
    "content-length": String(bytes.length),
    etag,
    "accept-ranges": "bytes",
    "repr-digest": `sha-256=:${Buffer.from(done.sha256, "hex").toString("base64")}:`,
    "x-content-type-options": "nosniff",
    "cache-control": "no-store",
  });
  expect(whole.headers.get("content-disposition")).toBe("attachment; filename*=UTF-8''out.bin");
  expect(sha(new Uint8Array(await whole.arrayBuffer()))).toBe(sha(bytes));
  // Fully delivered: terminal, its slot and disk returned; the receipt remains.
  await vi.waitFor(async () =>
    expect(
      await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: done.transferId } }),
    ).toMatchObject({ state: "EXPIRED", reservationHeld: false }),
  );
  const again = await get(f, operationId);
  expect(again.status).toBe(410);
  expect(await errorCode(again)).toBe("TRANSFER_EXPIRED");
  // Every response streamed from the one capture: no second operation or capture.
  expect(
    await db.inspect.sandboxOperation.count({
      where: { NOT: { idempotencyKey: { startsWith: "fixture-boot:" } }, userId: f.userId },
    }),
  ).toBe(1);
  expect(await db.inspect.sandboxTransfer.count({ where: { userId: f.userId } })).toBe(1);
  expect(transferSlotsInUse()).toBe(0);
});

it("serves an empty capture and refuses every range of it", async () => {
  const f = await seed();
  const operationId = await requestDownload(f);
  const done = await capture(f, operationId, new Uint8Array());
  const refused = await get(f, operationId, { range: "bytes=0-" });
  expect(refused.status).toBe(416);
  expect(refused.headers.get("content-range")).toBe("bytes */0");
  // Neither a refused range nor a HEAD delivers the (empty) content.
  const head = await app.request(`/v1/operations/${operationId}/content`, {
    method: "HEAD",
    headers: f.headers,
  });
  expect(head.status).toBe(200);
  const empty = await get(f, operationId);
  expect(empty.status).toBe(200);
  expect(empty.headers.get("content-length")).toBe("0");
  expect(empty.headers.get("etag")).toBe(`"${sha(new Uint8Array())}"`);
  expect((await empty.arrayBuffer()).byteLength).toBe(0);
  await vi.waitFor(async () =>
    expect(
      await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: done.transferId } }),
    ).toMatchObject({ state: "EXPIRED", reservationHeld: false }),
  );
});

it("resumes an interrupted download by range without a new capture", async () => {
  const f = await seed();
  const operationId = await requestDownload(f);
  const bytes = randomBytes(3 * CHUNK + 11);
  await capture(f, operationId, bytes);
  const etag = `"${sha(bytes)}"`;
  server = serve({ fetch: app.fetch, port: 0, hostname: "127.0.0.1" });
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("no port");
  // A real socket that stops after the first megabyte and disconnects.
  const received = await new Promise<Buffer>((resolve, reject) => {
    const req = request(
      {
        host: "127.0.0.1",
        port: address.port,
        path: `/v1/operations/${operationId}/content`,
        headers: f.headers,
      },
      (res) => {
        expect(res.statusCode).toBe(200);
        const parts: Buffer[] = [];
        let size = 0;
        res.on("data", (part: Buffer) => {
          parts.push(part);
          size += part.length;
          if (size >= CHUNK) {
            req.destroy();
            resolve(Buffer.concat(parts));
          }
        });
        res.on("error", () => {});
      },
    );
    req.on("error", () => {});
    req.on("close", () => reject(new Error("closed before the first megabyte")));
    req.end();
  });
  expect(received.subarray(0, CHUNK).equals(bytes.subarray(0, CHUNK))).toBe(true);
  // The aborted stream returns its slot and its reader (bounded server cleanup).
  await vi.waitFor(() => expect(transferSlotsInUse()).toBe(0));
  const offset = received.length;
  // Two concurrent resumed ranges of the same immutable capture both succeed.
  const [rest, again] = await Promise.all([
    get(f, operationId, { range: `bytes=${offset}-`, "if-range": etag }),
    get(f, operationId, { range: `bytes=${offset}-`, "if-range": etag }),
  ]);
  expect([rest.status, again.status]).toEqual([206, 206]);
  const tail = Buffer.from(await rest.arrayBuffer());
  expect(Buffer.from(await again.arrayBuffer()).equals(tail)).toBe(true);
  expect(sha(Buffer.concat([received, tail]))).toBe(sha(bytes));
  expect(
    await db.inspect.sandboxOperation.count({
      where: { NOT: { idempotencyKey: { startsWith: "fixture-boot:" } }, userId: f.userId },
    }),
  ).toBe(1);
  expect(await db.inspect.sandboxTransfer.count({ where: { userId: f.userId } })).toBe(1);
});

it("rechecks credential, scopes and originating identity on every request and chunk", async () => {
  const f = await seed(),
    foreign = await seed();
  const operationId = await requestDownload(f);
  const bytes = randomBytes(2 * CHUNK + 1);
  await capture(f, operationId, bytes);
  // Another owner and a sibling key of the same owner cannot see the capture.
  const foreignResponse = await get(foreign, operationId);
  expect(foreignResponse.status).toBe(404);
  expect(await errorCode(foreignResponse)).toBe("sandbox.operation_not_found");
  const sibling = await mintKey(f.owner, ["files:read", "operations:read"]);
  expect((await get(f, operationId, { authorization: `Bearer ${sibling.secret}` })).status).toBe(
    404,
  );
  // Each scope is required: bytes need files:read, the operation operations:read.
  for (const scopes of [["operations:read"], ["files:read"]] as ServiceScope[][]) {
    await db.inspect.sdkKey.update({ where: { id: f.key.key.id }, data: { scopes } });
    expect((await get(f, operationId)).status, scopes.join()).toBe(403);
  }
  await db.inspect.sdkKey.update({
    where: { id: f.key.key.id },
    data: { scopes: ["files:read", "operations:read"] },
  });
  // Revocation after the headers were sent stops the stream at the next chunk.
  const response = await get(f, operationId);
  expect(response.status).toBe(200);
  const reader = response.body!.getReader();
  const first = await reader.read();
  expect(first.value?.byteLength).toBe(CHUNK);
  await db.inspect.sdkKey.update({ where: { id: f.key.key.id }, data: { revokedAt: new Date() } });
  await expect(
    (async () => {
      for (;;) if ((await reader.read()).done) return;
    })(),
  ).rejects.toMatchObject({ status: 403 });
  expect(transferSlotsInUse()).toBe(0);
  expect((await get(f, operationId)).status).toBe(401);
});

it("stops serving content when it expires or its sandbox is deleted mid-download", async () => {
  const f = await seed();
  const expiring = await requestDownload(f);
  const deleting = await requestDownload(f, "/home/user/other.bin");
  const bytes = randomBytes(2 * CHUNK);
  const expiringCapture = await capture(f, expiring, bytes);
  const deletingCapture = await capture(f, deleting, bytes);

  const response = await get(f, expiring);
  const reader = response.body!.getReader();
  expect((await reader.read()).value?.byteLength).toBe(CHUNK);
  await db.inspect.sandboxTransfer.update({
    where: { id: expiringCapture.transferId },
    data: { idleExpiresAt: new Date(Date.now() - 1) },
  });
  await expect(reader.read()).rejects.toMatchObject({ status: 410 });
  const expired = await get(f, expiring);
  expect(expired.status).toBe(410);
  expect(await errorCode(expired)).toBe("TRANSFER_EXPIRED");

  const live = await get(f, deleting);
  const liveReader = live.body!.getReader();
  expect((await liveReader.read()).value?.byteLength).toBe(CHUNK);
  await db.inspect.sandbox.update({
    where: { id: f.sandbox.id },
    data: { state: "DELETED", generation: f.sandbox.generation + 1 },
  });
  await expect(liveReader.read()).rejects.toMatchObject({ status: 409 });
  const gone = await get(f, deleting);
  expect(gone.status).toBe(410);
  // Receipts survive; content and reservations are released by the sweep.
  expect(
    (await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: deleting } })).state,
  ).toBe("SUCCEEDED");
  await state.store!.sweep();
  for (const id of [expiringCapture.transferId, deletingCapture.transferId]) {
    expect(await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id } })).toMatchObject({
      state: "EXPIRED",
      reservationHeld: false,
    });
    await expect(access(join(root, `${id}.spool`))).rejects.toMatchObject({ code: "ENOENT" });
  }
  expect(transferSlotsInUse()).toBe(0);
});

it("reports unsuccessful and non-file operations without content", async () => {
  const f = await seed();
  const failed = await requestDownload(f);
  await db.inspect.sandboxOperation.update({
    where: { id: failed },
    data: { state: "FAILED", errorCode: "not_found", completedAt: new Date() },
  });
  const refused = await get(f, failed);
  expect(refused.status).toBe(409);
  expect(await errorCode(refused)).toBe("CONFLICT");
  await db.inspect.sandboxHost.update({
    where: { id: f.hostId },
    data: {
      connectionEpoch: 1,
      relayProtocolVersion: "1.0",
      relayProtocolEpoch: 1,
      admissionRuntime: "FAKE",
      admissionEpoch: 1,
    },
  });
  const listing = await app.request(`/v1/sandboxes/${f.sandbox.id}/files/list`, {
    method: "POST",
    headers: { ...f.headers, "content-type": "application/json", "idempotency-key": "list" },
    body: JSON.stringify({ path: "/" }),
  });
  const listed = mutationReceiptSchema.parse(await listing.json()).operationId;
  const notFile = await get(f, listed);
  expect(notFile.status).toBe(404);
  expect(await errorCode(notFile)).toBe("sandbox.operation_not_found");
  expect((await get(f, randomUUID())).status).toBe(404);
  expect(
    (
      await app.request(`/v1/operations/${failed}/content`, {
        method: "DELETE",
        headers: f.headers,
      })
    ).status,
  ).toBe(405);
  expect(
    (await app.request(`/v1/operations/${failed}/content?x=1`, { headers: f.headers })).status,
  ).toBe(400);
});

it("serves the dashboard plane only to same-site cookie sessions of their own captures", async () => {
  const f = await seed();
  const snapshot = await browserSession(f.userId);
  state.getSession.mockImplementation(async ({ headers }: { headers: Headers }) => {
    expect(headers.has("authorization")).toBe(false);
    return snapshot;
  });
  const receipt = await requestCapture(
    { kind: "session", ownerId: f.userId },
    { id: f.sandbox.id, idempotencyKey: "browser-capture", path: "/home/user/out.bin" },
  );
  const bytes = randomBytes(CHUNK + 5);
  await capture(f, receipt.operationId, bytes);
  const cookie = (headers: Record<string, string> = {}) =>
    app.request(`/api/dashboard/operations/${receipt.operationId}/content`, { headers });
  for (const site of [undefined, "same-origin", "none"]) {
    const ok = await app.request(`/api/dashboard/operations/${receipt.operationId}/content`, {
      method: "HEAD",
      headers: site ? { "sec-fetch-site": site } : {},
    });
    expect(ok.status, site).toBe(200);
    expect(ok.headers.get("content-length")).toBe(String(bytes.length));
  }
  for (const site of ["cross-site", "same-site"])
    expect((await cookie({ "sec-fetch-site": site })).status, site).toBe(403);
  const part = await cookie({ range: "bytes=-5" });
  expect(part.status).toBe(206);
  expect(Buffer.from(await part.arrayBuffer())).toEqual(bytes.subarray(-5));
  // A browser capture is not an SDK key's, and vice versa.
  expect((await get(f, receipt.operationId)).status).toBe(404);
  const sdkCapture = await requestDownload(f);
  await capture(f, sdkCapture, bytes);
  const still = await cookie();
  expect(still.status).toBe(200);
  expect(sha(new Uint8Array(await still.arrayBuffer()))).toBe(sha(bytes));
  expect((await app.request(`/api/dashboard/operations/${sdkCapture}/content`)).status).toBe(404);
  // Saved once in full: the browser capture is retired (E-17) once its
  // delivery grace ends (TQ-F1). A poll that lands inside the grace is served,
  // so drop its body rather than leave its stream open.
  await vi.waitFor(async () => {
    const response = await cookie();
    await response.body?.cancel();
    expect(response.status).toBe(410);
  });
  await db.inspect.appSetting.upsert({
    where: { key: "force2faPublicUsers" },
    create: { key: "force2faPublicUsers", value: "true" },
    update: { value: "true" },
  });
  invalidateForceTwoFactorSettingsCache();
  await db.inspect.user.update({ where: { id: f.userId }, data: { twoFactorEnabled: false } });
  expect((await cookie()).status).toBe(403);
  state.getSession.mockResolvedValue(null);
  expect((await cookie()).status).toBe(401);
  expect(transferSlotsInUse()).toBe(0);
});

it("round-trips 33 MiB of arbitrary bytes from upload through capture to download with one hash", async () => {
  const f = await seed();
  const total = 33 * CHUNK + 3;
  const created = await app.request("/v1/transfers", {
    method: "POST",
    headers: { ...f.headers, "content-type": "application/json", "idempotency-key": "up" },
    body: JSON.stringify({
      sandboxId: f.sandbox.id,
      guestPath: "/home/user/in.bin",
      totalBytes: total,
    }),
  });
  const upload = (await created.json()) as { id: string };
  const whole = createHash("sha256");
  const content = randomBytes(total);
  for (let offset = 0; offset < total; offset += CHUNK) {
    const bytes = content.subarray(offset, offset + CHUNK);
    whole.update(bytes);
    const put = await app.request(`/v1/transfers/${upload.id}`, {
      method: "PUT",
      headers: {
        ...f.headers,
        "content-type": "application/octet-stream",
        "content-range": `bytes ${offset}-${offset + bytes.length - 1}/${total}`,
      },
      body: bytes,
    });
    expect(put.status).toBe(200);
  }
  const digest = whole.digest("hex");
  const committed = await app.request(`/v1/transfers/${upload.id}/commit`, {
    method: "POST",
    headers: { ...f.headers, "content-type": "application/json", "idempotency-key": "commit" },
    body: JSON.stringify({ sha256: digest }),
  });
  const put = mutationReceiptSchema.parse(await committed.json());
  // The relay sends the upload source to the guest; the guest file is then
  // captured back chunk by chunk (as a host would for a GET_FILE).
  const source = await state.store!.uploadSource(upload.id, put.operationId);
  const echoed = Buffer.alloc(total);
  for (let offset = 0; offset < total; offset += CHUNK)
    Buffer.from(await source.read(offset, Math.min(CHUNK, total - offset))).copy(echoed, offset);
  const operationId = await requestDownload(f);
  await capture(f, operationId, echoed);
  const download = await get(f, operationId);
  expect(download.headers.get("etag")).toBe(`"${digest}"`);
  const hash = createHash("sha256");
  let size = 0;
  const reader = download.body!.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    expect(value.byteLength).toBeLessThanOrEqual(CHUNK);
    size += value.byteLength;
    hash.update(value);
  }
  expect(size).toBe(total);
  expect(hash.digest("hex")).toBe(digest);
  expect(
    await db.inspect.sandboxOperation.findMany({
      where: { userId: f.userId, NOT: { idempotencyKey: { startsWith: "fixture-boot:" } } },
      select: { kind: true },
      orderBy: { createdAt: "asc" },
    }),
  ).toEqual([{ kind: "PUT_FILE" }, { kind: "GET_FILE" }]);
  expect(transferSlotsInUse()).toBe(0);
});

it("round-trips a 1 GiB upload through capture and an interrupted ranged download with one hash", async () => {
  const f = await seed();
  const total = CAP;
  // Arbitrary bytes, streamed: a random block with every byte XORed with the
  // chunk index (& 255), built a 32-bit word at a time.
  const block = randomBytes(CHUNK);
  const chunkAt = (offset: number) => {
    const out = Buffer.allocUnsafeSlow(CHUNK);
    block.copy(out);
    const salt = ((offset / CHUNK) & 255) * 0x01010101;
    if (salt !== 0) {
      const words = new Uint32Array(out.buffer, out.byteOffset, CHUNK / 4);
      for (let i = 0; i < words.length; i++) words[i]! ^= salt;
    }
    return out;
  };
  const created = await app.request("/v1/transfers", {
    method: "POST",
    headers: { ...f.headers, "content-type": "application/json", "idempotency-key": "gib" },
    body: JSON.stringify({
      sandboxId: f.sandbox.id,
      guestPath: "/home/user/in.bin",
      totalBytes: total,
    }),
  });
  expect(created.status).toBe(201);
  const upload = (await created.json()) as { id: string };
  const uploaded = createHash("sha256");
  for (let offset = 0; offset < total; offset += CHUNK) {
    const bytes = chunkAt(offset);
    uploaded.update(bytes);
    const put = await app.request(`/v1/transfers/${upload.id}`, {
      method: "PUT",
      headers: {
        ...f.headers,
        "content-type": "application/octet-stream",
        "content-range": `bytes ${offset}-${offset + CHUNK - 1}/${total}`,
      },
      body: bytes,
    });
    expect(put.status).toBe(200);
  }
  const digest = uploaded.digest("hex");
  const committed = await app.request(`/v1/transfers/${upload.id}/commit`, {
    method: "POST",
    headers: { ...f.headers, "content-type": "application/json", "idempotency-key": "gib-commit" },
    body: JSON.stringify({ sha256: digest }),
  });
  expect(committed.status).toBe(202);
  const put = mutationReceiptSchema.parse(await committed.json());
  const source = await state.store!.uploadSource(upload.id, put.operationId);
  const operationId = await requestDownload(f);
  // The guest file is captured back one chunk at a time, straight from the upload spool.
  const done = await capture(f, operationId, { size: total, at: (o, n) => source.read(o, n) });
  expect(done).toMatchObject({ size: total, sha256: digest });
  const joined = createHash("sha256");
  const cut = total / 2 + 12345;
  let received = 0;
  const first = (await get(f, operationId)).body!.getReader();
  while (received < cut) {
    const { value } = await first.read();
    joined.update(value!);
    received += value!.byteLength;
  }
  await first.cancel();
  const rest = await get(f, operationId, {
    range: `bytes=${received}-`,
    "if-range": `"${digest}"`,
  });
  expect(rest.status).toBe(206);
  const reader = rest.body!.getReader();
  for (;;) {
    const { done: end, value } = await reader.read();
    if (end) break;
    joined.update(value);
    received += value.byteLength;
  }
  expect(received).toBe(total);
  expect(joined.digest("hex")).toBe(digest);
  expect(transferSlotsInUse()).toBe(0);
}, 600_000);

it("E-17 the 5th, 10th and 20th sequential download each succeed after full delivery", async () => {
  const f = await seed();
  for (let n = 1; n <= 20; n++) {
    const bytes = randomBytes(n % 4 === 0 ? 0 : 97 * n);
    const operationId = await requestDownload(f);
    // The capture itself reserves a slot (4 per owner): a delivered capture
    // must have returned its own before this one could be admitted.
    const done = await capture(f, operationId, bytes);
    const response = await get(f, operationId);
    expect(response.status, `download ${n}`).toBe(200);
    expect(sha(new Uint8Array(await response.arrayBuffer()))).toBe(sha(bytes));
    await vi.waitFor(async () =>
      expect(
        await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: done.transferId } }),
      ).toMatchObject({ state: "EXPIRED", reservationHeld: false }),
    );
  }
  expect(await db.inspect.sandboxTransfer.count({ where: { userId: f.userId } })).toBe(20);
  expect(transferSlotsInUse()).toBe(0);
});

it("E-17 an interrupted or partial download keeps its slot until a resume completes it", async () => {
  const f = await seed();
  const bytes = randomBytes(2 * CHUNK + 9);
  const captures: { operationId: string; transferId: string }[] = [];
  for (let n = 0; n < 4; n++) {
    const operationId = await requestDownload(f);
    captures.push({ operationId, ...(await capture(f, operationId, bytes)) });
  }
  // Partial range, consumer cancel, HEAD and an undelivered capture: none is
  // a delivery of the whole capture, so all four slots stay held.
  const ranged = await get(f, captures[0]!.operationId, { range: `bytes=0-${CHUNK}` });
  expect(Buffer.from(await ranged.arrayBuffer()).length).toBe(CHUNK + 1);
  const cancelled = await get(f, captures[1]!.operationId);
  const reader = cancelled.body!.getReader();
  await reader.read();
  await reader.cancel();
  await app.request(`/v1/operations/${captures[2]!.operationId}/content`, {
    method: "HEAD",
    headers: f.headers,
  });
  await vi.waitFor(() => expect(transferSlotsInUse()).toBe(0));
  const blocked = await requestDownload(f);
  await expect(capture(f, blocked, bytes)).rejects.toMatchObject({ code: "transfer_quota" });
  // Resuming the partial one from where it stopped completes its coverage.
  const rest = await get(f, captures[0]!.operationId, {
    range: `bytes=${CHUNK + 1}-`,
    "if-range": `"${sha(bytes)}"`,
  });
  expect(rest.status).toBe(206);
  expect(Buffer.from(await rest.arrayBuffer()).equals(bytes.subarray(CHUNK + 1))).toBe(true);
  await vi.waitFor(async () =>
    expect(
      await db.inspect.sandboxTransfer.findUniqueOrThrow({
        where: { id: captures[0]!.transferId },
      }),
    ).toMatchObject({ state: "EXPIRED", reservationHeld: false }),
  );
  // The cancelled one is still resumable; its slot is still held.
  expect(
    await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: captures[1]!.transferId } }),
  ).toMatchObject({ state: "SEALED", reservationHeld: true });
  const next = await requestDownload(f);
  await capture(f, next, bytes);
});

it("TQ-F1 a client that lost the tail of a full download resumes it within the grace, then gets 410", async () => {
  await state.store!.close();
  state.store = new Store(root, { ...limits, deliveredGraceMs: 1_500 });
  await state.store.start();
  const f = await seed();
  const bytes = randomBytes(CHUNK + 77);
  const operationId = await requestDownload(f);
  const done = await capture(f, operationId, bytes);
  const etag = `"${sha(bytes)}"`;
  // The server hands every byte over: the capture counts as delivered.
  const whole = await get(f, operationId);
  expect(whole.status).toBe(200);
  expect(sha(new Uint8Array(await whole.arrayBuffer()))).toBe(sha(bytes));
  await vi.waitFor(async () =>
    expect(
      await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: done.transferId } }),
    ).toMatchObject({ state: "EXPIRED", reservationHeld: true }),
  );
  // The client never got the last 77 bytes; inside the grace it resumes them.
  const tail = await get(f, operationId, { range: `bytes=${CHUNK}-`, "if-range": etag });
  expect(tail.status).toBe(206);
  expect(tail.headers.get("content-range")).toBe(`bytes ${CHUNK}-${CHUNK + 76}/${bytes.length}`);
  expect(Buffer.from(await tail.arrayBuffer()).equals(bytes.subarray(CHUNK))).toBe(true);
  // After the grace the content is gone.
  await vi.waitFor(
    async () =>
      expect(
        await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: done.transferId } }),
      ).toMatchObject({ state: "EXPIRED", reservationHeld: false }),
    { timeout: 5_000 },
  );
  const late = await get(f, operationId, { range: `bytes=${CHUNK}-`, "if-range": etag });
  expect(late.status).toBe(410);
  expect(await errorCode(late)).toBe("TRANSFER_EXPIRED");
  expect(transferSlotsInUse()).toBe(0);
});

it.each(["between pulls", "during read", "during failed read"])(
  "S0 durable revoke %s fences bytes/errors and releases once",
  async (boundary) => {
    const f = await seed();
    const snapshot = await browserSession(f.userId);
    const receipt = await requestCapture(
      { kind: "session", ownerId: f.userId },
      { id: f.sandbox.id, idempotencyKey: randomUUID(), path: "/tmp/out" },
    );
    await capture(f, receipt.operationId, randomBytes(CHUNK + 3));
    const original = state.store!.downloadSource.bind(state.store);
    let entered!: () => void;
    let release!: () => void;
    const waiting = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const close = vi.fn();
    const read = vi.fn();
    const spy = vi.spyOn(state.store!, "downloadSource").mockImplementation(async (...args) => {
      const source = await original(...args);
      return {
        ...source,
        read: async (offset, length) => {
          read();
          if (boundary !== "between pulls") {
            entered();
            await held;
            if (boundary === "during failed read") throw new Error("PRIVATE-READ-ERROR");
          }
          return source.read(offset, length);
        },
        close: () => {
          close();
          source.close();
        },
      };
    });
    try {
      const response = await app.request(
        `/api/dashboard/operations/${receipt.operationId}/content`,
      );
      expect(response.status).toBe(200);
      const reader = response.body!.getReader();
      if (boundary === "between pulls") {
        expect((await reader.read()).value?.length).toBe(CHUNK);
        await db.inspect.session.delete({ where: { id: snapshot.session.id } });
        await expect(reader.read()).rejects.toMatchObject({ code: "UNAUTHORIZED" });
        expect(read).toHaveBeenCalledTimes(1);
      } else {
        const pending = reader.read();
        const denied = expect(pending).rejects.toMatchObject({ code: "UNAUTHORIZED" });
        await waiting;
        await db.inspect.session.delete({ where: { id: snapshot.session.id } });
        release();
        await denied;
      }
      await reader.cancel().catch(() => {});
      expect(close).toHaveBeenCalledTimes(1);
      expect(transferSlotsInUse()).toBe(0);
      expect(
        (
          await app.request(`/api/dashboard/operations/${receipt.operationId}/content`, {
            method: "HEAD",
          })
        ).status,
      ).toBe(401);
    } finally {
      release();
      spy.mockRestore();
    }
  },
);

it.each(["revoked", "expired", "impersonated"])(
  "S0 transfer principal refuses a durable %s session",
  async (reason) => {
    const f = await seed();
    const snapshot = await browserSession(f.userId);
    if (reason === "revoked")
      await db.inspect.session.delete({ where: { id: snapshot.session.id } });
    else
      await db.inspect.session.update({
        where: { id: snapshot.session.id },
        data: reason === "expired" ? { expiresAt: new Date(0) } : { impersonatedBy: "admin" },
      });
    const response = await app.request(`/api/dashboard/operations/${randomUUID()}/content`, {
      method: "HEAD",
    });
    expect(response.status).toBe(401);
    expect(transferSlotsInUse()).toBe(0);
  },
);

it.each([false, true])(
  "S0 source-open exit recheck hides metadata/errors (error=%s) and closes once",
  async (rejected) => {
    const f = await seed();
    const snapshot = await browserSession(f.userId);
    const receipt = await requestCapture(
      { kind: "session", ownerId: f.userId },
      { id: f.sandbox.id, idempotencyKey: randomUUID(), path: "/tmp/out" },
    );
    await capture(f, receipt.operationId, new Uint8Array([1, 2, 3]));
    const original = state.store!.downloadSource.bind(state.store);
    const close = vi.fn();
    const spy = vi.spyOn(state.store!, "downloadSource").mockImplementation(async (...args) => {
      const source = await original(...args);
      await db.inspect.session.delete({ where: { id: snapshot.session.id } });
      if (rejected) {
        source.close();
        throw new Error("PRIVATE-OPEN-ERROR");
      }
      return {
        ...source,
        close: () => {
          close();
          source.close();
        },
      };
    });
    try {
      const response = await app.request(
        `/api/dashboard/operations/${receipt.operationId}/content`,
        { method: "HEAD" },
      );
      expect(response.status).toBe(401);
      expect(response.headers.get("Content-Disposition")).toBeNull();
      expect(response.headers.get("ETag")).toBeNull();
      expect(await response.text()).not.toContain("PRIVATE");
      expect(close).toHaveBeenCalledTimes(rejected ? 0 : 1);
      expect(transferSlotsInUse()).toBe(0);
    } finally {
      spy.mockRestore();
    }
  },
);

it("S0 revocation after the final enqueue closes normally and credits the complete capture", async () => {
  const f = await seed();
  const snapshot = await browserSession(f.userId);
  const receipt = await requestCapture(
    { kind: "session", ownerId: f.userId },
    { id: f.sandbox.id, idempotencyKey: randomUUID(), path: "/tmp/out" },
  );
  const bytes = randomBytes(CHUNK + 3);
  const captured = await capture(f, receipt.operationId, bytes);
  const original = state.store!.downloadSource.bind(state.store);
  const delivered = vi.fn();
  const close = vi.fn();
  const spy = vi.spyOn(state.store!, "downloadSource").mockImplementation(async (...args) => {
    const source = await original(...args);
    return {
      ...source,
      delivered: (offset, length) => {
        delivered(offset, length);
        source.delivered(offset, length);
      },
      close: () => {
        close();
        source.close();
      },
    };
  });
  try {
    const response = await app.request(`/api/dashboard/operations/${receipt.operationId}/content`);
    const reader = response.body!.getReader();
    expect((await reader.read()).value?.length).toBe(CHUNK);
    expect((await reader.read()).value?.length).toBe(3);
    await db.inspect.session.delete({ where: { id: snapshot.session.id } });
    expect((await reader.read()).done).toBe(true);
    expect(delivered.mock.calls).toEqual([
      [0, CHUNK],
      [CHUNK, 3],
      [CHUNK + 3, 0],
    ]);
    expect(close).toHaveBeenCalledTimes(1);
    expect(transferSlotsInUse()).toBe(0);
    await expect
      .poll(async () =>
        db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: captured.transferId } }),
      )
      .toMatchObject({ state: "EXPIRED", reservationHeld: false });
  } finally {
    spy.mockRestore();
  }
});
