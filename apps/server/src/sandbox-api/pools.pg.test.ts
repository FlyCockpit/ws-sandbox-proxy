vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "pool-http-fixture",
    RATE_LIMIT_RPC_POINTS: 10000,
    RATE_LIMIT_RPC_WINDOW_SECONDS: 60,
    RATE_LIMIT_SDK_IP_POINTS: 30000,
    RATE_LIMIT_SDK_KEY_POINTS: 10000,
    RATE_LIMIT_SDK_OWNER_POINTS: 30000,
    SANDBOX_MAX_TIMEOUT_MS: 86400000,
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@hono/node-server/conninfo", () => ({
  getConnInfo: () => ({ remote: { address: "198.51.100.35" } }),
}));
vi.mock("rate-limiter-flexible", async (original) => {
  const actual = await original<typeof import("rate-limiter-flexible")>();
  return { ...actual, RateLimiterRedis: actual.RateLimiterMemory };
});

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import {
  poolDetailSchema,
  poolMemberPageSchema,
  poolPageSchema,
  sandboxPageSchema,
} from "@wssp/sandbox-contracts";
import { Hono } from "hono";
import { afterAll, expect, it, vi } from "vitest";
import { deletePool } from "../../../../packages/api/src/sandbox/services/pools";
import { createSandbox } from "../../../../packages/api/src/sandbox/services/sandboxes";
import {
  allOwnedPoolKey,
  poolFixture,
  poolKey,
} from "../../../../packages/api/src/sandbox/testing/pool-fixtures";
import { createWsspClient } from "../../../../packages/sdk/src/client";
import { createSandboxApi } from "./middleware";

const db = await pgTestDatabase();
afterAll(() => db.close());
const app = new Hono().route("/v1", createSandboxApi());
function request(secret: string, path: string, body?: unknown, key = randomUUID()) {
  return app.request(path, {
    method: body === undefined ? "GET" : "POST",
    headers: {
      authorization: `Bearer ${secret}`,
      ...(body === undefined ? {} : { "content-type": "application/json", "idempotency-key": key }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}
it("HTTP pool discovery is paged, strict and intersected before take/count", async () => {
  const f = await poolFixture(db);
  const key = await poolKey(db, f, [f.pool.id], [f.host.id]);
  const response = await request(key.secret, "/v1/pools?limit=1");
  expect(response.status).toBe(200);
  expect(poolPageSchema.parse(await response.json()).items.map((p) => p.id)).toEqual([f.pool.id]);
  const members = await request(key.secret, `/v1/pools/${f.pool.id}/members?limit=1`);
  expect(members.status).toBe(200);
  expect(poolMemberPageSchema.parse(await members.json())).toMatchObject({
    items: [{ hostId: f.host.id }],
    nextCursor: null,
  });
  const detail = await request(key.secret, `/v1/pools/${f.pool.id}`);
  expect(poolDetailSchema.parse(await detail.json()).memberCount).toBe(1);
  for (const query of ["limit=0", "limit=101", "limit=1&limit=2", "unexpected=x"])
    expect((await request(key.secret, "/v1/pools?" + query)).status).toBe(400);
});
it("HTTP pool_revision_absence_equivalence and scope-first refusal", async () => {
  const f = await poolFixture(db);
  const b = await poolFixture(db);
  const hidden = await db.inspect.sandboxPool.create({
    data: { userId: f.id, slug: "hidden", label: "Hidden" },
  });
  const key = await poolKey(db, f);
  for (const id of [b.pool.id, hidden.id, "absent"]) {
    for (const path of [`/v1/pools/${id}`, `/v1/pools/${id}/members`]) {
      const res = await request(key.secret, path);
      expect(res.status).toBe(404);
      expect(await res.json()).toMatchObject({
        error: { code: "sandbox.pool_not_found", message: "Pool not found." },
      });
    }
  }
  await db.inspect.sdkKey.update({
    where: { id: key.key.id },
    data: { scopes: ["sandboxes:read"] },
  });
  for (const id of [f.pool.id, b.pool.id, "absent"])
    expect((await request(key.secret, `/v1/pools/${id}`)).status).toBe(403);
});
it("HTTP XOR pool/direct create, retained replay and pool refusals carry stable raw codes", async () => {
  const f = await poolFixture(db);
  const key = await poolKey(db, f);
  for (const body of [
    { template: "base" },
    { template: "base", poolId: f.pool.id, sandboxHostId: f.host.id },
  ])
    expect((await request(key.secret, "/v1/sandboxes", body)).status).toBe(400);
  await db.inspect.sandboxHost.updateMany({ where: { userId: f.id }, data: { draining: true } });
  const unavailable = await request(key.secret, "/v1/sandboxes", {
    template: "base",
    poolId: f.pool.id,
  });
  expect(unavailable.status).toBe(409);
  expect(await unavailable.json()).toMatchObject({ error: { code: "sandbox.pool_unavailable" } });
  expect(await db.inspect.sandboxOperation.count({ where: { userId: f.id } })).toBe(0);
  await db.inspect.sandboxHost.updateMany({ where: { userId: f.id }, data: { draining: false } });
  const body = { template: "base", poolId: f.pool.id };
  const accepted = await request(key.secret, "/v1/sandboxes", body, f.input.idempotencyKey);
  expect(accepted.status).toBe(202);
  const receipt: unknown = await accepted.json();
  await deletePool(f.owner, { id: f.pool.id });
  const replay = await request(key.secret, "/v1/sandboxes", body, f.input.idempotencyKey);
  expect(replay.status).toBe(202);
  expect(await replay.json()).toEqual(receipt);
});
it("HTTP retained creating key keeps reads, cleanup and same-key replay after selected pool loss", async () => {
  const f = await poolFixture(db);
  const key = await poolKey(db, f);
  const sandbox = await createSandbox(key.principal, f.input);
  const operation = await db.inspect.sandboxOperation.findFirstOrThrow({
    where: { sandboxId: sandbox.id },
  });
  await db.inspect.sdkKeyPoolAllowlist.deleteMany({ where: { sdkKeyId: key.key.id } });
  for (const path of [`/v1/sandboxes/${sandbox.id}`, `/v1/operations/${operation.id}`])
    expect((await request(key.secret, path)).status, path).toBe(200);
  const list = await request(key.secret, "/v1/sandboxes?states=REQUESTED&limit=1");
  expect(list.status).toBe(200);
  expect(await list.json()).toMatchObject({ items: [{ id: sandbox.id }] });
  // A new pool placement has no selected grant; replay still owns its accepted allocation.
  const { idempotencyKey, ...body } = f.input;
  expect((await request(key.secret, "/v1/sandboxes", body, idempotencyKey)).status).toBe(202);
  expect((await request(key.secret, "/v1/sandboxes", body)).status).toBe(404);
  await db.inspect.sdkKeyPoolAllowlist.create({
    data: {
      poolOwnerId: f.id,
      userId: f.id,
      sdkKeyId: key.key.id,
      poolId: f.pool.id,
    },
  });
  expect((await request(key.secret, `/v1/sandboxes/${sandbox.id}`)).status).toBe(200);
  const visible = await request(
    key.secret,
    "/v1/sandboxes?states=REQUESTED&limit=1&poolId=" + f.pool.id,
  );
  expect(visible.status).toBe(200);
  expect(await visible.json()).toMatchObject({ items: [{ id: sandbox.id }] });
});

it("HTTP and SDK sandboxes.list ALL_OWNED and ALLOWLIST equal get for pooled and direct READY rows", async () => {
  const f = await poolFixture(db);
  const all = await allOwnedPoolKey(f);
  const allow = await poolKey(db, f);
  const pooled = await createSandbox(all.principal, f.input);
  const direct = await createSandbox(all.principal, {
    template: "base",
    sandboxHostId: f.host.id,
    idempotencyKey: randomUUID(),
  });
  await db.inspect.sandbox.updateMany({ where: { userId: f.id }, data: { state: "READY" } });
  const expected = [pooled.id, direct.id].sort();
  expect((await request(allow.secret, `/v1/sandboxes/${pooled.id}`)).status).toBe(403);
  expect(await (await request(allow.secret, "/v1/sandboxes")).json()).toMatchObject({ items: [] });
  for (const key of [all]) {
    const sdk = createWsspClient({
      baseUrl: "https://api.example.test",
      apiKey: key.secret,
      fetch: async (url, init) => app.request(url, init),
    });
    for (const id of expected) expect((await sdk.sandboxes.get(id)).id).toBe(id);
    const ids: string[] = [];
    let cursor: string | undefined;
    do {
      const page = await sdk.sandboxes.list({ limit: 1, cursor });
      ids.push(...page.items.map((row) => row.id));
      cursor = page.nextCursor ?? undefined;
    } while (cursor);
    expect(ids.sort()).toEqual(expected);
    const response = await request(key.secret, "/v1/sandboxes");
    expect(response.status).toBe(200);
    expect(
      sandboxPageSchema
        .parse(await response.json())
        .items.map((row) => row.id)
        .sort(),
    ).toEqual(expected);
    for (const id of ids) expect((await sdk.sandboxes.get(id)).id).toBe(id);
    const filtered = await sdk.sandboxes.list({ poolId: f.pool.id });
    expect(filtered.items.map((row) => row.id)).toEqual([pooled.id]);
  }
});

it("HTTP all disabled visible members return 409 pool_unavailable for both key modes", async () => {
  const f = await poolFixture(db);
  const all = await allOwnedPoolKey(f);
  const allow = await poolKey(db, f);
  await db.inspect.sandboxPoolMember.updateMany({
    where: { userId: f.id },
    data: { enabled: false },
  });
  for (const key of [all, allow]) {
    const response = await request(key.secret, "/v1/sandboxes", {
      template: "base",
      poolId: f.pool.id,
    });
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({ error: { code: "sandbox.pool_unavailable" } });
  }
});

it("T12 HTTP pool lease discovery is the best visible path and respects the key's host allowlist", async () => {
  const f = await poolFixture(db);
  await db.inspect.sandboxHost.update({
    where: { id: f.host.id },
    data: { daemonMaxLeaseMs: 21_600_000 },
  });
  await db.inspect.sandboxHost.update({
    where: { id: f.other.id },
    data: { daemonMaxLeaseMs: 79_200_000 },
  });
  const all = await allOwnedPoolKey(f);
  const allowlisted = await poolKey(db, f, [f.pool.id], [f.host.id]);
  const lease = async (secret: string) =>
    poolDetailSchema.parse(await (await request(secret, `/v1/pools/${f.pool.id}`)).json()).lease;
  expect(await lease(all.secret)).toEqual({ maxTimeoutMs: 79_200_000, timeoutZero: false });
  // The allowlisted key never sees a maximum offered only by a host it cannot use.
  expect(await lease(allowlisted.secret)).toEqual({ maxTimeoutMs: 21_600_000, timeoutZero: false });
  const page = poolPageSchema.parse(await (await request(allowlisted.secret, "/v1/pools")).json());
  expect(page.items.find((p) => p.id === f.pool.id)?.lease.maxTimeoutMs).toBe(21_600_000);
  // A pool and membership maximum narrow it further; a disabled member never counts.
  await db.inspect.sandboxPool.update({
    where: { id: f.pool.id },
    data: { maxLeaseMs: 3_600_000 },
  });
  expect((await lease(all.secret)).maxTimeoutMs).toBe(3_600_000);
  await db.inspect.sandboxPool.update({ where: { id: f.pool.id }, data: { maxLeaseMs: null } });
  await db.inspect.sandboxPoolMember.updateMany({
    where: { poolId: f.pool.id, sandboxHostId: f.other.id },
    data: { enabled: false },
  });
  expect((await lease(all.secret)).maxTimeoutMs).toBe(21_600_000);
});
