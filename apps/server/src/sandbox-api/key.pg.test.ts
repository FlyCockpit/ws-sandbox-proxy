vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { keyInfoSchema } from "@wssp/sandbox-contracts";
import { Hono } from "hono";
import { afterAll, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => {
  const { pgTestDatabase: database } = await import("@wssp/db/testing/pg");
  return { default: (await database()).prisma };
});
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "self-key-pg-test-secret",
    RATE_LIMIT_RPC_POINTS: 10_000,
    RATE_LIMIT_RPC_WINDOW_SECONDS: 60,
    RATE_LIMIT_SDK_IP_POINTS: 30_000,
    RATE_LIMIT_SDK_KEY_POINTS: 10_000,
    RATE_LIMIT_SDK_OWNER_POINTS: 30_000,
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@hono/node-server/conninfo", () => ({
  getConnInfo: () => ({ remote: { address: "198.51.100.11" } }),
}));
vi.mock("rate-limiter-flexible", async (original) => {
  const actual = await original<typeof import("rate-limiter-flexible")>();
  return { ...actual, RateLimiterRedis: actual.RateLimiterMemory };
});

/** `GET /v1/key` and `DELETE /v1/key` through the real `/v1` stack. */
const db = await pgTestDatabase();
const { generateSdkKeySecret, digestSdkKeySecret } = await import("@wssp/api/lib/sdk-key-access");
const { credentialLookupPrefix } = await import("@wssp/db/credential-security");
const { createSandboxApi } = await import("./middleware.js");
afterAll(() => db.close());

const app = new Hono().route("/v1", createSandboxApi());
const call = (method: "GET" | "DELETE", secret: string) =>
  app.request("/v1/key", { method, headers: { authorization: `Bearer ${secret}` } });

async function seedKey(origin: "DASHBOARD" | "CLI_LOGIN") {
  const userId = `user-${randomUUID()}`;
  await db.inspect.user.create({
    data: {
      id: userId,
      name: "Owner",
      email: `${userId}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  const pool = await db.inspect.sandboxPool.create({
    data: { userId, slug: "lab", label: "Lab" },
  });
  const credential = generateSdkKeySecret();
  const key = await db.inspect.sdkKey.create({
    data: {
      userId,
      origin,
      name: "laptop",
      resourceMode: "ALL_OWNED",
      poolMode: "SELECTED",
      scopes: ["sandboxes:read", "files:read"],
      lookupPrefix: credentialLookupPrefix(credential),
      secretDigest: digestSdkKeySecret(credential.raw),
      expiresAt: new Date(Date.now() + 86_400_000),
      maxLiveSandboxes: 4,
      PoolAllowlist: { create: [{ poolId: pool.id, poolOwnerId: userId }] },
    },
  });
  return { key, pool, secret: credential.raw, email: `${userId}@example.test` };
}

describe("/v1/key", () => {
  it("describes the calling key without the owner email", async () => {
    const seeded = await seedKey("DASHBOARD");
    const response = await call("GET", seeded.secret);
    expect(response.status).toBe(200);
    const text = await response.text();
    expect(text).not.toContain(seeded.email);
    expect(keyInfoSchema.parse(JSON.parse(text))).toEqual({
      id: seeded.key.id,
      name: "laptop",
      origin: "dashboard",
      scopes: ["sandboxes:read", "files:read"],
      resourceMode: "allOwned",
      poolMode: "selected",
      pools: [{ id: seeded.pool.id, slug: "lab", label: "Lab" }],
      ownSandboxesOnly: false,
      expiresAt: seeded.key.expiresAt?.toISOString(),
      maxLiveSandboxes: 4,
      liveSandboxes: 0,
    });
  });

  it("a CLI login revokes itself and is then 401; a dashboard key is refused with 403", async () => {
    const login = await seedKey("CLI_LOGIN");
    const revoked = await call("DELETE", login.secret);
    expect(revoked.status).toBe(200);
    expect(await revoked.json()).toEqual({ id: login.key.id, revoked: true });
    expect((await call("GET", login.secret)).status).toBe(401);
    expect((await call("DELETE", login.secret)).status).toBe(401);

    const dashboard = await seedKey("DASHBOARD");
    const refused = await call("DELETE", dashboard.secret);
    expect(refused.status).toBe(403);
    expect(await refused.json()).toMatchObject({ error: { code: "key.self_revoke_forbidden" } });
    expect((await call("GET", dashboard.secret)).status).toBe(200);
  });
});
