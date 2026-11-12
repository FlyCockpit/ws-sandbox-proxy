import { randomUUID } from "node:crypto";
import { createRouterClient } from "@orpc/server";
import type { Session } from "@wssp/auth";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { Hono } from "hono";
import { afterAll, beforeEach, expect, it, vi } from "vitest";
import type { Context } from "../context";

const state = vi.hoisted(() => ({ getSession: vi.fn() }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "test".repeat(16),
    BETTER_AUTH_SECRET: ["credential", "mint", "test"].join("-"),
    BETTER_AUTH_URL: "https://wssp.example",
    CORS_ORIGIN: "https://wssp.example",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/auth", () => ({ auth: { api: { getSession: state.getSession } } }));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeSandboxWriteBudget: async () => {},
  consumeCreateConnectBudget: async () => {},
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("../lib/procedure-budget", () => ({ createProcedureBudget: () => async () => {} }));
const db = await pgTestDatabase();
const { sdkKeysRouter } = await import("./sdk-keys");
const { sandboxHostsRouter } = await import("./sandbox-hosts");
const { hostCredentialsRouter } = await import("./host-credentials");
const { invalidateForceTwoFactorSettingsCache } = await import("../lib/two-factor-policy");
const { deviceOwnerGate, deviceDecisionHandler } = await import(
  "../../../../apps/server/src/device-owner-gate.js"
);
afterAll(() => db.close());
beforeEach(() => invalidateForceTwoFactorSettingsCache());

async function owner() {
  const id = randomUUID();
  const user = await db.inspect.user.create({
    data: {
      id,
      email: `${id}@example.test`,
      name: "Owner",
      emailVerified: true,
      twoFactorEnabled: true,
      createdAt: new Date(0),
    },
  });
  const session = await db.inspect.session.create({
    data: { userId: id, token: randomUUID(), expiresAt: new Date(Date.now() + 3600000) },
  });
  const snapshot = { user, session } as Session;
  const context: Context = { session: snapshot, clientIp: undefined };
  state.getSession.mockResolvedValue(snapshot);
  return { id, session, context };
}
const reasons = ["revoked", "expired", "impersonated"] as const;
async function revoke(sessionId: string, reason: (typeof reasons)[number]) {
  if (reason === "revoked") await db.inspect.session.delete({ where: { id: sessionId } });
  else
    await db.inspect.session.update({
      where: { id: sessionId },
      data: reason === "expired" ? { expiresAt: new Date(0) } : { impersonatedBy: "admin" },
    });
}

for (const procedure of ["sdkKeys.create", "createHost", "createHostToken"] as const) {
  it.each(reasons)(`${procedure} refuses a %s session and creates no row`, async (reason) => {
    const o = await owner();
    const host = await db.inspect.sandboxHost.create({
      data: {
        userId: o.id,
        slug: "existing",
        label: "Existing",
        daemonMemoryBudgetMiB: 65536,
        daemonMaxCpuCount: 32,
      },
    });
    const sdk = createRouterClient(sdkKeysRouter, { context: o.context });
    const hosts = createRouterClient(sandboxHostsRouter, { context: o.context });
    const mint = () =>
      procedure === "sdkKeys.create"
        ? sdk.create({ name: "Test", scopes: ["commands:execute"], resourceMode: "ALL_OWNED" })
        : procedure === "createHost"
          ? hosts.createHost({ slug: "new", label: "New" })
          : hosts.createHostToken({ hostId: host.id, name: "Test" });
    await revoke(o.session.id, reason);
    await expect(mint()).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    expect(await db.inspect.sdkKey.count({ where: { userId: o.id } })).toBe(0);
    expect(await db.inspect.hostToken.count({ where: { userId: o.id } })).toBe(0);
    expect(await db.inspect.sandboxHost.count({ where: { userId: o.id } })).toBe(1);
    // The same valid input succeeds once fresh authority is supplied.
    const session = await db.inspect.session.create({
      data: { userId: o.id, token: randomUUID(), expiresAt: new Date(Date.now() + 60000) },
    });
    o.context.session = { ...o.context.session!, session } as Session;
    await expect(mint()).resolves.toBeDefined();
    expect(await db.inspect.sdkKey.count({ where: { userId: o.id } })).toBe(
      procedure === "sdkKeys.create" ? 1 : 0,
    );
    expect(await db.inspect.hostToken.count({ where: { userId: o.id } })).toBe(
      procedure === "createHostToken" ? 1 : 0,
    );
    expect(await db.inspect.sandboxHost.count({ where: { userId: o.id } })).toBe(
      procedure === "createHost" ? 2 : 1,
    );
  });
}

for (const action of ["claim", "create", "replace"] as const) {
  it.each(reasons)(
    `device ${action} refuses a %s browser session before enrollment`,
    async (reason) => {
      const o = await owner();
      const host = await db.inspect.sandboxHost.create({
        data: {
          userId: o.id,
          slug: "existing",
          label: "Existing",
          daemonMemoryBudgetMiB: 65536,
          daemonMaxCpuCount: 32,
        },
      });
      const row = await db.inspect.deviceCode.create({
        data: {
          deviceCode: randomUUID(),
          userCode: randomUUID(),
          scope: "host-slug:existing",
          userId: action === "claim" ? null : o.id,
          status: "pending",
          expiresAt: new Date(Date.now() + 60000),
          pollingInterval: 5000,
        },
      });
      const app = new Hono();
      app.use("*", deviceOwnerGate);
      app.post("/api/auth/device", deviceDecisionHandler);
      app.post("/api/auth/device/approve", deviceDecisionHandler);
      await revoke(o.session.id, reason);
      const response = await app.request(
        action === "claim" ? "/api/auth/device" : "/api/auth/device/approve",
        {
          method: "POST",
          headers: { origin: "https://wssp.example", "content-type": "application/json" },
          body: JSON.stringify({
            userCode: row.userCode,
            ...(action === "claim"
              ? {}
              : {
                  intent:
                    action === "create" ? { kind: "create" } : { kind: "replace", hostId: host.id },
                }),
          }),
        },
      );
      expect(response.status).toBe(401);
      expect(
        await db.inspect.deviceCode.findUniqueOrThrow({ where: { id: row.id } }),
      ).toMatchObject({
        status: "pending",
        userId: row.userId,
        enrollmentIntent: null,
      });
      const cli = createRouterClient(hostCredentialsRouter, { context: { session: null } });
      await expect(
        cli.exchangeDeviceCode({ deviceCode: row.deviceCode, hostSlug: "existing" }),
      ).rejects.toBeDefined();
      expect(await db.inspect.hostDeviceCredential.count({ where: { userId: o.id } })).toBe(0);
      expect(await db.inspect.sandboxHost.count({ where: { userId: o.id } })).toBe(1);
    },
  );
}

it.each(reasons)("device approval checks a session %s while reading the body", async (reason) => {
  const o = await owner();
  const row = await db.inspect.deviceCode.create({
    data: {
      deviceCode: randomUUID(),
      userCode: randomUUID(),
      scope: "host-slug:new",
      userId: o.id,
      status: "pending",
      expiresAt: new Date(Date.now() + 60000),
    },
  });
  const app = new Hono();
  app.use("*", deviceOwnerGate);
  app.post("/api/auth/device/approve", deviceDecisionHandler);
  const body = new ReadableStream<Uint8Array>(
    {
      async pull(c) {
        await revoke(o.session.id, reason);
        c.enqueue(
          new TextEncoder().encode(
            JSON.stringify({ userCode: row.userCode, intent: { kind: "create" } }),
          ),
        );
        c.close();
      },
    },
    { highWaterMark: 0 },
  );
  const response = await app.request(
    new Request("https://wssp.example/api/auth/device/approve", {
      method: "POST",
      headers: { origin: "https://wssp.example", "content-type": "application/json" },
      body,
      duplex: "half",
    } as RequestInit),
  );
  expect(response.status).toBe(401);
  expect(await db.inspect.deviceCode.findUniqueOrThrow({ where: { id: row.id } })).toMatchObject({
    status: "pending",
    enrollmentIntent: null,
  });
  expect(await db.inspect.hostDeviceCredential.count({ where: { userId: o.id } })).toBe(0);
  expect(await db.inspect.sandboxHost.count({ where: { userId: o.id } })).toBe(0);
});
