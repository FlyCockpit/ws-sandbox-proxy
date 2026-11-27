import { randomUUID } from "node:crypto";
import { createRouterClient } from "@orpc/server";
import type { Session } from "@wssp/auth";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { Hono } from "hono";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * `wssp login` under real PostgreSQL: approval through the real device decision
 * handler, the user-login exchange (consume once, active-login cap, pool access
 * re-checked at mint), the host/user exchange split and the `/v1` self-revoke.
 */
const state = vi.hoisted(() => ({ getSession: vi.fn() }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "test".repeat(16),
    BETTER_AUTH_SECRET: ["user", "login", "test"].join("-"),
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
vi.mock("./procedure-budget", () => ({ createProcedureBudget: () => async () => {} }));

const db = await pgTestDatabase();
const { userLoginsRouter } = await import("../routers/user-logins");
const { hostCredentialsRouter } = await import("../routers/host-credentials");
const { invalidateForceTwoFactorSettingsCache } = await import("./two-factor-policy");
const { authenticateSdkKeySecret } = await import("./sdk-key-access");
const { getSelfKey, revokeSelfKey } = await import("../sandbox/services/self-key");
const { createSdkKey } = await import("../sandbox/services/sdk-keys");
const { sessionPrincipal } = await import("../sandbox/contracts");
const { deviceOwnerGate, deviceDecisionHandler } = await import(
  "../../../../apps/server/src/device-owner-gate.js"
);
afterAll(() => db.close());
beforeEach(() => invalidateForceTwoFactorSettingsCache());

const grant = {
  access: "write",
  poolMode: "ALL_USABLE",
  poolIds: [] as string[],
  ownSandboxesOnly: true,
  maxLiveSandboxes: 2,
  expiresInDays: 7,
  name: "laptop",
};
const cli = () =>
  createRouterClient(userLoginsRouter, { context: { session: null, clientIp: "192.0.2.7" } });

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
  state.getSession.mockResolvedValue({ user, session } as Session);
  return { id, email: user.email, sessionId: session.id };
}

function deviceRow(
  userId: string | null,
  data: { scope?: string; status?: string; loginGrant?: object } = {},
) {
  return db.inspect.deviceCode.create({
    data: {
      deviceCode: randomUUID(),
      userCode: randomUUID(),
      scope: "user-login",
      userId,
      status: "pending",
      expiresAt: new Date(Date.now() + 600000),
      pollingInterval: 5000,
      ...data,
    },
  });
}

async function approve(userCode: string, body: Record<string, unknown>) {
  const app = new Hono();
  app.use("*", deviceOwnerGate);
  app.post("/api/auth/device/approve", deviceDecisionHandler);
  return app.request("/api/auth/device/approve", {
    method: "POST",
    headers: { origin: "https://wssp.example", "content-type": "application/json" },
    body: JSON.stringify({ userCode, ...body }),
  });
}

describe("user-login device flow", () => {
  it("approve then exchange mints exactly the chosen key once; a second exchange is NOT_FOUND", async () => {
    const o = await owner();
    const row = await deviceRow(o.id);
    const approved = await approve(row.userCode, { grant });
    expect(approved.status).toBe(200);
    expect(await db.inspect.deviceCode.findUniqueOrThrow({ where: { id: row.id } })).toMatchObject({
      status: "approved",
      enrollmentIntent: null,
      loginGrant: grant,
    });

    const minted = await cli().exchangeDeviceCode({ deviceCode: row.deviceCode });
    expect(minted).toMatchObject({
      name: "laptop",
      userId: o.id,
      email: o.email,
      poolMode: "ALL_USABLE",
      poolIds: [],
      ownSandboxesOnly: true,
      maxLiveSandboxes: 2,
    });
    expect(minted.secret).toMatch(/^wssp_sdk_/);
    expect(minted.scopes).toContain("sandboxes:create");
    expect(minted.scopes).not.toContain("hosts:execute");
    const days = (minted.expiresAt.getTime() - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(6.99);
    expect(days).toBeLessThanOrEqual(7);
    expect(
      await db.inspect.sdkKey.findUniqueOrThrow({ where: { id: minted.keyId } }),
    ).toMatchObject({
      kind: "API",
      origin: "CLI_LOGIN",
      resourceMode: "ALL_OWNED",
      maxLiveSandboxes: 2,
    });
    expect(await db.inspect.deviceCode.count({ where: { id: row.id } })).toBe(0);

    await expect(cli().exchangeDeviceCode({ deviceCode: row.deviceCode })).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
    expect(await db.inspect.sdkKey.count({ where: { userId: o.id } })).toBe(1);

    // The minted key works on /v1 and describes itself without the email.
    const principal = await authenticateSdkKeySecret(minted.secret);
    if (!principal) throw new Error("minted key inactive");
    const self = await getSelfKey(principal, undefined);
    expect(self).toMatchObject({
      id: minted.keyId,
      origin: "cliLogin",
      maxLiveSandboxes: 2,
      liveSandboxes: 0,
      ownSandboxesOnly: true,
    });
    expect(JSON.stringify(self)).not.toContain(o.email);
  });

  it("an unapproved code polls as pending through the shared poll contract", async () => {
    const o = await owner();
    const row = await deviceRow(o.id);
    await expect(cli().exchangeDeviceCode({ deviceCode: row.deviceCode })).rejects.toMatchObject({
      code: "BAD_REQUEST",
      data: { deviceFlowError: "authorization_pending" },
    });
    await expect(cli().exchangeDeviceCode({ deviceCode: row.deviceCode })).rejects.toMatchObject({
      data: { deviceFlowError: "slow_down" },
    });
  });

  it("caps active CLI logins at 20; a revoked one frees a slot and the refused code stays", async () => {
    const o = await owner();
    const minted = [];
    for (let i = 0; i < 20; i++) {
      const row = await deviceRow(o.id, { status: "approved", loginGrant: grant });
      minted.push(await cli().exchangeDeviceCode({ deviceCode: row.deviceCode }));
    }
    const over = await deviceRow(o.id, { status: "approved", loginGrant: grant });
    await expect(cli().exchangeDeviceCode({ deviceCode: over.deviceCode })).rejects.toMatchObject({
      code: "CONFLICT",
      data: { code: "user_login.limit" },
    });
    expect(await db.inspect.deviceCode.count({ where: { id: over.id } })).toBe(1);
    // Dashboard keys do not count against the CLI-login cap.
    await createSdkKey(sessionPrincipal(o.id, o.sessionId), {
      name: "dashboard",
      scopes: ["sandboxes:read"],
      resourceMode: "ALL_OWNED",
    });
    const first = await authenticateSdkKeySecret(minted[0]!.secret);
    if (!first) throw new Error("minted key inactive");
    await revokeSelfKey(first, undefined);
    await expect(cli().exchangeDeviceCode({ deviceCode: over.deviceCode })).resolves.toMatchObject({
      userId: o.id,
    });
  });

  it("a selected pool that became unusable after approval refuses the exchange and keeps the code", async () => {
    const o = await owner();
    const pool = await db.inspect.sandboxPool.create({
      data: { userId: o.id, slug: "lab", label: "Lab" },
    });
    const row = await deviceRow(o.id);
    const selected = { ...grant, poolMode: "SELECTED", poolIds: [pool.id] };
    expect((await approve(row.userCode, { grant: selected })).status).toBe(200);
    await db.inspect.sandboxPool.update({
      where: { id: pool.id },
      data: { deletedAt: new Date() },
    });
    await expect(cli().exchangeDeviceCode({ deviceCode: row.deviceCode })).rejects.toMatchObject({
      code: "FORBIDDEN",
      data: { code: "user_login.pool_unavailable" },
    });
    expect(await db.inspect.deviceCode.count({ where: { id: row.id } })).toBe(1);
    expect(await db.inspect.sdkKey.count({ where: { userId: o.id } })).toBe(0);
  });

  it("approval refuses a pool the approver cannot use, an intent on a user login and a grant on a host enrollment", async () => {
    const o = await owner();
    const stranger = await db.inspect.user.create({
      data: { id: randomUUID(), email: `${randomUUID()}@example.test`, name: "Other" },
    });
    const foreign = await db.inspect.sandboxPool.create({
      data: { userId: stranger.id, slug: "theirs", label: "Theirs" },
    });
    const row = await deviceRow(o.id);
    const refused = await approve(row.userCode, {
      grant: { ...grant, poolMode: "SELECTED", poolIds: [foreign.id] },
    });
    expect(refused.status).toBe(404);
    expect((await approve(row.userCode, { intent: { kind: "create" } })).status).toBe(400);
    const host = await deviceRow(o.id, { scope: "host-slug:desk" });
    expect((await approve(host.userCode, { grant })).status).toBe(400);
    for (const id of [row.id, host.id])
      expect(await db.inspect.deviceCode.findUniqueOrThrow({ where: { id } })).toMatchObject({
        status: "pending",
        loginGrant: null,
        enrollmentIntent: null,
      });
  });

  it("the host exchange refuses a user-login code and the user exchange refuses a host code", async () => {
    const o = await owner();
    const user = await deviceRow(o.id, { status: "approved", loginGrant: grant });
    const hosts = createRouterClient(hostCredentialsRouter, { context: { session: null } });
    await expect(
      hosts.exchangeDeviceCode({ deviceCode: user.deviceCode, hostSlug: "desk" }),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    const host = await db.inspect.deviceCode.create({
      data: {
        deviceCode: randomUUID(),
        userCode: randomUUID(),
        scope: "host-slug:desk",
        userId: o.id,
        status: "approved",
        enrollmentIntent: "create",
        expiresAt: new Date(Date.now() + 600000),
      },
    });
    await expect(cli().exchangeDeviceCode({ deviceCode: host.deviceCode })).rejects.toMatchObject({
      code: "BAD_REQUEST",
    });
    // Neither code was polled or consumed by the wrong exchange.
    for (const id of [user.id, host.id])
      expect(await db.inspect.deviceCode.findUniqueOrThrow({ where: { id } })).toMatchObject({
        status: "approved",
        lastPolledAt: null,
      });
    expect(await db.inspect.sdkKey.count({ where: { userId: o.id } })).toBe(0);
    expect(await db.inspect.hostDeviceCredential.count({ where: { userId: o.id } })).toBe(0);
  });

  it("a CLI login revokes itself and stops authenticating; a dashboard key cannot", async () => {
    const o = await owner();
    const row = await deviceRow(o.id, { status: "approved", loginGrant: grant });
    const minted = await cli().exchangeDeviceCode({ deviceCode: row.deviceCode });
    const principal = await authenticateSdkKeySecret(minted.secret);
    if (!principal) throw new Error("minted key inactive");
    await expect(revokeSelfKey(principal, undefined)).resolves.toEqual({
      id: minted.keyId,
      revoked: true,
    });
    expect(await authenticateSdkKeySecret(minted.secret)).toBeNull();

    const dashboard = await createSdkKey(sessionPrincipal(o.id, o.sessionId), {
      name: "dashboard",
      scopes: ["sandboxes:read"],
      resourceMode: "ALL_OWNED",
    });
    const keyPrincipal = await authenticateSdkKeySecret(dashboard.secret);
    if (!keyPrincipal) throw new Error("dashboard key inactive");
    await expect(revokeSelfKey(keyPrincipal, undefined)).rejects.toMatchObject({
      code: "FORBIDDEN",
      data: { code: "key.self_revoke_forbidden" },
    });
    expect(await authenticateSdkKeySecret(dashboard.secret)).not.toBeNull();
  });
});
