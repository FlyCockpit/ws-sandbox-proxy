import { createRouterClient, ORPCError } from "@orpc/server";
import { RPCHandler } from "@orpc/server/fetch";
import type { Session } from "@wssp/auth";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_SECRET: "test-better-auth-secret" },
}));

vi.mock("@wssp/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep() };
});

vi.mock("../lib/sensitive-session-two-factor-gate", () => ({
  isLiveOwnerSessionAuthorized: vi.fn().mockResolvedValue(true),
  isSensitiveSessionTwoFactorPolicySatisfied: vi.fn().mockResolvedValue(true),
  loadSensitiveSessionGateUser: vi.fn(),
}));
const { loadSensitiveSessionGateUser } = await import("../lib/sensitive-session-two-factor-gate");

const budget = vi.hoisted(() => vi.fn().mockResolvedValue(undefined));
vi.mock("../lib/procedure-budget", () => ({ createProcedureBudget: () => budget }));
vi.mock("../lib/owner-credential-policy", () => ({
  ownerCredentialPolicyUserSelect: {},
  isOwnerCredentialPolicySatisfied: vi.fn().mockResolvedValue(true),
}));
const { default: prisma } = await import("@wssp/db");
const { hostCredentialsRouter } = await import("./host-credentials");

const db = prisma as unknown as {
  $transaction: ReturnType<typeof vi.fn>;
  $queryRaw: ReturnType<typeof vi.fn>;
  appSetting: { findMany: ReturnType<typeof vi.fn> };
  user: { findUnique: ReturnType<typeof vi.fn> };
  deviceCode: {
    findUnique: ReturnType<typeof vi.fn>;
    findFirst: ReturnType<typeof vi.fn>;
    updateMany: ReturnType<typeof vi.fn>;
    deleteMany: ReturnType<typeof vi.fn>;
  };
  sandboxHost: {
    findUnique: ReturnType<typeof vi.fn>;
    create: ReturnType<typeof vi.fn>;
  };
  hostDeviceCredential: {
    create: ReturnType<typeof vi.fn>;
    findMany: ReturnType<typeof vi.fn>;
    updateMany: ReturnType<typeof vi.fn>;
  };
};

function deviceCodeRow(overrides: Record<string, unknown> = {}) {
  return {
    id: "device-code-row-1",
    userId: "user-1",
    expiresAt: new Date(Date.now() + 10 * 60_000),
    status: "approved",
    enrollmentIntent: "create",
    replaceHostId: null,
    lastPolledAt: null,
    pollingInterval: 5000,
    scope: "host-slug:desk-01",
    ...overrides,
  };
}

function buildContext(sessionOverride?: Partial<Session["user"]> | null) {
  if (sessionOverride === null) return { session: null };
  return {
    session: {
      user: {
        id: "user-1",
        email: "test@example.com",
        name: "Test User",
        emailVerified: true,
        role: "user",
        twoFactorEnabled: true,
        image: null,
        banned: false,
        banReason: null,
        banExpires: null,
        createdAt: new Date("2026-01-01T00:00:00.000Z"),
        updatedAt: new Date("2026-01-01T00:00:00.000Z"),
        ...sessionOverride,
      },
      session: {
        id: "session-1",
        userId: "user-1",
        token: "session-token",
        expiresAt: new Date(Date.now() + 60_000),
        ipAddress: "127.0.0.1",
        userAgent: "vitest",
        createdAt: new Date("2026-01-01T00:00:00.000Z"),
        updatedAt: new Date("2026-01-01T00:00:00.000Z"),
      },
    } as Session,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  db.$transaction.mockImplementation(async (callback: (tx: typeof db) => unknown) => callback(db));
  budget.mockResolvedValue(undefined);
  db.$queryRaw.mockResolvedValue([{ now: new Date() }]);
  db.appSetting.findMany.mockResolvedValue([]);
  vi.mocked(loadSensitiveSessionGateUser).mockResolvedValue({
    emailVerified: true,
    twoFactorEnabled: true,
    role: "user",
    banned: false,
    banExpires: null,
    createdAt: new Date("2020-01-01"),
  });
  db.user.findUnique.mockResolvedValue({ emailVerified: true });
  db.deviceCode.updateMany.mockResolvedValue({ count: 1 });
  db.deviceCode.deleteMany.mockResolvedValue({ count: 1 });
  db.sandboxHost.create.mockResolvedValue({ id: "host-1" });
  db.hostDeviceCredential.create.mockResolvedValue({ id: "credential-1", userId: "user-1" });
  db.hostDeviceCredential.findMany.mockResolvedValue([]);
  db.hostDeviceCredential.updateMany.mockResolvedValue({ count: 0 });
});

describe("hostCredentialsRouter", () => {
  it("exchanges an approved device code without a browser session", async () => {
    db.deviceCode.findUnique.mockResolvedValue(deviceCodeRow());
    const client = createRouterClient(hostCredentialsRouter, { context: buildContext(null) });

    const result = await client.exchangeDeviceCode({
      deviceCode: "approved-device-code",
      hostSlug: "desk-01",
    });

    expect(result.secret).toMatch(/^wssp_device_/);
    expect(result).toMatchObject({
      credentialId: "credential-1",
      userId: "user-1",
      hostId: "host-1",
    });
  });

  it("sends device-flow state on the wire in the oRPC json envelope", async () => {
    db.deviceCode.findUnique.mockResolvedValue(
      deviceCodeRow({ userId: null, status: "pending", scope: "host-slug:pending-ci" }),
    );
    const handler = new RPCHandler(hostCredentialsRouter);

    const result = await handler.handle(
      new Request("https://example.test/rpc/exchangeDeviceCode", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ json: { deviceCode: "device-code", hostSlug: "pending-ci" } }),
      }),
      { prefix: "/rpc", context: buildContext(null) },
    );

    expect(result.matched).toBe(true);
    if (!result.matched) return;
    expect(result.response.status).toBe(400);
    expect(await result.response.json()).toMatchObject({
      json: {
        code: "BAD_REQUEST",
        data: { deviceFlowError: "authorization_pending" },
      },
    });
  });

  it("deviceLoginRequest requires protected session and shows slug", async () => {
    db.deviceCode.findFirst.mockResolvedValue(deviceCodeRow({ status: "pending" }));
    db.sandboxHost.findUnique.mockResolvedValue(null);
    const client = createRouterClient(hostCredentialsRouter, { context: buildContext() });

    await expect(client.deviceLoginRequest({ userCode: "ABCD-EFGH" })).resolves.toEqual({
      kind: "host",
      requestId: "device-code-row-1",
      status: "pending",
      slug: "desk-01",
      existingHost: null,
    });
    expect(db.deviceCode.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { userCode: { in: ["ABCD-EFGH", "ABCDEFGH"] }, userId: "user-1" },
      }),
    );
  });

  it("deviceLoginRequest describes a user login by kind only, with nothing the CLI chose", async () => {
    db.deviceCode.findFirst.mockResolvedValue(
      deviceCodeRow({ status: "pending", scope: "user-login" }),
    );
    const client = createRouterClient(hostCredentialsRouter, { context: buildContext() });
    await expect(client.deviceLoginRequest({ userCode: "ABCDEFGH" })).resolves.toEqual({
      kind: "user",
      requestId: "device-code-row-1",
      status: "pending",
    });
    expect(db.sandboxHost.findUnique).not.toHaveBeenCalled();
  });

  it("host exchange refuses a user-login code before polling or consuming it", async () => {
    db.deviceCode.findUnique.mockResolvedValue(deviceCodeRow({ scope: "user-login" }));
    const client = createRouterClient(hostCredentialsRouter, { context: buildContext(null) });
    await expect(
      client.exchangeDeviceCode({ deviceCode: "approved-device-code", hostSlug: "desk-01" }),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    expect(db.$transaction).not.toHaveBeenCalled();
  });

  it("deviceLoginRequest requires authentication", async () => {
    const client = createRouterClient(hostCredentialsRouter, { context: buildContext(null) });
    await expect(client.deviceLoginRequest({ userCode: "ABCDEFGH" })).rejects.toSatisfy(
      (error: ORPCError) => error.code === "UNAUTHORIZED",
    );
  });

  it("deviceLoginRequest rejects unverified email through the router", async () => {
    vi.mocked(loadSensitiveSessionGateUser).mockResolvedValueOnce({
      emailVerified: false,
      twoFactorEnabled: true,
      role: "user",
      banned: false,
      banExpires: null,
      createdAt: new Date("2020-01-01"),
    });
    const client = createRouterClient(hostCredentialsRouter, { context: buildContext() });
    await expect(client.deviceLoginRequest({ userCode: "ABCDEFGH" })).rejects.toMatchObject({
      code: "FORBIDDEN",
    });
    expect(db.deviceCode.findFirst).not.toHaveBeenCalled();
  });
});

it("success crosses the real RPCHandler in the json envelope", async () => {
  db.deviceCode.findUnique.mockResolvedValue(deviceCodeRow());
  const handler = new RPCHandler(hostCredentialsRouter);
  const result = await handler.handle(
    new Request("https://example.test/rpc/exchangeDeviceCode", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ json: { deviceCode: "approved-device-code", hostSlug: "desk-01" } }),
    }),
    { prefix: "/rpc", context: buildContext(null) },
  );
  expect(result.matched).toBe(true);
  if (!result.matched) throw new Error("not matched");
  expect(result.response.status).toBe(200);
  expect(await result.response.json()).toEqual({
    json: {
      credentialId: "credential-1",
      userId: "user-1",
      hostId: "host-1",
      secret: expect.stringMatching(/^wssp_device_/),
    },
  });
});
it("budget rejection prevents exchange work for every procedure invocation", async () => {
  budget.mockRejectedValueOnce(new ORPCError("TOO_MANY_REQUESTS"));
  const before = db.deviceCode.findUnique.mock.calls.length;
  const client = createRouterClient(hostCredentialsRouter, {
    context: { session: null, clientIp: "192.0.2.1" },
  });
  await expect(
    client.exchangeDeviceCode({ deviceCode: "code", hostSlug: "desk-01" }),
  ).rejects.toMatchObject({ code: "TOO_MANY_REQUESTS" });
  expect(budget).toHaveBeenLastCalledWith("ip:192.0.2.1");
  expect(db.deviceCode.findUnique.mock.calls.length).toBe(before);
});
