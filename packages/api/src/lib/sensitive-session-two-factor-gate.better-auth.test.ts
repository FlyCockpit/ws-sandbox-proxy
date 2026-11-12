vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { createORPCClient } from "@orpc/client";
import { RPCLink } from "@orpc/client/fetch";
import { RPCHandler } from "@orpc/server/fetch";
import { BatchHandlerPlugin } from "@orpc/server/plugins";
import { auth } from "@wssp/auth";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { admin, twoFactor } from "better-auth/plugins";
import { Hono } from "hono";
import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { requireVerifiedAdminSession } from "../../../../apps/server/src/admin-session-gate";
import { sessionMiddleware } from "../../../../apps/server/src/session-middleware";
import { createContext } from "../context";
import { appRouter } from "../routers/index";
import { invalidateForceTwoFactorSettingsCache } from "./two-factor-policy";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});

vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_SECRET: "better-auth-retained-cookie-test-secret" },
  get SIGNUP_ENABLED() {
    return true;
  },
  ADMIN_EMAILS: new Set<string>(),
}));

vi.mock("@wssp/env/shared", () => ({ env: {} }));

vi.mock("@wssp/auth", () => ({
  auth: {
    api: {
      getSession: vi.fn(),
    },
  },
}));

vi.mock("../lib/procedure-budget", () => ({
  createProcedureBudget: () => async () => {},
}));

vi.mock("@wssp/mailer", () => ({
  sendEmail: vi.fn(),
  renderInviteUser: vi.fn(() => ({ subject: "", html: "" })),
  verifyTransport: vi.fn(async () => true),
  isEmailConfigured: () => true,
}));

vi.mock("@wssp/queue", () => {
  const fakeQueue = { add: vi.fn() };
  return {
    reapExpiredAuthTokensQueue: fakeQueue,
    imageStoreMaintenanceQueue: {
      add: vi.fn(),
      upsertJobScheduler: vi.fn(),
      removeJobScheduler: vi.fn(),
    },
    checkBackupFreshnessQueue: fakeQueue,
    notifyDataDeletionsQueue: fakeQueue,
    webhookDeliveryQueue: fakeQueue,
    reapWebhookLogQueue: fakeQueue,
    ensureRunnableJob: vi.fn(),
    QUEUE_NAMES: {},
    redisConnection: {},
  };
});

const { default: prisma } = await import("@wssp/db");

const db = prisma as unknown as {
  appSetting: { findMany: MockInstance };
  sandbox: { findMany: MockInstance };
  user: { findUnique: MockInstance };
};

type MemoryAuthData = {
  user: Record<string, unknown>[];
  session: unknown[];
  account: unknown[];
  verification: unknown[];
  twoFactor: unknown[];
};

const established = new Date("2020-01-01T00:00:00.000Z");

function cookieHeaderFromSetCookie(headers: Headers): Headers {
  return new Headers({
    cookie: headers
      .getSetCookie()
      .map((value) => value.split(";")[0])
      .join("; "),
  });
}

describe("Better Auth retained cookies through Hono session and RPC transport", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    db.appSetting.findMany.mockResolvedValue([]);
    db.sandbox.findMany.mockResolvedValue([]);
    invalidateForceTwoFactorSettingsCache();
  });

  it("allows stale-unenrolled cookies after enrollment and denies stale-enrolled cookies after disable", async () => {
    const authData: MemoryAuthData = {
      user: [],
      session: [],
      account: [],
      verification: [],
      twoFactor: [],
    };
    const realAuth = betterAuth({
      database: memoryAdapter(authData),
      secret: "review-only-memory-adapter-secret-32-characters",
      baseURL: "http://localhost:3000",
      emailAndPassword: {
        enabled: true,
        requireEmailVerification: true,
        minPasswordLength: 12,
      },
      session: {
        expiresIn: 60 * 60 * 24 * 30,
        updateAge: 60 * 60 * 24,
        cookieCache: { enabled: true, maxAge: 60 },
      },
      rateLimit: { enabled: false },
      plugins: [
        admin({ defaultRole: "user" }),
        twoFactor({
          issuer: "wssp",
          allowPasswordless: false,
          otpOptions: { storeOTP: "hashed", sendOTP: async () => {} },
        }),
      ],
    });
    const ctx = await realAuth.$context;
    const password = "review-only-password-123";

    const signup = await realAuth.api.signUpEmail({
      body: { name: "Review", email: "review@example.com", password },
      returnHeaders: true,
    });
    await ctx.internalAdapter.updateUser(signup.response.user.id, {
      emailVerified: true,
      createdAt: established,
      role: "admin",
    });

    const signin = await realAuth.api.signInEmail({
      body: { email: "review@example.com", password },
      returnHeaders: true,
    });
    const initialCookies = cookieHeaderFromSetCookie(signin.headers);
    expect(
      (await realAuth.api.getSession({ headers: initialCookies }))?.user.twoFactorEnabled,
    ).toBe(false);

    const enabled = await realAuth.api.enableTwoFactor({
      body: { password, method: "otp" },
      headers: initialCookies,
      returnHeaders: true,
    });
    expect(enabled.response).toMatchObject({ method: "otp" });
    const enrolledCookies = cookieHeaderFromSetCookie(enabled.headers);

    expect(
      (await realAuth.api.getSession({ headers: initialCookies }))?.user.twoFactorEnabled,
    ).toBe(false);
    expect(
      (await realAuth.api.getSession({ headers: enrolledCookies }))?.user.twoFactorEnabled,
    ).toBe(true);

    db.user.findUnique.mockImplementation(
      async ({ where, select }: { where: { id: string }; select: Record<string, boolean> }) => {
        const row = authData.user.find((u) => u.id === where.id);
        if (!row) return null;
        return Object.fromEntries(Object.keys(select).map((key) => [key, row[key]]));
      },
    );
    vi.mocked(auth.api.getSession).mockImplementation((args) => realAuth.api.getSession(args));

    db.appSetting.findMany.mockResolvedValue([{ key: "force2faInternalUsers", value: "true" }]);
    invalidateForceTwoFactorSettingsCache();

    const handler = new RPCHandler(appRouter, {
      plugins: [new BatchHandlerPlugin({ maxSize: 10 })],
    });
    const app = new Hono();
    app.use("/rpc/*", sessionMiddleware);
    app.all("/rpc/*", async (c) => {
      const out = await handler.handle(c.req.raw, {
        prefix: "/rpc",
        context: await createContext({ context: c }),
      });
      return out.response;
    });

    const clientFor = (headers: Headers) =>
      createORPCClient(
        new RPCLink({
          url: "http://localhost/rpc",
          headers: () => Object.fromEntries(headers),
          fetch: (request) => app.request(request),
        }),
      );

    await expect(clientFor(initialCookies).sandboxes.list({ limit: 1 })).resolves.toEqual({
      items: [],
      nextCursor: null,
    });
    expect((await requireVerifiedAdminSession(initialCookies)).ok).toBe(true);

    const disabled = await realAuth.api.disableTwoFactor({
      body: { password },
      headers: enrolledCookies,
      returnHeaders: true,
    });
    expect(disabled.response).toEqual({ status: true });
    expect(await realAuth.api.getSession({ headers: enrolledCookies })).toBeNull();
    expect(
      (await realAuth.api.getSession({ headers: cookieHeaderFromSetCookie(disabled.headers) }))
        ?.user.twoFactorEnabled,
    ).toBe(false);
    expect(
      await realAuth.api.getSession({
        headers: enrolledCookies,
        query: { disableCookieCache: true },
      }),
    ).toBeNull();

    db.sandbox.findMany.mockClear();
    await expect(clientFor(enrolledCookies).sandboxes.list({ limit: 1 })).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
    await expect(clientFor(enrolledCookies).queue.backupStatus()).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
    expect(await requireVerifiedAdminSession(enrolledCookies)).toMatchObject({
      ok: false,
      status: 404,
    });
    expect(db.sandbox.findMany).not.toHaveBeenCalled();
  });
});
