vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { createRouterClient, ORPCError } from "@orpc/server";
import type { Session } from "@wssp/auth";
import { PASSWORD_CHANGE_REQUIRED_ERROR_CODE } from "@wssp/auth/two-factor-policy";
import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Context } from "../context";
import { checkLiveOwnerSession } from "../index";
import {
  isLiveOwnerSessionAuthorized,
  sensitiveSessionRefusal,
} from "../lib/sensitive-session-two-factor-gate";
import { invalidateForceTwoFactorSettingsCache } from "../lib/two-factor-policy";
import { appRouter } from "../routers/index";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});

vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_SECRET: "stale-session-gate-secret" },
  get SIGNUP_ENABLED() {
    return true;
  },
  ADMIN_EMAILS: new Set<string>(),
}));

vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/auth", () => ({ auth: { api: {} } }));
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
  user: { findUnique: MockInstance };
  sandbox: { findMany: MockInstance };
};

const established = new Date("2020-01-01T00:00:00.000Z");

function buildContext(userOverrides: Partial<Session["user"]> = {}): Context {
  const user = {
    id: "user-1",
    email: "user@example.com",
    name: "User",
    emailVerified: true,
    role: "user",
    twoFactorEnabled: false,
    image: null,
    banned: false,
    banReason: null,
    banExpires: null,
    createdAt: established,
    updatedAt: established,
    ...userOverrides,
  };
  return {
    session: {
      user,
      session: {
        id: "sess-1",
        userId: user.id,
        token: "token",
        expiresAt: new Date(Date.now() + 86_400_000),
        ipAddress: null,
        userAgent: null,
        createdAt: established,
        updatedAt: established,
      },
    } as Session,
  };
}

function mockAuthoritativeUser(user: Session["user"], mustChangePassword = false) {
  db.user.findUnique.mockImplementation(async ({ where }: { where: { id: string } }) => {
    if (where.id !== user.id) return null;
    return {
      mustChangePassword,
      twoFactorEnabled: user.twoFactorEnabled,
      role: user.role,
      emailVerified: user.emailVerified,
      banned: user.banned,
      banExpires: user.banExpires,
      createdAt: user.createdAt,
    };
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  db.appSetting.findMany.mockResolvedValue([{ key: "force2faPublicUsers", value: "true" }]);
  db.sandbox.findMany.mockResolvedValue([]);
  invalidateForceTwoFactorSettingsCache();
});

describe("authoritative sensitive session 2FA gate", () => {
  it("denies sandboxes.list when the cookie session still shows enrolled but DB shows disabled", async () => {
    const sessionUser = buildContext({
      twoFactorEnabled: true,
      createdAt: established,
    }).session!.user;
    mockAuthoritativeUser({ ...sessionUser, twoFactorEnabled: false });

    const client = createRouterClient(appRouter, {
      context: buildContext({ twoFactorEnabled: true, createdAt: established }),
    });
    await expect(client.sandboxes.list({ limit: 1 })).rejects.toSatisfy((error: ORPCError) => {
      expect(error.code).toBe("FORBIDDEN");
      return true;
    });
  });

  it("allows sandboxes.list when the cookie session is stale-unenrolled but DB shows enrolled", async () => {
    const sessionUser = buildContext({
      twoFactorEnabled: false,
      createdAt: established,
    }).session!.user;
    mockAuthoritativeUser({ ...sessionUser, twoFactorEnabled: true });

    const client = createRouterClient(appRouter, {
      context: buildContext({ twoFactorEnabled: false, createdAt: established }),
    });
    await expect(client.sandboxes.list({ limit: 1 })).resolves.toEqual({
      items: [],
      nextCursor: null,
    });
  });
});

describe("admin-set temporary password gate", () => {
  it("refuses protected procedures with its own code until the password is replaced, before 2FA", async () => {
    // Enrolled or not, the pending password change is what the caller hears.
    for (const twoFactorEnabled of [true, false]) {
      const context = buildContext({ twoFactorEnabled });
      mockAuthoritativeUser(context.session!.user, true);
      const client = createRouterClient(appRouter, { context });
      await expect(client.sandboxes.list({ limit: 1 })).rejects.toMatchObject({
        code: "FORBIDDEN",
        data: { code: PASSWORD_CHANGE_REQUIRED_ERROR_CODE },
      });
    }
    const context = buildContext({ twoFactorEnabled: true });
    mockAuthoritativeUser(context.session!.user, false);
    await expect(
      createRouterClient(appRouter, { context }).sandboxes.list({ limit: 1 }),
    ).resolves.toEqual({ items: [], nextCursor: null });
  });

  it("a revoked session's cookie cache does not pass once the flag is cleared", async () => {
    const context = buildContext({ twoFactorEnabled: true });
    mockAuthoritativeUser(context.session!.user, false);
    // The password change deleted this session's row; its signed cookie
    // cache still names it for up to a minute.
    vi.mocked(prisma.session.findUnique).mockResolvedValueOnce(null);
    await expect(
      createRouterClient(appRouter, { context }).sandboxes.list({ limit: 1 }),
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    await expect(
      createRouterClient(appRouter, { context }).sandboxes.list({ limit: 1 }),
    ).resolves.toEqual({ items: [], nextCursor: null });
  });

  it("reads the session row only after the flag", async () => {
    // A password change deletes the sessions before it writes the password,
    // and the flag clears only after that write, so a cleared flag must never
    // be paired with a session row read before it was seen.
    const context = buildContext({ twoFactorEnabled: true });
    mockAuthoritativeUser(context.session!.user, false);
    const row = await prisma.user.findUnique({ where: { id: "user-1" } });
    let release: (value: unknown) => void = () => {};
    vi.mocked(prisma.user.findUnique).mockImplementationOnce(
      () => new Promise((resolve) => (release = resolve)) as never,
    );
    const sessionRead = vi.mocked(prisma.session.findUnique);
    sessionRead.mockClear();
    const call = createRouterClient(appRouter, { context }).sandboxes.list({ limit: 1 });
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(sessionRead).not.toHaveBeenCalled();
    release(row);
    await expect(call).resolves.toEqual({ items: [], nextCursor: null });
    expect(sessionRead).toHaveBeenCalled();
  });

  it("hides the admin area and refuses live owner authority while it is pending", async () => {
    const context = buildContext({ twoFactorEnabled: true, role: "admin" });
    mockAuthoritativeUser(context.session!.user, true);
    await expect(
      createRouterClient(appRouter, { context }).users.list({ limit: 1 }),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
    expect(await isLiveOwnerSessionAuthorized(context.session)).toBe(false);
    expect(await sensitiveSessionRefusal("user-1")).toBe("password_change_required");
    mockAuthoritativeUser(context.session!.user, false);
    expect(await sensitiveSessionRefusal("user-1")).toBeNull();
  });
});

it("IO fencing checks durable authority once without a middleware exit check", async () => {
  const context = buildContext({ twoFactorEnabled: true });
  mockAuthoritativeUser(context.session!.user);
  const sessionRead = vi.spyOn(prisma.session, "findUnique");
  // The shared mock supplies a live row; count the actual gate queries.
  await checkLiveOwnerSession(context.session);
  expect(sessionRead).toHaveBeenCalledTimes(1);
  expect(db.user.findUnique).toHaveBeenCalledTimes(1);
});
