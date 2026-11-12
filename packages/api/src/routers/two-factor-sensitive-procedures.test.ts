vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { createRouterClient, ORPCError } from "@orpc/server";
import type { Session } from "@wssp/auth";
import { TWO_FACTOR_REQUIRED_ERROR_CODE } from "@wssp/auth/two-factor-policy";
import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Context } from "../context";
import { invalidateForceTwoFactorSettingsCache } from "../lib/two-factor-policy";
import { appRouter } from "./index";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});

vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_SECRET: "two-factor-sensitive-test-secret" },
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
  sandboxHost: { findMany: MockInstance };
  sandboxTemplate: { findMany: MockInstance };
  sdkKey: { findMany: MockInstance };
  sandboxOperation: { findFirst: MockInstance };
};

function wireAuthoritativeUser(user: Session["user"]) {
  db.user.findUnique.mockResolvedValue({
    twoFactorEnabled: user.twoFactorEnabled,
    role: user.role,
    emailVerified: user.emailVerified,
    banned: user.banned,
    banExpires: user.banExpires,
    createdAt: user.createdAt,
  });
}

const established = new Date("2020-01-01T00:00:00.000Z");
const justSignedUp = new Date(Date.now() - 60_000);

function buildContext(
  overrides: Partial<Session["user"]> = {},
  sessionOverride: Partial<Session["session"]> | null = {},
): Context {
  return {
    session: {
      user: {
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
        ...overrides,
      },
      session: {
        id: "sess-1",
        userId: overrides.id ?? "user-1",
        token: "token",
        expiresAt: new Date(Date.now() + 86_400_000),
        ipAddress: null,
        userAgent: null,
        createdAt: established,
        updatedAt: established,
        ...(sessionOverride ?? {}),
      },
    } as Session,
  };
}

const SENSITIVE_ROUTER_SAMPLES = [
  [
    "sandboxes.list",
    (client: ReturnType<typeof createRouterClient<typeof appRouter>>) =>
      client.sandboxes.list({ limit: 1 }),
  ],
  [
    "sandboxes.getCommandOutput",
    (client: ReturnType<typeof createRouterClient<typeof appRouter>>) =>
      client.sandboxes.getCommandOutput({ operationId: "op-1" }),
  ],
  [
    "sandboxHosts.listHosts",
    (client: ReturnType<typeof createRouterClient<typeof appRouter>>) =>
      client.sandboxHosts.listHosts({ limit: 1 }),
  ],
  // C44: every host mutation the Hosts page sends is gated the same way.
  [
    "sandboxHosts.updateHost",
    (client: ReturnType<typeof createRouterClient<typeof appRouter>>) =>
      client.sandboxHosts.updateHost({ id: "host-1" }),
  ],
  [
    "sandboxHosts.setHostDraining",
    (client: ReturnType<typeof createRouterClient<typeof appRouter>>) =>
      client.sandboxHosts.setHostDraining({ id: "host-1", draining: true }),
  ],
  [
    "sandboxHosts.deleteHost",
    (client: ReturnType<typeof createRouterClient<typeof appRouter>>) =>
      client.sandboxHosts.deleteHost({ id: "host-1" }),
  ],
  [
    "sandboxTemplates.listTemplates",
    (client: ReturnType<typeof createRouterClient<typeof appRouter>>) =>
      client.sandboxTemplates.listTemplates({ limit: 1 }),
  ],
  // C46: the templates page's other procedures.
  [
    "sandboxTemplates.getTemplate",
    (client: ReturnType<typeof createRouterClient<typeof appRouter>>) =>
      client.sandboxTemplates.getTemplate({ id: "template-1" }),
  ],
  [
    "sandboxTemplates.createTemplate",
    (client: ReturnType<typeof createRouterClient<typeof appRouter>>) =>
      client.sandboxTemplates.createTemplate({
        hostId: "host-1",
        slug: "base",
        label: "Base",
        imageRef: "local:base",
      }),
  ],
  [
    "sandboxTemplates.retireTemplate",
    (client: ReturnType<typeof createRouterClient<typeof appRouter>>) =>
      client.sandboxTemplates.retireTemplate({ id: "template-1" }),
  ],
  [
    "sdkKeys.list",
    (client: ReturnType<typeof createRouterClient<typeof appRouter>>) =>
      client.sdkKeys.list({ limit: 1 }),
  ],
  // C45: every credential procedure the credentials pages send.
  [
    "sdkKeys.create",
    (client: ReturnType<typeof createRouterClient<typeof appRouter>>) =>
      client.sdkKeys.create({ name: "ci", scopes: ["hosts:read"], resourceMode: "ALL_OWNED" }),
  ],
  [
    "sdkKeys.revoke",
    (client: ReturnType<typeof createRouterClient<typeof appRouter>>) =>
      client.sdkKeys.revoke({ id: "key-1" }),
  ],
  [
    "sandboxHosts.listHostTokens",
    (client: ReturnType<typeof createRouterClient<typeof appRouter>>) =>
      client.sandboxHosts.listHostTokens({ limit: 1 }),
  ],
  [
    "sandboxHosts.createHostToken",
    (client: ReturnType<typeof createRouterClient<typeof appRouter>>) =>
      client.sandboxHosts.createHostToken({ hostId: "host-1", name: "daemon" }),
  ],
  [
    "sandboxHosts.revokeHostToken",
    (client: ReturnType<typeof createRouterClient<typeof appRouter>>) =>
      client.sandboxHosts.revokeHostToken({ id: "token-1" }),
  ],
  [
    "sandboxHosts.listDeviceCredentials",
    (client: ReturnType<typeof createRouterClient<typeof appRouter>>) =>
      client.sandboxHosts.listDeviceCredentials({ limit: 1 }),
  ],
  [
    "sandboxHosts.revokeDeviceCredential",
    (client: ReturnType<typeof createRouterClient<typeof appRouter>>) =>
      client.sandboxHosts.revokeDeviceCredential({ id: "device-1" }),
  ],
  // Webhooks: every write opens an outbound data channel or reveals a secret.
  [
    "webhooks.list",
    (client: ReturnType<typeof createRouterClient<typeof appRouter>>) =>
      client.webhooks.list({ limit: 1 }),
  ],
  [
    "webhooks.create",
    (client: ReturnType<typeof createRouterClient<typeof appRouter>>) =>
      client.webhooks.create({ url: "https://hooks.example.com/x", events: ["sandbox.ready"] }),
  ],
  [
    "webhooks.update",
    (client: ReturnType<typeof createRouterClient<typeof appRouter>>) =>
      client.webhooks.update({
        id: "whe-1",
        url: "https://hooks.example.com/x",
        description: null,
        events: ["sandbox.ready"],
        operationKinds: "all",
        enabled: true,
      }),
  ],
  [
    "webhooks.delete",
    (client: ReturnType<typeof createRouterClient<typeof appRouter>>) =>
      client.webhooks.delete({ id: "whe-1" }),
  ],
  [
    "webhooks.rotateSecret",
    (client: ReturnType<typeof createRouterClient<typeof appRouter>>) =>
      client.webhooks.rotateSecret({ id: "whe-1" }),
  ],
  [
    "webhooks.test",
    (client: ReturnType<typeof createRouterClient<typeof appRouter>>) =>
      client.webhooks.test({ id: "whe-1" }),
  ],
  [
    "webhooks.redeliver",
    (client: ReturnType<typeof createRouterClient<typeof appRouter>>) =>
      client.webhooks.redeliver({ id: "whd-1" }),
  ],
] as const;

beforeEach(() => {
  vi.clearAllMocks();
  db.appSetting.findMany.mockResolvedValue([]);
  db.sandbox.findMany.mockResolvedValue([]);
  db.sandboxHost.findMany.mockResolvedValue([]);
  db.sandboxTemplate.findMany.mockResolvedValue([]);
  db.sdkKey.findMany.mockResolvedValue([]);
  db.sandboxOperation.findFirst.mockResolvedValue(null);
  invalidateForceTwoFactorSettingsCache();
});

describe("C18 sensitive browser procedures", () => {
  it.each(SENSITIVE_ROUTER_SAMPLES)(
    "%s rejects established unenrolled users when public force-2FA is on",
    async (_path, invoke) => {
      db.appSetting.findMany.mockResolvedValue([{ key: "force2faPublicUsers", value: "true" }]);
      invalidateForceTwoFactorSettingsCache();
      const ctx = buildContext({ role: "user", twoFactorEnabled: false, createdAt: established });
      wireAuthoritativeUser(ctx.session!.user);
      const client = createRouterClient(appRouter, { context: ctx });
      await expect(invoke(client)).rejects.toSatisfy((error: ORPCError) => {
        expect(error).toBeInstanceOf(ORPCError);
        expect(error.code).toBe("FORBIDDEN");
        expect(error.message).toMatch(/Two-factor authentication setup is required/);
        // C45: the web app keys its enrollment redirect on this stable code.
        expect(error.data).toEqual({ code: TWO_FACTOR_REQUIRED_ERROR_CODE });
        return true;
      });
    },
  );

  it("still allows security enrollment reads on authenticatedProcedure", async () => {
    db.appSetting.findMany.mockResolvedValue([{ key: "force2faPublicUsers", value: "true" }]);
    invalidateForceTwoFactorSettingsCache();
    const ctx = buildContext({ twoFactorEnabled: false, createdAt: established });
    wireAuthoritativeUser(ctx.session!.user);
    const client = createRouterClient(appRouter, { context: ctx });
    await expect(client.settings.getAll()).resolves.toEqual(
      expect.objectContaining({ force2faPublicUsers: "true" }),
    );
    await expect(client.auth.verifyEmailTransport()).resolves.toEqual({ ok: true });
  });

  it("admits grace-period admins to protected procedures while internal force is on", async () => {
    db.appSetting.findMany.mockResolvedValue([{ key: "force2faInternalUsers", value: "true" }]);
    invalidateForceTwoFactorSettingsCache();
    const ctx = buildContext({
      role: "admin",
      twoFactorEnabled: false,
      createdAt: justSignedUp,
    });
    wireAuthoritativeUser(ctx.session!.user);
    const client = createRouterClient(appRouter, { context: ctx });
    await expect(client.sandboxes.list({ limit: 1 })).resolves.toEqual({
      items: [],
      nextCursor: null,
    });
  });

  it("allows sensitive calls when force-2FA is explicitly disabled for the role", async () => {
    db.appSetting.findMany.mockResolvedValue([{ key: "force2faPublicUsers", value: "false" }]);
    invalidateForceTwoFactorSettingsCache();
    const client = createRouterClient(appRouter, {
      context: buildContext({ twoFactorEnabled: false, createdAt: established }),
    });
    await expect(client.sandboxes.list({ limit: 1 })).resolves.toEqual({
      items: [],
      nextCursor: null,
    });
  });
});
