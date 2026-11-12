vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { createORPCClient } from "@orpc/client";
import { RPCLink } from "@orpc/client/fetch";
import { BatchLinkPlugin } from "@orpc/client/plugins";
import { ORPCError } from "@orpc/server";
import { RPCHandler } from "@orpc/server/fetch";
import { BatchHandlerPlugin } from "@orpc/server/plugins";
import type { Session } from "@wssp/auth";
import { ORPC_BATCH_MAX_SIZE } from "@wssp/config/orpc-batch";
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
  env: { BETTER_AUTH_SECRET: "batch-rpc-test-secret" },
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

function buildContext(): Context {
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

beforeEach(() => {
  vi.clearAllMocks();
  db.appSetting.findMany.mockResolvedValue([{ key: "force2faPublicUsers", value: "true" }]);
  db.sandbox.findMany.mockResolvedValue([]);
  db.user.findUnique.mockResolvedValue({
    twoFactorEnabled: false,
    role: "user",
    emailVerified: true,
    banned: false,
    banExpires: null,
    createdAt: established,
  });
  invalidateForceTwoFactorSettingsCache();
});

describe("mixed RPC batch transport", () => {
  it("returns independent outcomes in one batched HTTP request without forbidden sandbox IO", async () => {
    const rpcContext = buildContext();
    const handler = new RPCHandler(appRouter, {
      plugins: [new BatchHandlerPlugin({ maxSize: ORPC_BATCH_MAX_SIZE })],
    });

    let httpRequestCount = 0;
    let batchHeader: string | null = null;

    const link = new RPCLink({
      url: "http://batch-test.local/rpc",
      plugins: [
        new BatchLinkPlugin({
          groups: [{ condition: () => true, context: {} }],
          maxSize: ORPC_BATCH_MAX_SIZE,
        }),
      ],
      fetch: async (input, init) => {
        httpRequestCount += 1;
        const request = input instanceof Request ? input : new Request(input, init);
        batchHeader = request.headers.get("x-orpc-batch");
        const response = await handler.handle(request, {
          prefix: "/rpc",
          context: rpcContext,
        });
        if (!response.matched || !response.response) {
          throw new Error("RPC handler did not match batch request");
        }
        return response.response;
      },
    });

    const client = createORPCClient<typeof appRouter>(link);

    const [settingsResult, sandboxResult] = await Promise.all([
      client.settings.getAll(),
      client.sandboxes.list({ limit: 1 }).catch((error) => error),
    ]);

    expect(httpRequestCount).toBe(1);
    expect(batchHeader).toBeTruthy();
    expect(settingsResult).toEqual(expect.objectContaining({ force2faPublicUsers: "true" }));
    expect(sandboxResult).toSatisfy((error: ORPCError) => {
      expect(error).toBeInstanceOf(ORPCError);
      expect(error.code).toBe("FORBIDDEN");
      return true;
    });
    expect(db.sandbox.findMany).not.toHaveBeenCalled();
  });
});
