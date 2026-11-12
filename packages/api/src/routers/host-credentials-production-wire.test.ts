vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { ORPCError } from "@orpc/server";
import { RPCHandler } from "@orpc/server/fetch";
import { BatchHandlerPlugin, SimpleCsrfProtectionHandlerPlugin } from "@orpc/server/plugins";
import { ORPC_BATCH_MAX_SIZE } from "@wssp/config/orpc-batch";
import { beforeEach, expect, it, vi } from "vitest";
import { deviceRow, deviceStore } from "../lib/device-code-test-harness";

vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_SECRET: "test-better-auth-secret" },
  ADMIN_EMAILS: new Set(),
  SIGNUP_ENABLED: true,
}));
vi.mock("@wssp/db", async () => ({
  default: await (await import("../test/mock-prisma")).createMockPrisma(),
}));
vi.mock("@wssp/queue", () => ({}));
vi.mock("@wssp/mailer", () => ({ isEmailConfigured: () => false }));
const budget = vi.hoisted(() => vi.fn().mockResolvedValue(undefined));
vi.mock("../lib/procedure-budget", () => ({
  createProcedureBudget: () => budget,
}));
vi.mock("./auth", () => ({ authRouter: {} }));
vi.mock("./push", () => ({ pushRouter: {} }));
vi.mock("./queue", () => ({ queueRouter: {} }));
vi.mock("./sandbox-hosts", () => ({ sandboxHostsRouter: {} }));
vi.mock("./sandbox-templates", () => ({ sandboxTemplatesRouter: {} }));
vi.mock("./sandboxes", () => ({ sandboxesRouter: {} }));
vi.mock("./sdk-keys", () => ({ sdkKeysRouter: {} }));
vi.mock("./settings", () => ({ settingsRouter: {} }));
vi.mock("./users", () => ({ usersRouter: {} }));

const { default: prisma } = await import("@wssp/db");
const { appRouter } = await import("./index");

/** Mirrors `apps/server/src/app.ts` rpcHandler when `CORS_ORIGIN` is set. */
const productionRpcHandler = new RPCHandler(appRouter, {
  plugins: [
    new BatchHandlerPlugin({ maxSize: ORPC_BATCH_MAX_SIZE }),
    new SimpleCsrfProtectionHandlerPlugin(),
  ],
});

let store: ReturnType<typeof deviceStore>;
beforeEach(() => {
  store = deviceStore();
  Object.assign(prisma, store.db);
  budget.mockResolvedValue(undefined);
  store.state.deviceCode.set("code-1", deviceRow({ status: "pending", userId: null }));
  store.state.user.set("user-1", {
    id: "user-1",
    emailVerified: true,
    twoFactorEnabled: true,
    role: "admin",
    banned: false,
    banExpires: null,
    createdAt: new Date("2020-01-01"),
  });
});

async function exchange(headers: Record<string, string> = { "x-csrf-token": "orpc" }) {
  const response = await productionRpcHandler.handle(
    new Request("https://api.example.test/rpc/hostCredentials/exchangeDeviceCode", {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body: JSON.stringify({ json: { deviceCode: "secret-code-1", hostSlug: "desk-01" } }),
    }),
    { prefix: "/rpc", context: { session: null, clientIp: "203.0.113.1" } },
  );
  if (!response.matched) throw new Error("RPC did not match");
  return { status: response.response.status, body: await response.response.json() };
}

it("rejects split-origin exchange without CSRF header", async () => {
  const result = await exchange({});
  expect(result.status).toBe(403);
  expect(result.body).toMatchObject({ json: { code: "CSRF_TOKEN_MISMATCH" } });
});

it("documents every C20 deviceFlowError and terminal status on the production handler", async () => {
  expect(await exchange()).toMatchObject({
    status: 400,
    body: { json: { code: "BAD_REQUEST", data: { deviceFlowError: "authorization_pending" } } },
  });

  store.state.deviceCode.set(
    "code-1",
    deviceRow({ status: "pending", userId: null, lastPolledAt: store.now }),
  );
  expect(await exchange()).toMatchObject({
    status: 400,
    body: { json: { code: "BAD_REQUEST", data: { deviceFlowError: "slow_down" } } },
  });

  store.state.deviceCode.set("code-1", deviceRow({ status: "denied" }));
  expect(await exchange()).toMatchObject({
    status: 403,
    body: { json: { code: "FORBIDDEN", data: { deviceFlowError: "access_denied" } } },
  });

  store.state.deviceCode.set(
    "code-1",
    deviceRow({ status: "pending", userId: null, expiresAt: new Date("2026-06-01") }),
  );
  expect(await exchange()).toMatchObject({
    status: 400,
    body: { json: { code: "BAD_REQUEST", data: { deviceFlowError: "expired_token" } } },
  });

  store.state.deviceCode.clear();
  expect(await exchange()).toMatchObject({ status: 404, body: { json: { code: "NOT_FOUND" } } });

  store.state.deviceCode.set("code-1", deviceRow({ status: "approved" }));
  store.state.sandboxHost.set("host-existing", {
    id: "host-existing",
    userId: "user-1",
    slug: "desk-01",
    label: "desk-01",
  });
  store.hooks.beforeCredential = async () => {
    throw { code: "P2002", meta: { target: ["sandbox_host_userId_slug_key"] } };
  };
  expect(await exchange()).toMatchObject({ status: 409, body: { json: { code: "CONFLICT" } } });

  budget.mockRejectedValueOnce(
    new ORPCError("TOO_MANY_REQUESTS", {
      message: "Too many device exchanges. Retry in 30 seconds.",
      data: { retryAfterSeconds: 30 },
    }),
  );
  expect(await exchange()).toMatchObject({
    status: 429,
    body: { json: { code: "TOO_MANY_REQUESTS", data: { retryAfterSeconds: 30 } } },
  });

  budget.mockRejectedValueOnce(
    new ORPCError("SERVICE_UNAVAILABLE", {
      message: "Device exchange is temporarily unavailable.",
    }),
  );
  expect(await exchange()).toMatchObject({
    status: 503,
    body: {
      json: {
        code: "SERVICE_UNAVAILABLE",
        data: { deviceFlowError: "authorization_pending" },
      },
    },
  });

  store.db.$transaction.mockRejectedValueOnce({ code: "P2034" });
  expect(await exchange()).toMatchObject({
    status: 503,
    body: {
      json: { code: "SERVICE_UNAVAILABLE", data: { deviceFlowError: "authorization_pending" } },
    },
  });

  store.hooks.beforeCredential = undefined;
  store.state.sandboxHost.clear();
  store.state.hostDeviceCredential.clear();
  store.state.deviceCode.set("code-1", deviceRow());
  expect(await exchange()).toMatchObject({
    status: 200,
    body: { json: { secret: expect.stringMatching(/^wssp_device_/) } },
  });
  store.state.deviceCode.clear();
  expect(await exchange()).toMatchObject({ status: 404, body: { json: { code: "NOT_FOUND" } } });
});
