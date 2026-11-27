vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { RPCHandler } from "@orpc/server/fetch";
import { beforeEach, expect, it, vi } from "vitest";
import { deviceRow, deviceStore, gate } from "../lib/device-code-test-harness";

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
vi.mock("../lib/procedure-budget", () => ({
  createProcedureBudget: () => vi.fn().mockResolvedValue(undefined),
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
const { transitionDeviceCode } = await import("../lib/device-code-transitions");
const handler = new RPCHandler(appRouter);
let store: ReturnType<typeof deviceStore>;
beforeEach(() => {
  store = deviceStore();
  Object.assign(prisma, store.db);
  store.state.deviceCode.set("code-1", deviceRow({ status: "pending", userId: null }));
  store.state.session.set("approver-session", {
    id: "approver-session",
    userId: "user-1",
    expiresAt: new Date("2099-01-01"),
    impersonatedBy: null,
  });
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
async function poll() {
  const response = await handler.handle(
    new Request("https://api.example.test/rpc/hostCredentials/exchangeDeviceCode", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ json: { deviceCode: "secret-code-1", hostSlug: "desk-01" } }),
    }),
    { prefix: "/rpc", context: { session: null } },
  );
  if (!response.matched) throw new Error("Production nested device router did not match");
  return { status: response.response.status, body: await response.response.json() };
}
it.each(["claim", "approve", "poll"])(
  "%s-during-poll stays retryable on the real nested RPC wire",
  async (action) => {
    if (action === "approve")
      store.state.deviceCode.set("code-1", deviceRow({ status: "pending" }));
    const reached = gate(),
      release = gate();
    let first = true;
    store.hooks.beforeLock = async () => {
      if (first) {
        first = false;
        reached.open();
        await release.promise;
      }
    };
    const delayed = poll();
    await reached.promise;
    if (action === "poll") await poll();
    else
      await transitionDeviceCode({
        userCode: "ABCDEFGH",
        userId: "user-1",
        sessionId: "approver-session",
        action,
        intent: { kind: "create" },
      });
    release.open();
    expect(await delayed).toMatchObject({
      status: 400,
      body: {
        json: {
          code: "BAD_REQUEST",
          data: {
            deviceFlowError: action === "poll" ? "slow_down" : "authorization_pending",
          },
        },
      },
    });
    expect(store.state.deviceCode.size).toBe(1);
    if (action === "approve") {
      expect(store.state.deviceCode.get("code-1")?.lastPolledAt).toBeNull();
      expect(await poll()).toMatchObject({
        status: 200,
        body: { json: { userId: "user-1", secret: expect.stringMatching(/^wssp_device_/) } },
      });
      expect(store.state.hostDeviceCredential.size).toBe(1);
    }
  },
);
it.each([
  { code: "P2034" },
  { code: "40P01" },
  { code: "40001" },
  { code: "P2010", meta: { code: "40P01" } },
  { meta: { driverAdapterError: { cause: { originalCode: "40001" } } } },
])("transaction conflict %j is a typed retryable wire outcome", async (error) => {
  store.db.$transaction.mockRejectedValueOnce(error);
  expect(await poll()).toMatchObject({
    status: 503,
    body: {
      json: { code: "SERVICE_UNAVAILABLE", data: { deviceFlowError: "authorization_pending" } },
    },
  });
  expect(store.state.deviceCode.size).toBe(1);
});
