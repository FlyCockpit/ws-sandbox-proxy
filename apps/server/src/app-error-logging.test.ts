import { ORPCError } from "@orpc/server";
import { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ error: undefined as unknown }));

vi.mock("@wssp/env/server", () => ({
  env: {
    NODE_ENV: "test",
    RATE_LIMIT_AUTH_POINTS: 30,
    RATE_LIMIT_AUTH_WINDOW_SECONDS: 60,
    RATE_LIMIT_RPC_POINTS: 100,
    RATE_LIMIT_RPC_WINDOW_SECONDS: 60,
    RATE_LIMIT_EMAIL_POINTS: 3,
    RATE_LIMIT_EMAIL_WINDOW_SECONDS: 3600,
    TRUST_PROXY_HOPS: 0,
  },
  ADMIN_EMAILS: new Set(),
  resolveAppName: () => "WS Sandbox Proxy",
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/db", async () => ({ default: (await import("vitest-mock-extended")).mockDeep() }));
vi.mock("@wssp/auth", () => ({
  auth: { api: { getSession: vi.fn().mockResolvedValue(null) }, handler: vi.fn() },
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {}, QUEUE_NAMES: {} }));
vi.mock("@wssp/queue/consumer-health", () => ({ hasExternalConsumer: vi.fn() }));
vi.mock("./lifecycle.js", () => ({ withTimeout: (promise: Promise<unknown>) => promise }));
vi.mock("@hono/node-server/conninfo", () => ({
  getConnInfo: () => ({ remote: { address: "198.51.100.7" } }),
}));
vi.mock("rate-limiter-flexible", async (importOriginal) => {
  const original = await importOriginal<typeof import("rate-limiter-flexible")>();
  return { ...original, RateLimiterRedis: original.RateLimiterMemory };
});
vi.mock("@wssp/api/context", () => ({ createContext: vi.fn().mockResolvedValue({}) }));
vi.mock("@wssp/api/routers/index", async () => {
  const { os } = await import("@orpc/server");
  return {
    appRouter: {
      probe: os.handler(() => {
        throw state.error;
      }),
    },
  };
});
vi.mock("@wssp/api/lib/push-subscription", () => ({
  pushSubscriptionInputSchema: {},
  upsertPushSubscription: vi.fn(),
}));
vi.mock("@wssp/api/lib/sensitive-session-two-factor-gate", () => ({
  isSensitiveSessionTwoFactorPolicySatisfied: vi.fn(),
}));

// Unrelated API planes are excluded; requests still use the production app's
// oRPC handler and its actual error interceptor and values-free log boundary.
vi.mock("./sandbox-api/middleware.js", () => ({ createSandboxApi: () => new Hono() }));
vi.mock("./sandbox-api/hosts.js", () => ({ createHostControlApi: () => new Hono() }));
vi.mock("./sandbox-transfers/dashboard-routes.js", () => ({
  createDashboardTransferApi: () => new Hono(),
}));
vi.mock("./sandbox-image-relay/index.js", () => ({ imageRelaySpool: {} }));
vi.mock("./sandbox-image-relay/routes.js", () => ({
  IMAGE_RELAY_ROUTE: "/host/image-relay",
  createImageRelayApi: () => new Hono(),
}));
vi.mock("./sandbox-relay/websocket.js", () => ({
  createSandboxRelayWebsocketMiddleware: () => async (_c: unknown, next: () => Promise<void>) =>
    next(),
  sandboxRelayUpgradeHandler: () => async (_c: unknown, next: () => Promise<void>) => next(),
}));
vi.mock("./sandbox-relay/browser-terminal-upgrade.js", () => ({
  BROWSER_TERMINAL_ROUTE: "/api/dashboard/sandboxes/:id/terminal/ws",
  HOST_TERMINAL_ROUTE: "/api/dashboard/hosts/:id/terminal/ws",
  createBrowserTerminalUpgradeMiddleware: () => async (_c: unknown, next: () => Promise<void>) =>
    next(),
  browserTerminalUpgradeHandler: () => async (_c: unknown, next: () => Promise<void>) => next(),
}));

const { createApp } = await import("./app.js");

describe("oRPC error log levels", () => {
  let app: Awaited<ReturnType<typeof createApp>>;

  beforeEach(async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.spyOn(console, "error").mockImplementation(() => {});
    app = await createApp({ isShuttingDown: () => false, isWorkerReady: () => true });
    vi.clearAllMocks();
  });

  afterEach(() => vi.restoreAllMocks());

  it.each([500, 501, 502, 503, 504, 505])("logs HTTP %i at error", async (status) => {
    state.error = new ORPCError("TEST_FAILURE", { status });
    expect(
      (await app.request("/rpc/probe", { method: "POST", headers: { "x-csrf-token": "orpc" } }))
        .status,
    ).toBe(status);
    expect(console.error).toHaveBeenCalledWith("[orpc] Request failed", expect.anything());
    expect(console.warn).not.toHaveBeenCalled();
  });

  it.each([400, 401, 404, 429])("logs HTTP %i at warn", async (status) => {
    state.error = new ORPCError("TEST_FAILURE", { status });
    expect(
      (await app.request("/rpc/probe", { method: "POST", headers: { "x-csrf-token": "orpc" } }))
        .status,
    ).toBe(status);
    expect(console.warn).toHaveBeenCalledWith("[orpc] Request failed", expect.anything());
    expect(console.error).not.toHaveBeenCalled();
  });

  it("logs an unexpected exception at error", async () => {
    state.error = new Error("Unexpected failure");
    expect(
      (await app.request("/rpc/probe", { method: "POST", headers: { "x-csrf-token": "orpc" } }))
        .status,
    ).toBe(500);
    expect(console.error).toHaveBeenCalledWith("[orpc] Request failed", expect.anything());
    expect(console.warn).not.toHaveBeenCalled();
  });
});
