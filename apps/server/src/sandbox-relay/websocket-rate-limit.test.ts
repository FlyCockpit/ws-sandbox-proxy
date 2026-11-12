import { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SANDBOX_RELAY_SUBPROTOCOL } from "./protocol.js";

const state = vi.hoisted(() => ({
  peer: "198.51.100.7",
  authenticate: vi.fn(),
  options: [] as { keyPrefix?: string; insuranceLimiter?: unknown }[],
}));

vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/env/server", () => ({
  env: {
    RATE_LIMIT_AUTH_POINTS: 30,
    RATE_LIMIT_AUTH_WINDOW_SECONDS: 60,
    RATE_LIMIT_RPC_POINTS: 100,
    RATE_LIMIT_RPC_WINDOW_SECONDS: 60,
    RATE_LIMIT_EMAIL_POINTS: 3,
    RATE_LIMIT_EMAIL_WINDOW_SECONDS: 3600,
    TRUST_PROXY_HOPS: 0,
  },
}));
vi.mock("@hono/node-server/conninfo", () => ({
  getConnInfo: () => ({ remote: { address: state.peer } }),
}));
vi.mock("./auth.js", () => ({ authenticateSandboxHostWebsocket: state.authenticate }));
vi.mock("./session-manager.js", () => ({ sandboxRelaySessionManager: {} }));

// Replace only Redis IO; the production limiters and middleware count requests
// using the library's real in-memory implementation, as in rate-limit.test.ts.
vi.mock("rate-limiter-flexible", async (importOriginal) => {
  const original = await importOriginal<typeof import("rate-limiter-flexible")>();
  return {
    ...original,
    RateLimiterRedis: class extends original.RateLimiterMemory {
      constructor(options: ConstructorParameters<typeof original.RateLimiterMemory>[0]) {
        super(options);
        state.options.push(options);
      }
    },
  };
});

const { authLimiter, createRateLimiterMiddleware, hostRelayLimiter } = await import(
  "../rate-limit.js"
);
const { createSandboxRelayWebsocketMiddleware } = await import("./websocket.js");

function app() {
  const hono = new Hono<{ Variables: { session: { user: { id: string } } } }>();
  // Even an unrelated browser session must not change the host's per-IP key.
  hono.use("/ws/sandbox-host", async (c, next) => {
    c.set("session", { user: { id: c.req.header("x-test-browser-user") ?? "browser-user" } });
    await next();
  });
  hono.use("/ws/sandbox-host", createSandboxRelayWebsocketMiddleware());
  hono.get("/ws/sandbox-host", (c) => c.text("upgraded"));
  hono.use("/api/auth/*", createRateLimiterMiddleware(authLimiter, { failClosed: true }));
  hono.get("/api/auth/probe", (c) => c.text("browser auth"));
  return hono;
}

function upgrade(hono: ReturnType<typeof app>, user = "browser-user") {
  return hono.request("/ws/sandbox-host", {
    headers: {
      Upgrade: "websocket",
      "Sec-WebSocket-Protocol": SANDBOX_RELAY_SUBPROTOCOL,
      Authorization: "Bearer synthetic-host-credential",
      "x-test-browser-user": user,
    },
  });
}

describe("host relay upgrade rate limiting", () => {
  beforeEach(async () => {
    state.peer = "198.51.100.7";
    await hostRelayLimiter.delete(state.peer);
    await authLimiter.delete(state.peer);
    state.authenticate.mockReset();
    state.authenticate.mockResolvedValue({ identity: { hostId: "host-1", userId: "owner-1" } });
  });

  afterEach(() => vi.restoreAllMocks());

  it("has a dedicated fixed budget and no insurance fallback", () => {
    expect(hostRelayLimiter.keyPrefix).toBe("rl:host-relay");
    expect(hostRelayLimiter.points).toBe(1200);
    expect(hostRelayLimiter.duration).toBe(60);
    expect(
      state.options.find((options) => options.keyPrefix === "rl:host-relay"),
    ).not.toHaveProperty("insuranceLimiter");
  });

  it("admits the budget, then returns 429 with Retry-After before authentication", async () => {
    const hono = app();
    for (let i = 0; i < hostRelayLimiter.points; i++) {
      expect((await upgrade(hono, `browser-${i}`)).status).toBe(200);
    }
    expect(state.authenticate).toHaveBeenCalledTimes(hostRelayLimiter.points);

    const rejected = await upgrade(hono, "another-browser");
    expect(rejected.status).toBe(429);
    expect(rejected.headers.get("X-RateLimit-Limit")).toBe(String(hostRelayLimiter.points));
    expect(rejected.headers.get("X-RateLimit-Remaining")).toBe("0");
    expect(rejected.headers.get("Retry-After")).toMatch(/^[1-9]\d*$/);
    expect(Number(rejected.headers.get("Retry-After"))).toBeLessThanOrEqual(60);
    expect(state.authenticate).toHaveBeenCalledTimes(hostRelayLimiter.points);

    state.peer = "198.51.100.8";
    await hostRelayLimiter.delete(state.peer);
    expect((await upgrade(hono)).status).toBe(200);
  });

  it("counts rejected host credentials without spending browser auth points", async () => {
    const hono = app();
    state.authenticate.mockResolvedValue(null);
    for (let i = 0; i < hostRelayLimiter.points; i++) {
      expect((await upgrade(hono)).status).toBe(401);
    }
    expect((await upgrade(hono)).status).toBe(429);
    expect(await authLimiter.get(state.peer)).toBeNull();

    for (let i = 0; i < authLimiter.points; i++) {
      expect((await hono.request("/api/auth/probe")).status).toBe(200);
    }
    expect((await hono.request("/api/auth/probe")).status).toBe(429);
  });

  it("fails closed with 503 and Retry-After when the limiter backend fails", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(hostRelayLimiter, "consume").mockRejectedValue(new Error("Redis unavailable"));
    const response = await upgrade(app());
    expect(response.status).toBe(503);
    expect(response.headers.get("Retry-After")).toBe("5");
    expect(state.authenticate).not.toHaveBeenCalled();
    expect(log).toHaveBeenCalledOnce();
  });
});
