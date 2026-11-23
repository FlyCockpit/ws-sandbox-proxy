vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { IncomingMessage, ServerResponse } from "node:http";
import { Socket } from "node:net";
import { inspect } from "node:util";
import { getRequestListener } from "@hono/node-server";
import { ORPCError } from "@orpc/server";
import {
  digestSdkKeySecret,
  generateSdkKeySecret,
  serviceProcedure,
} from "@wssp/api/lib/sdk-key-access";
import { invalidateForceTwoFactorSettingsCache } from "@wssp/api/lib/two-factor-policy";
import { withAuthorityChange } from "@wssp/db/authority";
import {
  credentialLookupPrefix,
  generateProductCredentialSecret,
} from "@wssp/db/credential-security";
import { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createApp } from "./app.js";
import type { SandboxApiEnv } from "./sandbox-api/auth.js";
import { SDK_JSON_MAX_BYTES } from "./sandbox-api/middleware.js";

const state = vi.hoisted(() => ({
  globalBody: vi.fn(),
  transferStatus: vi.fn(),
  transferWrite: vi.fn(),
  getSession: vi.fn(),
  render: vi.fn(),
  effect: vi.fn(),
  failure: undefined as unknown,
  afterRead: undefined as (() => Promise<unknown>) | undefined,
  budgetFailure: undefined as unknown,
  charges: [] as { prefix: string; key: string }[],
  budgets: [] as { keyPrefix: string; points: number; duration: number; storeClient: unknown }[],
  peer: "198.51.100.7",
  env: {
    NODE_ENV: "production",
    WORKER_MODE: "embedded",
    CORS_ORIGIN: "https://browser.example" as string | undefined,
    BETTER_AUTH_URL: "https://api.example",
    BETTER_AUTH_SECRET: "c22-test-only-secret",
    RATE_LIMIT_AUTH_POINTS: 30,
    RATE_LIMIT_AUTH_WINDOW_SECONDS: 60,
    RATE_LIMIT_RPC_POINTS: 100,
    RATE_LIMIT_RPC_WINDOW_SECONDS: 60,
    RATE_LIMIT_SDK_IP_POINTS: 300,
    RATE_LIMIT_SDK_KEY_POINTS: 100,
    RATE_LIMIT_SDK_OWNER_POINTS: 300,
    RATE_LIMIT_EMAIL_POINTS: 3,
    RATE_LIMIT_EMAIL_WINDOW_SECONDS: 3600,
    TRUST_PROXY_HOPS: undefined as number | undefined,
  },
}));
vi.mock("./sandbox-transfers/runtime.js", () => ({
  transferStore: () => ({ status: state.transferStatus, write: state.transferWrite }),
}));
vi.mock("hono/body-limit", async (original) => {
  const actual = await original<typeof import("hono/body-limit")>();
  return {
    ...actual,
    bodyLimit: (...args: Parameters<typeof actual.bodyLimit>) => {
      const middleware = actual.bodyLimit(...args);
      return (...input: Parameters<typeof middleware>) => {
        state.globalBody();
        return middleware(...input);
      };
    },
  };
});
vi.mock("@wssp/env/server", () => ({
  env: state.env,
  ADMIN_EMAILS: new Set(),
  SIGNUP_ENABLED: true,
  resolveAppName: () => "WS Sandbox Proxy",
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/auth", () => ({
  auth: { api: { getSession: state.getSession }, handler: vi.fn() },
}));
vi.mock("@wssp/queue", () => ({
  redisConnection: { ping: vi.fn() },
  QUEUE_NAMES: {
    reapExpiredAuthTokens: "reap",
    checkBackupFreshness: "check",
    webhookDelivery: "webhook-delivery",
    reapWebhookLog: "reap-webhook-log",
  },
  reapExpiredAuthTokensQueue: {},
  imageStoreMaintenanceQueue: {
    add: vi.fn(),
    upsertJobScheduler: vi.fn(),
    removeJobScheduler: vi.fn(),
  },
  checkBackupFreshnessQueue: {},
  webhookDeliveryQueue: {},
  reapWebhookLogQueue: {},
  notifyDataDeletionsQueue: {},
}));
vi.mock("@wssp/queue/consumer-health", () => ({ hasExternalConsumer: vi.fn() }));
vi.mock("@wssp/mailer", () => ({ isEmailConfigured: () => false }));
vi.mock("./lifecycle.js", () => ({ withTimeout: (promise: Promise<unknown>) => promise }));
vi.mock("./ssr-handler.js", () => ({ loadSsrHandler: async () => ({ fetch: state.render }) }));
vi.mock("@hono/node-server/conninfo", () => ({
  getConnInfo: () => ({ remote: { address: state.peer } }),
}));
vi.mock("rate-limiter-flexible", async (original) => {
  const actual = await original<typeof import("rate-limiter-flexible")>();
  // Only Redis IO is replaced; the real library accounts points/windows.
  return {
    ...actual,
    RateLimiterRedis: class extends actual.RateLimiterMemory {
      constructor(options: {
        keyPrefix: string;
        points: number;
        duration: number;
        storeClient: unknown;
      }) {
        super(options);
        state.budgets.push(options);
      }
      override consume(key: string, points?: number) {
        state.charges.push({ prefix: this.keyPrefix, key });
        if (state.budgetFailure) return Promise.reject(state.budgetFailure);
        return super.consume(key, points);
      }
    },
  };
});
vi.mock("./sandbox-api/routes.js", () => ({
  // C22 has no public DTO endpoints. Synthetic routes exercise the actual C21
  // service chokepoint, inside the REAL production application's middleware.
  createSandboxApiRoutes: () => {
    const routes = new Hono<SandboxApiEnv>();
    const read = serviceProcedure({ action: "hosts.list" }, async (principal) => {
      state.effect(principal.ownerId);
      await state.afterRead?.();
      if (state.failure) throw state.failure;
      return { ownerId: principal.ownerId };
    });
    routes.get("/probe", async (c) => c.json(await read(c.var.principal, undefined)));
    routes.post("/probe", async (c) => {
      await read(c.var.principal, undefined);
      return c.json({ body: await c.req.json().catch(() => null) });
    });
    return routes;
  },
}));
const { default: prisma } = await import("@wssp/db");
const db = prisma as import("@wssp/api/test/mock-prisma").MockPrisma;
const { RateLimiterRes } = await import("rate-limiter-flexible");
const credential = generateSdkKeySecret();
const bearer = { authorization: `Bearer ${credential.raw}` };
const cookie = "better-auth.session_token=cookie-fixture";
const session = {
  user: { id: "browser-owner", role: "user", emailVerified: true, twoFactorEnabled: true },
  session: { id: "session-1" },
};
function keyRow() {
  return {
    id: "key-a",
    kind: "API" as const,
    ownSandboxesOnly: false,
    userId: "owner-a",
    resourceMode: "ALL_OWNED" as const,
    scopes: ["hosts:read"],
    lookupPrefix: credentialLookupPrefix(credential),
    secretDigest: digestSdkKeySecret(credential.raw),
    revokedAt: null as Date | null,
    expiresAt: null as Date | null,
    HostAllowlist: [],
    RevisionAllowlist: [],
    User: {
      banned: false,
      banExpires: null,
      deletionRequestedAt: null as Date | null,
      twoFactorEnabled: true,
      createdAt: new Date("2020-01-01"),
      role: "user",
    },
  };
}
let row = keyRow();
db.sdkKey.findUnique.mockResolvedValue(row as never);
let app: Awaited<ReturnType<typeof createApp>>;
async function build() {
  return createApp({ isShuttingDown: () => false, isWorkerReady: () => true });
}
async function errorCode(response: Response, status: number, code: string) {
  expect(response.status).toBe(status);
  expect(response.headers.get("content-type")).toContain("application/json");
  expect(response.headers.get("cache-control")).toBe("no-store");
  const id = response.headers.get("x-request-id");
  expect(id).toMatch(/^[\da-f]{8}-[\da-f]{4}-4[\da-f]{3}-[89ab][\da-f]{3}-[\da-f]{12}$/);
  expect(await response.json()).toMatchObject({ error: { code, requestId: id } });
}
beforeEach(async () => {
  vi.clearAllMocks();
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
  state.failure = undefined;
  state.afterRead = undefined;
  state.budgetFailure = undefined;
  state.charges = [];
  state.budgets = [];
  state.peer = "198.51.100.7";
  state.env.TRUST_PROXY_HOPS = undefined;
  row = keyRow();
  db.sdkKey.findUnique.mockResolvedValue(row as never);
  db.sdkKey.findUnique.mockResolvedValue(row as never);
  db.sdkKey.update.mockResolvedValue({ id: row.id } as never);
  db.sandboxHost.findMany.mockResolvedValue([]);
  invalidateForceTwoFactorSettingsCache();
  state.render.mockImplementation(async () => new Response("SSR fixture"));
  state.getSession.mockImplementation(async ({ headers }: { headers: Headers }) =>
    headers.has("authorization") || headers.get("cookie") === cookie ? session : null,
  );
  app = await build();
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("production bearer application", () => {
  it("serves only the public SDK spec anonymously, before any browser middleware", async () => {
    const response = await app.request("/v1/openapi.json", {
      headers: { origin: "https://evil.example", cookie },
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
    expect(response.headers.get("cache-control")).toBe("no-store");
    const doc = (await response.json()) as {
      paths: Record<string, unknown>;
      components: { schemas: Record<string, unknown> };
    };
    expect(Object.keys(doc.paths).every((path) => path.startsWith("/v1/"))).toBe(true);
    expect(JSON.stringify(doc)).not.toMatch(/\/rpc|api-reference|\/admin/);
    expect(Object.keys(doc.components.schemas)).not.toContain("Admin");
    expect(state.charges.map((charge) => charge.prefix)).toEqual(["sdk-http:ip"]);
    expect(state.getSession).not.toHaveBeenCalled();
    expect(db.sdkKey.findUnique).not.toHaveBeenCalled();
    expect(state.render).not.toHaveBeenCalled();
  });
  it("isolates root and all v1 paths from browser session CORS RPC OpenAPI and SSR", async () => {
    for (const path of [
      "/v1",
      "/v1/",
      "/v1/no-such-route",
      "/v1/rpc/sandboxHosts/listHosts",
      "/v1/api-reference/openapi.json",
      "/v1/assets/test.js",
      "/v1/en-US",
      "/v1//probe",
    ]) {
      await errorCode(
        await app.request(path, { headers: { ...bearer, origin: state.env.CORS_ORIGIN, cookie } }),
        404,
        "NOT_FOUND",
      );
    }
    expect(state.getSession).not.toHaveBeenCalled();
    expect(state.render).not.toHaveBeenCalled();
    const page = await app.request("/en-US");
    expect(await page.text()).toBe("SSR fixture");
    expect(state.render).toHaveBeenCalledOnce();
    const health = await app.request("/health", { headers: { origin: state.env.CORS_ORIGIN } });
    expect(health.status).toBe(200);
    expect(health.headers.get("access-control-allow-origin")).toBe(state.env.CORS_ORIGIN);
  });
  it("serves the CLI installer before SSR, with the security headers and no session", async () => {
    const response = await app.request("/install.sh", {
      headers: { cookie, host: "evil.example" },
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("text/x-shellscript; charset=utf-8");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("content-security-policy")).toBeTruthy();
    const text = await response.text();
    expect(text).toMatch(/^#!\/bin\/sh\n/);
    expect(text).toContain("WSSP_ORIGIN='https://api.example'");
    expect(text).not.toContain("evil.example");
    const ps1 = await app.request("/install.ps1");
    expect(ps1.status).toBe(200);
    expect(await ps1.text()).toContain("Linux only");
    expect(state.render).not.toHaveBeenCalled();
    expect(state.getSession).not.toHaveBeenCalled();
  });
  it("resolves no browser session for asset and page requests", async () => {
    for (const path of ["/assets/test.js", "/en-US", "/en-US/sandboxes", "/rpcx", "/favicon.ico"])
      await app.request(path, { headers: { cookie } });
    expect(state.getSession).not.toHaveBeenCalled();
  });
  it("authenticates SDK keys only and ignores cookies without consulting sessions", async () => {
    const invalid = [
      undefined,
      "Basic abc",
      "Bearer",
      "Bearer invalid",
      `Bearer ${generateProductCredentialSecret("hostToken").raw}`,
      `Bearer ${generateProductCredentialSecret("deviceCredential").raw}`,
      `Bearer ${generateSdkKeySecret().raw}`,
      `Bearer  ${credential.raw}`,
      `Bearer\t${credential.raw}`,
      `Bearer ${credential.raw}, Bearer ${credential.raw}`,
      `Bearer ${credential.raw} extra`,
    ];
    for (const authorization of invalid) {
      await errorCode(
        await app.request("/v1/probe", {
          headers: { cookie, ...(authorization ? { authorization } : {}) },
        }),
        401,
        "UNAUTHORIZED",
      );
    }
    for (const headers of [
      bearer,
      { ...bearer, cookie },
      { authorization: `bEaReR ${credential.raw}`, cookie: "invalid-cookie" },
    ]) {
      const response = await app.request("/v1/probe", { headers });
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ ownerId: "owner-a" });
    }
    expect(state.getSession).not.toHaveBeenCalled();
  });
  it("rejects duplicate Authorization through the installed Node HTTP adapter", async () => {
    const incoming = new IncomingMessage(new Socket());
    incoming.url = "/v1/probe";
    incoming.method = "GET";
    incoming.headers = { host: "localhost" };
    incoming.httpVersionMajor = 1;
    incoming.httpVersion = "1.1";
    incoming.rawHeaders = [
      "Host",
      "localhost",
      "Authorization",
      bearer.authorization,
      "authorization",
      bearer.authorization,
    ];
    const response = new ServerResponse(incoming);
    const chunks: string[] = [];
    vi.spyOn(response, "write").mockImplementation((chunk) => {
      chunks.push(String(chunk));
      return true;
    });
    vi.spyOn(response, "end").mockImplementation((chunk) => {
      if (chunk) chunks.push(String(chunk));
      return response;
    });
    incoming.push(null);
    await getRequestListener(app.fetch)(incoming, response);
    expect(response.statusCode, JSON.stringify(vi.mocked(console.error).mock.calls)).toBe(401);
    expect(chunks.join("")).toContain('"code":"UNAUTHORIZED"');
    expect(db.sdkKey.findUnique).not.toHaveBeenCalled();
    incoming.destroy();
  });
  it("rejects query credentials including encoded aliases even with a valid bearer", async () => {
    for (const name of [
      "token",
      "key",
      "api_key",
      "access_token",
      "Authorization",
      "api-key",
      "%61pi%5fkey",
      "sdkKey",
      "secret",
      "client_secret",
      "refresh_token",
      "password",
    ]) {
      for (const headers of [{}, bearer]) {
        await errorCode(
          await app.request(`/v1/probe?${name}=${credential.raw}`, { headers }),
          400,
          "BAD_REQUEST",
        );
      }
    }
    await errorCode(
      await app.request(`/v1/probe?unrecognized=${credential.raw}`, { headers: bearer }),
      400,
      "BAD_REQUEST",
    );
    expect(db.sdkKey.findUnique).not.toHaveBeenCalled();
    expect((await app.request("/v1/probe?cursor=normal-value", { headers: bearer })).status).toBe(
      200,
    );
  });
  it("does not grant CORS or preflight for any Origin or credential combination", async () => {
    for (const origin of [undefined, state.env.CORS_ORIGIN, "https://evil.example", "null"]) {
      for (const authorized of [false, true]) {
        for (const method of ["GET", "OPTIONS"]) {
          const response = await app.request("/v1/probe", {
            method,
            headers: {
              ...(authorized ? bearer : { cookie }),
              ...(origin ? { origin } : {}),
              "access-control-request-method": "POST",
              "access-control-request-headers": "authorization",
            },
          });
          expect(response.status).toBe(authorized ? (method === "OPTIONS" ? 405 : 200) : 401);
          expect(
            [...response.headers.keys()].filter((h) => h.startsWith("access-control-")),
          ).toEqual([]);
          expect(response.headers.get("cache-control")).toBe("no-store");
        }
      }
    }
  });
  it("rejects SDK and cookie credentials on the real host relay route", async () => {
    for (const headers of [bearer, { cookie }]) {
      const response = await app.request("/ws/sandbox-host", {
        headers: {
          ...headers,
          upgrade: "websocket",
          "sec-websocket-protocol": "ws-sandbox-proxy.relay.v1",
        },
      });
      expect(response.status).toBe(401);
      expect(state.getSession).not.toHaveBeenCalled();
    }
  });
  it("cannot use SDK bearer authority on the real RPC router while cookie auth remains usable", async () => {
    const send = (headers: Record<string, string>) =>
      app.request("/rpc/sandboxHosts/listHosts", {
        method: "POST",
        headers: { ...headers, "content-type": "application/json", "x-csrf-token": "orpc" },
        body: JSON.stringify({ json: {} }),
      });
    const unauthorized = await send(bearer);
    expect(unauthorized.status).toBe(401);
    expect(await unauthorized.json()).toMatchObject({ json: { code: "UNAUTHORIZED" } });
    for (const headers of [{ cookie }, { ...bearer, cookie }])
      expect((await send(headers)).status).toBe(200);
    for (const [input] of state.getSession.mock.calls)
      expect(input.headers.has("authorization")).toBe(false);
  });
  it("enforces service scopes and denies revoked expired banned deleting and unenrolled owners on the next request", async () => {
    expect((await app.request("/v1/probe", { headers: bearer })).status).toBe(200);
    row.scopes = ["sandboxes:read"];
    await errorCode(await app.request("/v1/probe", { headers: bearer }), 403, "FORBIDDEN");
    for (const change of [
      () => {
        row.revokedAt = new Date();
      },
      () => {
        row.expiresAt = new Date(0);
      },
      () => {
        row.User.banned = true;
      },
      () => {
        row.User.deletionRequestedAt = new Date();
      },
      () => {
        row.User.twoFactorEnabled = false;
        row.User.role = "admin";
      },
    ]) {
      row = keyRow();
      db.sdkKey.findUnique.mockResolvedValue(row as never);
      change();
      await errorCode(await app.request("/v1/probe", { headers: bearer }), 401, "UNAUTHORIZED");
    }
    expect(state.effect).toHaveBeenCalledTimes(1);
  });
  it("checks owner scoped tickets on service return and failure without fencing unrelated owners", async () => {
    state.afterRead = () => withAuthorityChange({ ownerId: "other-owner" }, async () => {});
    expect((await app.request("/v1/probe", { headers: bearer })).status).toBe(200);
    state.afterRead = () =>
      withAuthorityChange({ ownerId: row.userId, credentialId: row.id }, async () => {});
    await errorCode(await app.request("/v1/probe", { headers: bearer }), 403, "FORBIDDEN");
    state.failure = new ORPCError("NOT_FOUND", { message: credential.raw });
    await errorCode(await app.request("/v1/probe", { headers: bearer }), 403, "FORBIDDEN");
  });
  it("charges IP before lookup and key and owner once per authenticated request", async () => {
    await app.request("/v1/probe", { headers: bearer });
    expect(state.charges).toEqual([
      { prefix: "sdk-http:ip", key: state.peer },
      { prefix: "sdk-http:key", key: "key-a" },
      { prefix: "sdk-http:owner", key: "owner-a" },
    ]);
    expect(state.budgets.filter((b) => b.keyPrefix.startsWith("sdk-http:"))).toMatchObject([
      { keyPrefix: "sdk-http:ip", points: 300, duration: 60, storeClient: {} },
      { keyPrefix: "sdk-http:key", points: 100, duration: 60, storeClient: {} },
      { keyPrefix: "sdk-http:owner", points: 300, duration: 60, storeClient: {} },
    ]);
  });
  it("enforces exact per-key per-owner and per-IP budgets and releases windows", async () => {
    for (const dimension of ["key", "owner", "ip"]) {
      app = await build();
      const count = dimension === "key" ? 100 : 300;
      for (let i = 0; i < count; i++) {
        if (dimension !== "ip") state.peer = `198.51.${Math.floor(i / 250)}.${i % 250}`;
        if (dimension !== "key") row.id = `key-${i}`;
        if (dimension === "ip") row.userId = `owner-${i}`;
        expect((await app.request("/v1/probe", { headers: bearer })).status).toBe(200);
      }
      const response = await app.request("/v1/probe", { headers: bearer });
      expect(response.status).toBe(429);
      expect(response.headers.get("retry-after")).toMatch(/^\d+$/);
      await errorCode(response, 429, "TOO_MANY_REQUESTS");
      vi.useFakeTimers();
      vi.setSystemTime(Date.now() + 61_000);
      expect((await app.request("/v1/probe", { headers: bearer })).status).toBe(200);
      vi.useRealTimers();
      row = keyRow();
      db.sdkKey.findUnique.mockResolvedValue(row as never);
    }
  });
  it("takes each /v1 budget from its own env var over a fixed 60 s window, not the RPC family", async () => {
    const saved = { ...state.env };
    try {
      Object.assign(state.env, {
        RATE_LIMIT_SDK_IP_POINTS: 7,
        RATE_LIMIT_SDK_KEY_POINTS: 2,
        RATE_LIMIT_SDK_OWNER_POINTS: 5,
        // Scaling the RPC family must not move any /v1 budget.
        RATE_LIMIT_RPC_POINTS: 1000,
        RATE_LIMIT_RPC_WINDOW_SECONDS: 600,
      });
      app = await build();
      for (let i = 0; i < 2; i++)
        expect((await app.request("/v1/probe", { headers: bearer })).status).toBe(200);
      await errorCode(
        await app.request("/v1/probe", { headers: bearer }),
        429,
        "TOO_MANY_REQUESTS",
      );
      expect(state.budgets.filter((b) => b.keyPrefix.startsWith("sdk-http:"))).toMatchObject([
        { keyPrefix: "sdk-http:ip", points: 7, duration: 60 },
        { keyPrefix: "sdk-http:key", points: 2, duration: 60 },
        { keyPrefix: "sdk-http:owner", points: 5, duration: 60 },
      ]);
    } finally {
      Object.assign(state.env, saved);
    }
  });
  it("refuses a /v1 budget that is not a positive integer instead of building a limiter", async () => {
    const saved = { ...state.env };
    try {
      for (const bad of [0, -1, 1.5, Number.NaN, undefined]) {
        Object.assign(state.env, { ...saved, RATE_LIMIT_SDK_OWNER_POINTS: bad });
        await expect(build()).rejects.toThrow(/RATE_LIMIT_SDK_OWNER_POINTS/);
      }
    } finally {
      Object.assign(state.env, saved);
    }
  });
  it("charges anonymous rejections and fails closed before authentication when the store fails", async () => {
    for (let i = 0; i < 300; i++) expect((await app.request("/v1/probe")).status).toBe(401);
    await errorCode(await app.request("/v1/probe"), 429, "TOO_MANY_REQUESTS");
    expect(db.sdkKey.findUnique).not.toHaveBeenCalled();
    app = await build();
    state.budgetFailure = new Error(credential.raw);
    const response = await app.request("/v1/probe", { headers: bearer });
    expect(response.headers.get("retry-after")).toBe("5");
    await errorCode(response, 503, "SERVICE_UNAVAILABLE");
    expect(db.sdkKey.findUnique).not.toHaveBeenCalled();
  });
  it("keys the IP budget on exactly TRUST_PROXY_HOPS trusted proxies, else the socket peer", async () => {
    for (const [peer, hops, forwarded, expected] of [
      ["198.51.100.7", undefined, "1.2.3.4", "198.51.100.7"],
      // A LAN client cannot choose its key with no trusted proxy configured.
      ["10.0.0.2", undefined, "1.2.3.4, 198.51.100.8, 10.0.0.1", "10.0.0.2"],
      ["10.0.0.2", 0, "1.2.3.4", "10.0.0.2"],
      ["198.51.100.9", 1, "1.2.3.4, 198.51.100.8", "198.51.100.8"],
      // Short or malformed chains fall back to the socket, never chain[0].
      ["10.0.0.2", 2, "1.2.3.4", "10.0.0.2"],
      ["10.0.0.2", 1, "1.2.3.4, garbage", "10.0.0.2"],
    ] as const) {
      state.peer = peer;
      state.env.TRUST_PROXY_HOPS = hops;
      await app.request("/v1/probe", { headers: { "x-forwarded-for": forwarded } });
      expect(state.charges.at(-1)).toEqual({ prefix: "sdk-http:ip", key: expected });
    }
  });
  it("counts streamed JSON bytes at the cap despite misleading Content-Length", async () => {
    const send = (body: string, extra: Record<string, string> = {}) =>
      app.request("/v1/probe", {
        method: "POST",
        headers: { ...bearer, "content-type": "application/json", ...extra },
        body,
      });
    expect(SDK_JSON_MAX_BYTES).toBe(1_048_576);
    const exact = JSON.stringify("é".repeat((SDK_JSON_MAX_BYTES - 2) / 2));
    expect(Buffer.byteLength(exact)).toBe(SDK_JSON_MAX_BYTES);
    expect((await send(exact)).status).toBe(200);
    const lengths: Record<string, string>[] = [
      {},
      { "content-length": "1" },
      { "content-length": String(SDK_JSON_MAX_BYTES + 1) },
    ];
    for (const extra of lengths)
      await errorCode(await send(`${exact} `, extra), 413, "PAYLOAD_TOO_LARGE");
    await errorCode(await send("{broken"), 400, "BAD_REQUEST");
    await errorCode(
      await send("{}", { "content-encoding": "gzip" }),
      415,
      "UNSUPPORTED_MEDIA_TYPE",
    );
    await errorCode(
      await send("{}", { "content-type": "text/plain" }),
      415,
      "UNSUPPORTED_MEDIA_TYPE",
    );
    expect((await send("{}")).status).toBe(200);
    expect((await app.request("/v1/probe", { method: "POST", headers: bearer })).status).toBe(200);
  });
  it("cancels oversized streams and rejects interrupted and already aborted bodies before service work", async () => {
    const cancel = vi.fn();
    let pulls = 0;
    const oversized = new ReadableStream<Uint8Array>(
      {
        pull(controller) {
          pulls++;
          controller.enqueue(new Uint8Array(256 * 1024));
        },
        cancel,
      },
      { highWaterMark: 0 },
    );
    const send = (body: ReadableStream<Uint8Array>, signal?: AbortSignal) =>
      app.request(
        new Request("http://localhost/v1/probe", {
          method: "POST",
          headers: { ...bearer, "content-type": "application/json" },
          body,
          duplex: "half",
          signal,
        }),
      );
    await errorCode(await send(oversized), 413, "PAYLOAD_TOO_LARGE");
    expect(cancel).toHaveBeenCalledOnce();
    expect(pulls).toBe(5);
    const invalidUtf8 = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([34, 255, 34]));
        controller.close();
      },
    });
    await errorCode(await send(invalidUtf8), 400, "BAD_REQUEST");
    const interrupted = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.error(new Error("private stream failure"));
      },
    });
    await errorCode(await send(interrupted), 400, "BAD_REQUEST");
    await errorCode(
      await send(
        new ReadableStream({
          start(controller) {
            controller.close();
          },
        }),
        AbortSignal.abort(),
      ),
      400,
      "BAD_REQUEST",
    );
    expect(state.effect).not.toHaveBeenCalled();
    expect((await app.request("/v1/probe", { headers: bearer })).status).toBe(200);
  });
  it("redacts credentials error causes and hostile request IDs from responses and logs", async () => {
    const ids = new Set<string | null>();
    for (const error of [
      new Error(credential.raw),
      new ORPCError("BAD_REQUEST", {
        message: credential.raw,
        data: { secret: credential.raw },
        cause: new Error(credential.raw),
      }),
      new ORPCError("toString", { message: credential.raw }),
    ]) {
      state.failure = error;
      const response = await app.request(`/v1/probe?ordinary=secret-query`, {
        headers: { ...bearer, "x-request-id": credential.raw },
      });
      ids.add(response.headers.get("x-request-id"));
      expect(await response.text()).not.toContain(credential.raw);
    }
    await app.request(`/v1/${credential.raw}?token=${credential.raw}`, { headers: bearer });
    state.budgetFailure = new Error(credential.raw);
    await app.request("/v1/probe", { headers: bearer });
    expect(ids.size).toBe(3);
    for (const log of [console.log, console.warn, console.error]) {
      expect(JSON.stringify(vi.mocked(log).mock.calls)).not.toContain(credential.raw);
      expect(JSON.stringify(vi.mocked(log).mock.calls)).not.toContain("secret-query");
    }
  });
  it("maps database failure to a redacted internal error and limiter failures to stable retry metadata", async () => {
    db.sdkKey.findUnique.mockRejectedValueOnce(new Error(credential.raw));
    await errorCode(
      await app.request("/v1/probe", { headers: bearer }),
      500,
      "INTERNAL_SERVER_ERROR",
    );
    state.budgetFailure = new RateLimiterRes(0, 1200, 600, false);
    const response = await app.request("/v1/probe", { headers: bearer });
    expect(response.headers.get("retry-after")).toBe("2");
    await errorCode(response, 429, "TOO_MANY_REQUESTS");
  });
});

it("mounts both binary upload planes before JSON parsing and the global body limit", async () => {
  const id = "ee000000-0000-4000-8000-000000000001";
  const receipt = {
    id,
    sandboxId: "sbx",
    generation: 1,
    direction: "UPLOAD",
    state: "OPEN",
    totalBytes: 1048576,
    receivedBytes: 0,
    chunkBytes: 1048576,
    idleExpiresAt: new Date().toISOString(),
    expiresAt: new Date().toISOString(),
  };
  state.transferStatus.mockResolvedValue(receipt);
  state.transferWrite.mockResolvedValue({ ...receipt, receivedBytes: 1048576 });
  db.user.findUnique.mockResolvedValue({
    twoFactorEnabled: true,
    role: "user",
    banned: false,
  } as never);
  for (const base of ["/v1", "/api/dashboard"]) {
    const headers = {
      ...bearer,
      cookie,
      origin: "https://api.example",
      "content-type": "application/octet-stream",
      "content-range": "bytes 0-1048575/1048576",
    };
    const good = await app.request(`${base}/transfers/${id}`, {
      method: "PUT",
      headers,
      body: new Uint8Array(1048576),
    });
    expect(good.status).toBe(200);
    expect(good.headers.get("access-control-allow-origin")).toBeNull();
    const overflow = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(new Uint8Array(1048576));
        c.enqueue(new Uint8Array(1));
        c.close();
      },
    });
    const bad = await app.request(
      new Request(`https://api.example${base}/transfers/${id}`, {
        method: "PUT",
        headers,
        body: overflow,
        duplex: "half",
      } as RequestInit),
    );
    expect(bad.status).toBe(413);
  }
  expect(state.transferWrite).toHaveBeenCalledTimes(2);
  expect(state.globalBody).not.toHaveBeenCalled();
  expect(state.render).not.toHaveBeenCalled();
});

it("rejects raw duplicate public map keys before RPC, batch and OpenAPI object decoding", async () => {
  state.getSession.mockResolvedValue({ ...session, user: { ...session.user, role: "admin" } });
  db.user.findUnique.mockResolvedValue({
    twoFactorEnabled: true,
    role: "admin",
    emailVerified: true,
    banned: false,
    banExpires: null,
    deletionRequestedAt: null,
    createdAt: new Date("2020-01-01"),
  } as never);
  for (const [path, body, extra, code] of [
    [
      "/rpc/sandboxes/runCommand",
      '{"json":{"envs":{"A":"private-first","\\u0041":"private-second"}}}',
      {},
      "sandbox.env_invalid",
    ],
    [
      "/rpc/sandboxes/__batch__",
      '[{"url":"http://test/rpc/sandboxes/runCommand","body":{"json":{"envs":{"A":"private-first","A":"private-second"}}}}]',
      { "x-orpc-batch": "buffered" },
      "sandbox.env_invalid",
    ],
    [
      "/api-reference/sandboxes/runCommand",
      '{"envs":{"A":"private-first","A":"private-second"}}',
      {},
      "sandbox.env_invalid",
    ],
    [
      "/rpc/sandboxes/createSandbox",
      '{"json":{"sandboxHostId":"host-1","templateId":"tpl-1","idempotencyKey":"metadata-duplicate","metadata":{"team":"private-first","t\\u0065am":"private-second"}}}',
      {},
      "sandbox.metadata_invalid",
    ],
    [
      "/api-reference/sandboxes/createSandbox",
      '{"sandboxHostId":"host-1","templateId":"tpl-1","idempotencyKey":"metadata-duplicate","metadata":{"team":"private-first","team":"private-second"}}',
      {},
      "sandbox.metadata_invalid",
    ],
  ] as const) {
    const response = await app.request(path, {
      method: "POST",
      headers: { cookie, "content-type": "application/json", "x-csrf-token": "orpc", ...extra },
      body,
    });
    expect(response.status, path).toBe(400);
    const text = await response.text();
    expect(text).toContain(code);
    expect(text).not.toContain("private-");
  }
});

it("checks alternate RPC JSON carriers and GET subrequests in batches before decoding", async () => {
  const raw = '{"json":{"envs":{"A":"first","\\u0041":"second"}}}';
  const jsonHeaders = { cookie, "x-csrf-token": "orpc" };
  const noContentType = new Request("http://test/rpc/sandboxes/runCommand", {
    method: "POST",
    headers: jsonHeaders,
    body: new TextEncoder().encode(raw),
  });
  expect((await app.request(noContentType)).status).toBe(400);
  expect(
    (
      await app.request(`/rpc/sandboxes/runCommand?data=${encodeURIComponent(raw)}`, {
        headers: jsonHeaders,
      })
    ).status,
  ).toBe(400);
  const form = new FormData();
  form.set("data", raw);
  expect(
    (
      await app.request("/rpc/sandboxes/runCommand", {
        method: "POST",
        headers: jsonHeaders,
        body: form,
      })
    ).status,
  ).toBe(400);
  const batch = [
    { method: "GET", url: `http://test/rpc/sandboxes/runCommand?data=${encodeURIComponent(raw)}` },
  ];
  const response = await app.request("/rpc/sandboxes/__batch__", {
    method: "POST",
    headers: { ...jsonHeaders, "content-type": "application/json", "x-orpc-batch": "buffered" },
    body: JSON.stringify(batch),
  });
  expect(response.status).toBe(207);
  expect(await response.json()).toMatchObject([{ status: 400 }]);
});

it("keeps the metadata error code through RPC form, GET and batch subrequest guards", async () => {
  const raw = '{"json":{"metadata":{"team":"private-first","t\\u0065am":"private-second"}}}';
  const headers = { cookie, "x-csrf-token": "orpc" };
  const form = new FormData();
  form.set("data", raw);
  const formResponse = await app.request("/rpc/sandboxes/createSandbox", {
    method: "POST",
    headers,
    body: form,
  });
  const getResponse = await app.request(`/rpc/sandboxes/list?data=${encodeURIComponent(raw)}`, {
    headers,
  });
  for (const response of [formResponse, getResponse]) {
    expect(response.status).toBe(400);
    const text = await response.text();
    expect(text).toContain("sandbox.metadata_invalid");
    expect(text).not.toContain("private-");
    expect(text).not.toContain("sandbox.env_invalid");
  }
  const response = await app.request("/rpc/sandboxes/__batch__", {
    method: "POST",
    headers: { ...headers, "content-type": "application/json", "x-orpc-batch": "buffered" },
    body: JSON.stringify([
      { method: "GET", url: `http://test/rpc/sandboxes/list?data=${encodeURIComponent(raw)}` },
    ]),
  });
  expect(response.status).toBe(207);
  const text = await response.text();
  expect(text).toContain("sandbox.metadata_invalid");
  expect(text).not.toContain("private-");
  expect(text).not.toContain("sandbox.env_invalid");
});

it("3A actual Hono error handler strips raw producer text stack and cause", async () => {
  const sentinel = "synthetic-env-stdin-hono-3a";
  state.render.mockRejectedValueOnce(
    new Error(sentinel, { cause: new Error(Buffer.from(sentinel).toString("base64")) }),
  );
  const response = await app.request("/en-US/dashboard");
  expect(response.status).toBe(500);
  expect(await response.text()).not.toContain(sentinel);
  const logged = inspect(vi.mocked(console.error).mock.calls, { depth: 20 });
  expect(logged).not.toContain(sentinel);
  expect(logged).not.toContain(Buffer.from(sentinel).toString("base64"));
  expect(console.error).toHaveBeenCalledWith(expect.stringContaining("Unhandled error"), {
    code: "unhandled_error",
    errorClass: "Error",
  });
});

it("redacts reset callback path tokens in both access logs and the real onError handler", async () => {
  const { auth } = await import("@wssp/auth");
  vi.mocked(auth.handler).mockRejectedValueOnce(new Error("producer text"));
  const response = await app.request(
    "/api/auth/reset-password/RESET-SENTINEL?callbackURL=PRIVATE-QUERY",
  );
  expect(response.status).toBe(500);
  const logged = inspect([vi.mocked(console.log).mock.calls, vi.mocked(console.error).mock.calls], {
    depth: 20,
  });
  expect(logged).toContain("/api/auth/reset-password/[redacted]");
  expect(logged).not.toContain("RESET-SENTINEL");
  expect(logged).not.toContain("PRIVATE-QUERY");
  expect(console.error).toHaveBeenCalledWith(
    expect.stringContaining("Unhandled error on GET /api/auth/reset-password/[redacted]"),
    expect.any(Object),
  );
});

describe("unknown dashboard RPC procedures", () => {
  it("answer oRPC NOT_FOUND (404) for every caller instead of a generic 500", async () => {
    for (const headers of [{ cookie }, {}, bearer]) {
      for (const [method, path] of [
        ["POST", "/rpc/sandboxHosts/noSuchProcedure"],
        ["POST", "/rpc/noSuchRouter"],
        ["GET", "/rpc/sandboxHosts/noSuchProcedure"],
        ["POST", "/rpc"],
      ] as const) {
        const response = await app.request(path, {
          method,
          headers: { ...headers, "content-type": "application/json", "x-csrf-token": "orpc" },
          ...(method === "POST" ? { body: JSON.stringify({ json: {} }) } : {}),
        });
        expect(response.status, `${method} ${path}`).toBe(404);
        expect(await response.json()).toEqual({
          json: { defined: false, code: "NOT_FOUND", status: 404, message: "Not Found" },
        });
      }
    }
    expect(state.render).not.toHaveBeenCalled();
    expect(console.error).not.toHaveBeenCalledWith(
      expect.stringContaining("Unhandled error"),
      expect.anything(),
    );
    // Known procedures keep their auth answer for anonymous callers.
    const known = await app.request("/rpc/sandboxHosts/listHosts", {
      method: "POST",
      headers: { "content-type": "application/json", "x-csrf-token": "orpc" },
      body: JSON.stringify({ json: {} }),
    });
    expect(known.status).toBe(401);
  });
});

describe("/sw/push-renew", () => {
  const renew = () =>
    app.request("/sw/push-renew", {
      method: "POST",
      headers: {
        cookie,
        "content-type": "application/json",
        origin: state.env.CORS_ORIGIN,
        "sec-fetch-site": "same-site",
      },
      body: JSON.stringify({
        endpoint: "https://fcm.googleapis.com/fcm/send/renew-fixture",
        keys: { p256dh: "p256dh-fixture", auth: "auth-fixture" },
      }),
    });
  // Forced 2FA defaults on for admins, so an unenrolled admin past the grace fails it.
  const gateUser = (twoFactorEnabled: boolean) => ({
    twoFactorEnabled,
    role: "admin",
    emailVerified: true,
    banned: false,
    banExpires: null,
    deletionRequestedAt: null,
    createdAt: new Date("2020-01-01"),
  });
  it("applies the required-2FA gate before touching the subscription", async () => {
    state.getSession.mockResolvedValue(session);
    db.user.findUnique.mockResolvedValue(gateUser(false) as never);
    const response = await renew();
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ code: "auth.two_factor_required" });
    expect(db.pushSubscription.findUnique).not.toHaveBeenCalled();
    expect(db.pushSubscription.create).not.toHaveBeenCalled();
  });
  it("renews for a session that satisfies the 2FA policy", async () => {
    state.getSession.mockResolvedValue(session);
    db.user.findUnique.mockResolvedValue(gateUser(true) as never);
    db.pushSubscription.findUnique.mockResolvedValue(null);
    const response = await renew();
    expect(response.status).toBe(200);
    expect(db.pushSubscription.create).toHaveBeenCalledOnce();
  });
  it("answers 409, not 500, for an endpoint registered to another user", async () => {
    state.getSession.mockResolvedValue(session);
    db.user.findUnique.mockResolvedValue(gateUser(true) as never);
    db.pushSubscription.findUnique.mockResolvedValue({ userId: "someone-else" } as never);
    const response = await renew();
    expect(response.status).toBe(409);
    expect(db.pushSubscription.create).not.toHaveBeenCalled();
  });
});

// Same-site sibling origins can submit simple form posts without a preflight.
// The oRPC header gate must stay active when CORS_ORIGIN is unset.
describe("R5-TS-01 CSRF protection without CORS_ORIGIN", () => {
  beforeEach(async () => {
    state.env.CORS_ORIGIN = undefined;
    state.getSession.mockResolvedValue({ ...session, user: { ...session.user, role: "admin" } });
    db.user.findUnique.mockResolvedValue({
      twoFactorEnabled: true,
      role: "admin",
      emailVerified: true,
      banned: false,
      banExpires: null,
      deletionRequestedAt: null,
      createdAt: new Date("2020-01-01"),
    } as never);
    app = await build();
  });
  afterEach(() => {
    state.env.CORS_ORIGIN = "https://browser.example";
  });

  it("rejects direct multipart RPC posts without the header", async () => {
    const form = new FormData();
    form.set("data", JSON.stringify({ json: {} }));
    const response = await app.request("/rpc/health/check", {
      method: "POST",
      headers: { cookie, origin: "https://sibling.api.example" },
      body: form,
    });
    expect(response.status).toBe(403);
    expect(await response.text()).toContain("CSRF_TOKEN_MISMATCH");
  });

  it("rejects a multipart procedure through the batch path without the header", async () => {
    const response = await app.request("/rpc/health/__batch__", {
      method: "POST",
      headers: { cookie, "content-type": "application/json", "x-orpc-batch": "buffered" },
      body: JSON.stringify([
        {
          method: "POST",
          url: "http://test/rpc/health/check",
          headers: { "content-type": "multipart/form-data; boundary=inner" },
          body: { json: {} },
        },
      ]),
    });
    expect(response.status).toBe(207);
    expect(await response.json()).toMatchObject([{ status: 403 }]);
  });

  it("rejects urlencoded OpenAPI posts without the header", async () => {
    const response = await app.request("/api-reference/health/check", {
      method: "POST",
      headers: {
        cookie,
        "content-type": "application/x-www-form-urlencoded",
        origin: "https://sibling.api.example",
      },
      body: "data=%7B%7D",
    });
    expect(response.status).toBe(403);
    expect(await response.text()).toContain("CSRF_TOKEN_MISMATCH");
  });

  it("accepts the normal client header", async () => {
    const response = await app.request("/rpc/health/check", {
      method: "POST",
      headers: { cookie, "content-type": "application/json", "x-csrf-token": "orpc" },
      body: JSON.stringify({ json: {} }),
    });
    expect(response.status).toBe(200);
    expect(await response.text()).toContain("OK");
  });
});

describe("readiness build identity", () => {
  beforeEach(async () => {
    const { redisConnection } = await import("@wssp/queue");
    vi.mocked(redisConnection.ping).mockResolvedValue("PONG");
    db.$queryRaw.mockResolvedValue([]);
  });
  afterEach(() => vi.unstubAllEnvs());

  it.each([undefined, "short", "a".repeat(40)])(
    "returns commit or null on every branch (%s)",
    async (version) => {
      vi.stubEnv("BUILD_VERSION", version);
      const commit = version?.length === 40 ? version : null;
      let closing = false;
      let ready = true;
      const application = await createApp({
        isShuttingDown: () => closing,
        isWorkerReady: () => ready,
      });
      state.env.WORKER_MODE = "embedded";
      expect(await (await application.request("/ready")).json()).toMatchObject({
        ok: true,
        commit,
      });
      ready = false;
      const missing = await application.request("/ready");
      expect(missing.status).toBe(503);
      expect(await missing.json()).toMatchObject({ ok: false, commit });
      db.$queryRaw.mockRejectedValueOnce(new Error("wssp_sdk_readiness-private"));
      const failed = await application.request("/ready");
      expect(failed.status).toBe(503);
      expect(await failed.json()).toMatchObject({ ok: false, commit });
      closing = true;
      const charges = state.charges.length;
      for (let i = 0; i < 65; i++) {
        const drained = await application.request("/ready");
        expect(drained.status).toBe(503);
        expect(await drained.json()).toEqual({ ok: false, commit, checks: { shuttingDown: true } });
      }
      expect(state.charges).toHaveLength(charges);
    },
  );
});
