vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { createAdaptorServer } from "@hono/node-server";
import { ORPCError } from "@orpc/server";
import type { ServicePrincipal } from "@wssp/api/lib/sdk-key-access";
import type { SandboxConnectCheck } from "@wssp/api/sandbox/connect-binding";
import { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WebSocketServer } from "ws";
import {
  killBrowserClients,
  upgradeBrowserTerminal,
} from "../sandbox-relay/browser-terminal-client-harness.js";
import { selectWebSocketSubprotocol } from "../sandbox-relay/browser-terminal-upgrade.js";
import { ConnectManager } from "../sandbox-relay/connect-manager.js";
import { createSandboxApi } from "./middleware.js";

vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_SECRET: "connect-route-test",
    // The relay's limiter module loads with the subprotocol selector.
    RATE_LIMIT_AUTH_POINTS: 30,
    RATE_LIMIT_AUTH_WINDOW_SECONDS: 60,
    RATE_LIMIT_RPC_POINTS: 100,
    RATE_LIMIT_RPC_WINDOW_SECONDS: 60,
    RATE_LIMIT_EMAIL_POINTS: 3,
    RATE_LIMIT_EMAIL_WINDOW_SECONDS: 3600,
    RATE_LIMIT_SDK_IP_POINTS: 100,
    RATE_LIMIT_SDK_KEY_POINTS: 100,
    RATE_LIMIT_SDK_OWNER_POINTS: 100,
  },
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
// Loaded with the subprotocol selector (the browser terminal module); never called.
vi.mock("@wssp/auth", () => ({ auth: { api: { getSession: vi.fn() }, handler: vi.fn() } }));
vi.mock("../client-ip.js", () => ({ resolveClientIp: () => "203.0.113.9" }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/db", async () => ({
  default: await (await import("@wssp/api/test/mock-prisma")).createMockPrisma(),
}));

/** Budgets by key prefix: the connect limiter's own buckets can be exhausted or down. */
const budget = vi.hoisted(() => ({
  refuse: new Map<string, "limited" | "down">(),
  seen: [] as { prefix: string; key: string }[],
}));
vi.mock("@wssp/api/lib/procedure-budget", async () => {
  const { ORPCError } = await import("@orpc/server");
  return {
    createProcedureBudget: (options: { keyPrefix: string }) => async (key: string) => {
      budget.seen.push({ prefix: options.keyPrefix, key });
      const refusal = budget.refuse.get(options.keyPrefix);
      if (refusal === "limited") throw new ORPCError("TOO_MANY_REQUESTS");
      if (refusal === "down") throw new ORPCError("SERVICE_UNAVAILABLE");
    },
  };
});

const keys = vi.hoisted(() => new Map<string, unknown>());
vi.mock("@wssp/api/lib/sdk-key-access", async (original) => ({
  ...(await original<typeof import("@wssp/api/lib/sdk-key-access")>()),
  authenticateSdkKeySecret: async (raw: string) => keys.get(raw) ?? null,
}));

const connect = vi.hoisted(() => ({
  check: vi.fn<(...args: unknown[]) => Promise<unknown>>(),
}));
vi.mock("@wssp/api/sandbox/connect-binding", () => ({
  checkSandboxConnect: (...args: unknown[]) => connect.check(...args),
}));

const SECRET = "wssp_sdk_connecttestsecret";
function principal(kind: ServicePrincipal["credentialKind"] = "API"): ServicePrincipal {
  return {
    kind: "sdkKey",
    credentialKind: kind,
    ownSandboxesOnly: false,
    expiresAt: null,
    keyId: "key-1",
    ownerId: "owner-1",
    resourceMode: "ALL_OWNED",
    scopes: new Set(["sandboxes:connect"]),
    allowedHostIds: "allOwned",
    allowedRevisionIds: "allOwned",
    allowedPoolIds: "allUsable",
  };
}

const binding = {
  ownerId: "owner-1",
  keyId: "key-1",
  sandboxId: "sbx-1",
  hostId: "host-1",
  hostOwnerId: "owner-1",
  generation: 1,
  epoch: 2,
  keyExpiresAt: null,
  leaseExpiresAt: null,
};
const retained = {
  context: {},
  current: () => true,
  recheck: async () => retained,
};
const okCheck: SandboxConnectCheck = { ok: true, binding, retained };

let host: "ok" | "outdated" | "unavailable";
let reservation:
  | { ok: true; reservation: { binding: typeof binding; release: () => void } }
  | {
      ok: false;
      reason: "shutdown" | "capacity";
    };
let released: number;
let shuttingDown: boolean;
const manager = {
  get shuttingDown() {
    return shuttingDown;
  },
  hostAvailability: () => host,
  lifecycleMark: () => 0,
  reserve: () => reservation,
  attach: vi.fn(),
} as unknown as ConnectManager;

const app = new Hono().route("/v1", createSandboxApi({ connects: () => manager }));

function upgrade(
  headers: Record<string, string> = {},
  path = "/v1/sandboxes/sbx-1/connect",
  method = "GET",
) {
  return app.request(path, {
    method,
    headers: {
      upgrade: "websocket",
      connection: "Upgrade",
      "sec-websocket-protocol": "wssp.connect.v1",
      authorization: `Bearer ${SECRET}`,
      ...headers,
    },
  });
}

async function refusal(response: Response) {
  const body = (await response.json()) as { error: { code: string; reason?: string } };
  // The Node adapter drops a refused upgrade's body: the headers carry the same code and reason.
  expect(response.headers.get("x-wssp-error-code")).toBe(body.error.code);
  expect(response.headers.get("x-wssp-error-reason")).toBe(body.error.reason ?? null);
  return { status: response.status, code: body.error.code, reason: body.error.reason };
}

beforeEach(() => {
  keys.clear();
  keys.set(SECRET, principal());
  budget.refuse.clear();
  budget.seen.length = 0;
  connect.check.mockReset();
  connect.check.mockResolvedValue(okCheck);
  host = "ok";
  released = 0;
  shuttingDown = false;
  reservation = { ok: true, reservation: { binding, release: () => (released += 1) } };
});

describe("GET /v1/sandboxes/{id}/connect refusals (before any WebSocket)", () => {
  it("refuses during shutdown with 503", async () => {
    shuttingDown = true;
    expect(await refusal(await upgrade())).toMatchObject({
      status: 503,
      code: "SERVICE_UNAVAILABLE",
    });
    expect(connect.check).not.toHaveBeenCalled();
  });

  it("requires a WebSocket upgrade (426)", async () => {
    const response = await upgrade({ upgrade: "h2c" });
    expect(response.status).toBe(426);
  });

  it.each([
    [{ origin: "https://evil.example" }],
    [{ origin: "null" }],
    [{ cookie: "better-auth.session_token=abc" }],
  ])("refuses browser material %j with 403 before authentication", async (headers) => {
    keys.clear(); // even an unauthenticated request is refused at this step
    expect(await refusal(await upgrade(headers))).toMatchObject({ status: 403, code: "FORBIDDEN" });
  });

  it.each([
    [""],
    ["wssp.terminal.v1"],
    ["wssp.connect.v1, wssp.connect.v2"],
    [`wssp.connect.v1, ${SECRET}`],
    ["wssp.connect.v1, bearer.abc"],
  ])("requires exactly the wssp.connect.v1 subprotocol (offered %j)", async (offered) => {
    expect(await refusal(await upgrade({ "sec-websocket-protocol": offered }))).toMatchObject({
      status: 400,
      code: "BAD_REQUEST",
    });
    expect(connect.check).not.toHaveBeenCalled();
  });

  it("refuses a credential in the query even next to a valid header", async () => {
    const response = await upgrade({}, `/v1/sandboxes/sbx-1/connect?token=${SECRET}`);
    expect(await refusal(response)).toMatchObject({ status: 400 });
  });

  it("refuses a missing, unknown or non-API credential with 401", async () => {
    expect((await upgrade({ authorization: "" })).status).toBe(401);
    expect((await upgrade({ authorization: "Bearer wssp_sdk_unknown" })).status).toBe(401);
    keys.set(SECRET, principal("AGENT_TOKEN"));
    expect((await upgrade()).status).toBe(401);
    keys.set(SECRET, principal("OAUTH_GRANT"));
    expect((await upgrade()).status).toBe(401);
    expect(connect.check).not.toHaveBeenCalled();
  });

  it("applies the connect budget per IP and per key, fail closed", async () => {
    budget.refuse.set("sdk-connect:key", "limited");
    expect(await refusal(await upgrade())).toMatchObject({
      status: 429,
      code: "TOO_MANY_REQUESTS",
    });
    expect(budget.seen).toEqual(
      expect.arrayContaining([
        { prefix: "sdk-connect:ip", key: "203.0.113.9" },
        { prefix: "sdk-connect:key", key: "key-1" },
      ]),
    );
    budget.refuse.set("sdk-connect:key", "down");
    expect(await refusal(await upgrade())).toMatchObject({ status: 503 });
    budget.refuse.clear();
    budget.refuse.set("sdk-connect:ip", "limited");
    expect((await upgrade()).status).toBe(429);
    expect(connect.check).not.toHaveBeenCalled();
  });

  it.each([
    [new ORPCError("FORBIDDEN"), 403, "FORBIDDEN"],
    [new ORPCError("NOT_FOUND", { message: "Sandbox not found." }), 404, "NOT_FOUND"],
    [
      new ORPCError("CONFLICT", { data: { code: "sandbox.managed", purpose: "template_build" } }),
      409,
      "sandbox.managed",
    ],
  ])("maps the authorization's refusal %s", async (error, status, code) => {
    connect.check.mockRejectedValue(error);
    expect(await refusal(await upgrade())).toMatchObject({ status, code });
  });

  it("refuses a sandbox that is not running on a usable host with 409 state_conflict", async () => {
    for (const intent of ["sandbox_stopped", "sandbox_destroyed", "expired", "revoked"]) {
      connect.check.mockResolvedValue({ ok: false, intent });
      expect(await refusal(await upgrade())).toMatchObject({
        status: 409,
        code: "sandbox.state_conflict",
      });
    }
  });

  it("refuses build/managed sandboxes and incapable hosts with UNSUPPORTED_CAPABILITY", async () => {
    connect.check.mockResolvedValue({ ok: false, intent: "unsupported" });
    expect(await refusal(await upgrade())).toMatchObject({
      code: "UNSUPPORTED_CAPABILITY",
      reason: "connect_sandbox_unsupported",
    });
    connect.check.mockResolvedValue(okCheck);
    host = "outdated";
    expect(await refusal(await upgrade())).toMatchObject({
      code: "UNSUPPORTED_CAPABILITY",
      reason: "connect_host_outdated",
    });
    host = "unavailable";
    expect(await refusal(await upgrade())).toMatchObject({
      status: 409,
      code: "sandbox.host_unavailable",
    });
  });

  it("refuses past the connection caps with 429", async () => {
    reservation = { ok: false, reason: "capacity" };
    expect(await refusal(await upgrade())).toMatchObject({
      status: 429,
      code: "TOO_MANY_REQUESTS",
    });
  });

  it("an authorized upgrade the adapter cannot complete frees its slot at once", async () => {
    const response = await upgrade();
    // No Node upgrade waiter in app.request(): the adapter answers 500.
    expect(response.status).toBe(500);
    expect(connect.check).toHaveBeenCalledWith(principal(), "sbx-1");
    expect(released).toBe(1);
    expect(manager.attach).not.toHaveBeenCalled();
  });

  it("is GET only", async () => {
    expect((await upgrade({}, "/v1/sandboxes/sbx-1/connect", "POST")).status).toBe(405);
  });
});

describe("GET /v1/sandboxes/{id}/connect over a real WebSocket", () => {
  // The test I/O guard blocks outbound TCP in-process: the CLI is a child process.
  let server: ReturnType<typeof createAdaptorServer> | undefined;
  let real: ConnectManager;
  const hostSends: string[] = [];
  afterEach(async () => {
    killBrowserClients();
    real?.dispose();
    if (server) {
      server.close();
      await once(server, "close").catch(() => undefined);
    }
    server = undefined;
  });

  async function listen() {
    hostSends.length = 0;
    real = new ConnectManager(
      {
        connectHost: () => ({
          link: {
            socket: {
              readyState: 1,
              send: (data: string | ArrayBuffer | Uint8Array) => {
                if (typeof data === "string") hostSends.push(data);
              },
            },
            hostId: "host-1",
            ownerId: "owner-1",
            epoch: 2,
            protocolVersion: "1.0",
            authorized: () => true,
            kinds: ["pty", "exec"],
          },
        }),
        closeHostSocket: () => undefined,
      },
      { check: async () => okCheck },
    );
    const realApp = new Hono().route("/v1", createSandboxApi({ connects: () => real }));
    server = createAdaptorServer({
      fetch: realApp.fetch,
      websocket: {
        server: new WebSocketServer({
          noServer: true,
          handleProtocols: (protocols, request) =>
            selectWebSocketSubprotocol(protocols, request.url),
        }),
      },
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    return `127.0.0.1:${(server.address() as AddressInfo).port}`;
  }

  it("selects wssp.connect.v1, sends hello, relays an open and ends with 4401", async () => {
    const base = await listen();
    const client = await upgradeBrowserTerminal({
      base,
      path: "/v1/sandboxes/sbx-1/connect",
      protocols: ["wssp.connect.v1"],
      origin: null,
      authorization: `Bearer ${SECRET}`,
    });
    if (client.kind !== "open") throw new Error(`refused ${client.status}`);
    expect(client.protocol).toBe("wssp.connect.v1");
    await vi.waitFor(() =>
      expect(client.text[0]).toMatchObject({ type: "hello", sandboxId: "sbx-1" }),
    );
    client.sendText(JSON.stringify({ type: "open", channel: 1, kind: "exec", argv: ["true"] }));
    await vi.waitFor(() =>
      expect(hostSends.map((f) => JSON.parse(f).type)).toContain("channel.open"),
    );
    real.list()[0]!.end("revoked");
    const closed = await client.closed;
    expect(closed.code).toBe(4401);
    expect(client.text.at(-1)).toEqual({ type: "end", intent: "revoked" });
    expect(hostSends.map((f) => JSON.parse(f))).toContainEqual(
      expect.objectContaining({ type: "channel.close", intent: "revoked" }),
    );
    expect(real.resources()).toMatchObject({ connections: 0, reservations: 0 });
  });

  it("refuses the handshake before any socket for a browser origin", async () => {
    const base = await listen();
    const client = await upgradeBrowserTerminal({
      base,
      path: "/v1/sandboxes/sbx-1/connect",
      protocols: ["wssp.connect.v1"],
      origin: "https://evil.example",
      authorization: `Bearer ${SECRET}`,
    });
    expect(client).toMatchObject({ kind: "refused", status: 403 });
    expect(real.resources()).toMatchObject({ connections: 0, reservations: 0 });
  });

  it("a refused upgrade arrives without its body, with the code and reason in headers", async () => {
    connect.check.mockResolvedValue({ ok: false, intent: "sandbox_stopped" });
    const base = await listen();
    const attempt = () =>
      upgradeBrowserTerminal({
        base,
        path: "/v1/sandboxes/sbx-1/connect",
        protocols: ["wssp.connect.v1"],
        origin: null,
        authorization: `Bearer ${SECRET}`,
      });
    expect(await attempt()).toEqual({
      kind: "refused",
      status: 409,
      refusal: null,
      errorCode: "sandbox.state_conflict",
      errorReason: null,
      bodyLength: 0,
    });
    connect.check.mockResolvedValue({ ok: false, intent: "unsupported" });
    expect(await attempt()).toMatchObject({
      status: 400,
      errorCode: "UNSUPPORTED_CAPABILITY",
      errorReason: "connect_sandbox_unsupported",
      bodyLength: 0,
    });
    expect(real.resources()).toMatchObject({ connections: 0, reservations: 0 });
  });
});
