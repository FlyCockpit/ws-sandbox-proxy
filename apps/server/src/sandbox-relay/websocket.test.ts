import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WebSocketServer } from "ws";
import { killBrowserClients, upgradeBrowserTerminal } from "./browser-terminal-client-harness.js";
import { SANDBOX_RELAY_SUBPROTOCOL } from "./protocol.js";

vi.mock("@wssp/db", () => ({
  default: {
    sandboxHost: {
      update: vi.fn().mockResolvedValue({}),
    },
  },
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    RATE_LIMIT_AUTH_POINTS: 100,
    RATE_LIMIT_AUTH_WINDOW_SECONDS: 60,
    TRUST_PROXY_HOPS: undefined,
    DATABASE_URL: "postgresql://localhost:5432/test",
    REDIS_URL: "redis://localhost:6379",
  },
}));
vi.mock("@wssp/env/shared", () => ({
  env: {
    DATABASE_URL: "postgresql://localhost:5432/test",
    REDIS_URL: "redis://localhost:6379",
  },
}));

vi.mock("./auth.js", () => ({
  authenticateSandboxHostWebsocket: vi.fn(),
}));

vi.mock("../rate-limit.js", () => ({
  hostRelayLimiter: {},
  createRateLimiterMiddleware: () => async (_context: unknown, next: () => Promise<void>) => {
    await next();
  },
}));

const { authenticateSandboxHostWebsocket } = await import("./auth.js");
const { createSandboxRelayWebsocketMiddleware, sandboxRelayUpgradeHandler } = await import(
  "./websocket.js"
);
const { sandboxRelaySessionManager } = await import("./session-manager.js");

const authenticateMock = vi.mocked(authenticateSandboxHostWebsocket);

function app() {
  const hono = new Hono();
  hono.use("/ws/sandbox-host", createSandboxRelayWebsocketMiddleware());
  hono.get("/ws/sandbox-host", (c) => c.text("ok"));
  return hono;
}

function websocketHeaders(extra: Record<string, string> = {}) {
  return {
    Upgrade: "websocket",
    "Sec-WebSocket-Protocol": SANDBOX_RELAY_SUBPROTOCOL,
    ...extra,
  };
}

describe("createSandboxRelayWebsocketMiddleware", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("rejects unauthenticated websocket upgrades", async () => {
    const response = await app().request("/ws/sandbox-host", {
      method: "GET",
      headers: websocketHeaders(),
    });

    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({
      error: "Sandbox host websocket authentication required.",
    });
  });

  it("rejects unsupported relay protocol versions before upgrade", async () => {
    const response = await app().request("/ws/sandbox-host", {
      method: "GET",
      headers: websocketHeaders({
        Authorization: "Bearer host_secret",
        "Sec-WebSocket-Protocol": "ws-sandbox-proxy.relay.v999",
      }),
    });

    expect(response.status).toBe(426);
    await expect(response.json()).resolves.toMatchObject({
      type: "protocol.error",
      failure: "protocol_error",
    });
  });

  it("rejects revoked websocket credentials", async () => {
    authenticateMock.mockResolvedValue(null);

    const response = await app().request("/ws/sandbox-host", {
      method: "GET",
      headers: websocketHeaders({ Authorization: "Bearer host_secret" }),
    });

    expect(response.status).toBe(401);
    // Ambiguous: no verdict for an unknown, malformed or wrong-secret credential.
    expect(response.headers.get("x-wssp-credential-refusal")).toBeNull();
    await expect(response.json()).resolves.toEqual({
      error: "Invalid or revoked sandbox host websocket credential.",
    });
  });

  it.each(["credential_revoked", "owner_unavailable"] as const)(
    "names the explicit %s verdict (only produced after the secret verified)",
    async (refusal) => {
      authenticateMock.mockResolvedValue({ refusal });
      const response = await app().request("/ws/sandbox-host", {
        method: "GET",
        headers: websocketHeaders({ Authorization: "Bearer host_secret" }),
      });
      expect(response.status).toBe(401);
      expect(response.headers.get("x-wssp-credential-refusal")).toBe(refusal);
      await expect(response.json()).resolves.toEqual({
        error: "Invalid or revoked sandbox host websocket credential.",
        code: refusal,
      });
    },
  );
});

describe("WP4 liveness through the REAL ws adapter (ping/pong)", () => {
  // The production singleton, with short liveness bounds for these tests only.
  let saved: [number, number];
  let server: ReturnType<typeof serve>;
  let base: string;
  afterAll(() => killBrowserClients());
  beforeEach(async () => {
    saved = [
      sandboxRelaySessionManager.pingIntervalMs,
      sandboxRelaySessionManager.livenessTimeoutMs,
    ];
    sandboxRelaySessionManager.pingIntervalMs = 40;
    sandboxRelaySessionManager.livenessTimeoutMs = 250;
    const hono = new Hono<{ Variables: { sandboxRelayIdentity: unknown } }>();
    hono.get(
      "/ws/sandbox-host",
      async (c, next) => {
        c.set("sandboxRelayIdentity", {
          hostId: `host-${Math.random()}`,
          userId: "user-1",
          tokenId: "token-1",
          credentialKind: "hostToken",
          expiresAt: null,
        });
        await next();
      },
      sandboxRelayUpgradeHandler() as never,
    );
    server = serve({
      fetch: hono.fetch,
      port: 0,
      hostname: "127.0.0.1",
      websocket: { server: new WebSocketServer({ noServer: true }) },
    });
    await once(server, "listening");
    base = `127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterEach(async () => {
    [sandboxRelaySessionManager.pingIntervalMs, sandboxRelaySessionManager.livenessTimeoutMs] =
      saved;
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  /** A real `ws` client in a child process (the I/O guard blocks in-process TCP). */
  async function connect(autoPong: boolean) {
    const peer = await upgradeBrowserTerminal({
      base,
      path: "/ws/sandbox-host",
      protocols: [SANDBOX_RELAY_SUBPROTOCOL],
      origin: null,
      autoPong,
    });
    if (peer.kind !== "open") throw new Error("expected an open relay socket");
    return peer;
  }

  it("a peer whose pongs arrive stays connected past the silence bound", async () => {
    const peer = await connect(true);
    let closedEarly = false;
    void peer.closed.then(() => {
      closedEarly = true;
    });
    await new Promise((resolve) => setTimeout(resolve, 900));
    expect(closedEarly).toBe(false);
    peer.close();
    await peer.closed;
  });

  it("a half-open peer (pings never answered) is removed with 1001", async () => {
    const peer = await connect(false);
    expect(await peer.closed).toMatchObject({ code: 1001, reason: "session_removed" });
  });
});
