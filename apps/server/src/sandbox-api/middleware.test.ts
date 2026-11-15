vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import type { ServicePrincipal } from "@wssp/api/lib/sdk-key-access";
import { Hono } from "hono";
import { describe, expect, it, vi } from "vitest";
import type { SandboxApiEnv } from "./auth.js";
import { sdkErrorResponse } from "./errors.js";
import { createJsonBodyLimit, createSandboxApi, SDK_JSON_MAX_BYTES } from "./middleware.js";

vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_SECRET: "service-principal-test",
    RATE_LIMIT_SDK_IP_POINTS: 100,
    RATE_LIMIT_SDK_KEY_POINTS: 100,
    RATE_LIMIT_SDK_OWNER_POINTS: 100,
  },
}));
vi.mock("../client-ip.js", () => ({ resolveClientIp: () => "127.0.0.1" }));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/api/lib/procedure-budget", () => ({ createProcedureBudget: () => async () => {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/db", async () => ({
  default: await (await import("@wssp/api/test/mock-prisma")).createMockPrisma(),
}));

function testPrincipal(ownerId: string): ServicePrincipal {
  return {
    kind: "sdkKey",
    credentialKind: "API" as const,
    ownSandboxesOnly: false,
    expiresAt: null,
    keyId: "key-1",
    ownerId,
    resourceMode: "ALL_OWNED",
    scopes: new Set(["sandboxes:read"]),
    allowedHostIds: "allOwned",
    allowedRevisionIds: "allOwned",
    allowedPoolIds: "allUsable",
  };
}

/** A Hono app carrying only the JSON body admission under test. */
function jsonBodyApp(options: { deadlineMs: number; globalReaders: number; ownerReaders: number }) {
  const app = new Hono<SandboxApiEnv>();
  app.onError((error, c) => sdkErrorResponse(c, error));
  app.use("*", async (c, next) => {
    c.set("principal", testPrincipal(c.req.header("x-owner") ?? "owner-1"));
    await next();
  });
  app.use("*", createJsonBodyLimit(options));
  app.post("/echo", async (c) => c.json({ ok: true, body: await c.req.text() }));
  return app;
}

function streamingRequest(parts: {
  chunks: Uint8Array[];
  gates?: Array<Promise<void>>;
  neverDone?: boolean;
  owner?: string;
  contentLength?: number;
}) {
  let index = 0;
  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (index >= parts.chunks.length) {
        if (parts.neverDone) return; // never enqueues, never closes: a stalled sender
        controller.close();
        return;
      }
      const chunk = parts.chunks[index];
      if (!chunk) return;
      const gate = parts.gates?.[index];
      controller.enqueue(chunk);
      index++;
      await gate; // optional: hold the body open after this chunk
    },
  });
  return new Request("http://test/echo", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-owner": parts.owner ?? "owner-1",
      ...(parts.contentLength === undefined
        ? {}
        : { "content-length": String(parts.contentLength) }),
    },
    body: stream,
    ...({ duplex: "half" } as RequestInit & { duplex: "half" }),
  });
}

describe("createJsonBodyLimit (C22)", () => {
  it("buffers a complete JSON body and passes it downstream", async () => {
    const app = jsonBodyApp({ deadlineMs: 5_000, globalReaders: 2, ownerReaders: 2 });
    const response = await app.request(
      streamingRequest({ chunks: [new TextEncoder().encode('{"a":1}')] }),
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true, body: '{"a":1}' });
  });

  it("fails a body that stalls past the deadline and releases its slot", async () => {
    const app = jsonBodyApp({ deadlineMs: 25, globalReaders: 1, ownerReaders: 1 });
    const stalled = await app.request(
      streamingRequest({ chunks: [new TextEncoder().encode('{"a":')], neverDone: true }),
    );
    expect(stalled.status).toBe(400);
    // The slot was released: a healthy body is admitted immediately after.
    const healthy = await app.request(
      streamingRequest({ chunks: [new TextEncoder().encode('{"a":1}')] }),
    );
    expect(healthy.status).toBe(200);
  });

  it("refuses a second concurrent reader once the global budget is spent", async () => {
    const app = jsonBodyApp({ deadlineMs: 5_000, globalReaders: 1, ownerReaders: 5 });
    let releaseGate!: () => void;
    const gate = new Promise<void>((resolve) => {
      releaseGate = resolve;
    });
    const first = app.request(
      streamingRequest({ chunks: [new TextEncoder().encode('{"a":1}')], gates: [gate] }),
    );
    await vi.waitFor(() => expect(releaseGate).toBeDefined());
    const second = await app.request(
      streamingRequest({ chunks: [new TextEncoder().encode('{"b":2}')] }),
    );
    expect(second.status).toBe(429);
    releaseGate();
    expect((await first).status).toBe(200);
  });

  it("refuses the per-owner overflow while another owner is still admitted", async () => {
    const app = jsonBodyApp({ deadlineMs: 5_000, globalReaders: 5, ownerReaders: 1 });
    let releaseGate!: () => void;
    const gate = new Promise<void>((resolve) => {
      releaseGate = resolve;
    });
    const first = app.request(
      streamingRequest({
        chunks: [new TextEncoder().encode('{"a":1}')],
        gates: [gate],
        owner: "owner-1",
      }),
    );
    await vi.waitFor(() => expect(releaseGate).toBeDefined());
    // Same owner overflows its own slot while the global budget still has room.
    const sameOwner = await app.request(
      streamingRequest({ chunks: [new TextEncoder().encode('{"b":2}')], owner: "owner-1" }),
    );
    expect(sameOwner.status).toBe(429);
    // Another owner is unaffected by owner-1's occupied slot.
    const otherOwner = await app.request(
      streamingRequest({ chunks: [new TextEncoder().encode('{"c":3}')], owner: "owner-2" }),
    );
    expect(otherOwner.status).toBe(200);
    releaseGate();
    expect((await first).status).toBe(200);
  });

  it("sizes the buffer to a declared length and rejects a body past it", async () => {
    const app = jsonBodyApp({ deadlineMs: 5_000, globalReaders: 2, ownerReaders: 2 });
    const encode = (text: string) => new TextEncoder().encode(text);
    const exact = await app.request(
      streamingRequest({ chunks: [encode('{"a":'), encode("1}")], contentLength: 7 }),
    );
    expect(exact.status).toBe(200);
    expect(await exact.json()).toEqual({ ok: true, body: '{"a":1}' });
    const over = await app.request(
      streamingRequest({ chunks: [encode('{"a":'), encode("12}")], contentLength: 7 }),
    );
    expect(over.status).toBe(413);
    // The slot was released after the rejection.
    const after = await app.request(streamingRequest({ chunks: [encode('{"a":1}')] }));
    expect(after.status).toBe(200);
  });

  it("keeps the maximum buffer without a declared length", async () => {
    const app = jsonBodyApp({ deadlineMs: 5_000, globalReaders: 2, ownerReaders: 2 });
    const pad = new Uint8Array(SDK_JSON_MAX_BYTES - 8).fill(0x20);
    const fits = await app.request(
      streamingRequest({ chunks: [new TextEncoder().encode('{"a":1}'), pad] }),
    );
    expect(fits.status).toBe(200);
    const tooLarge = await app.request(
      streamingRequest({ chunks: [new TextEncoder().encode('{"a":1}'), pad, pad] }),
    );
    expect(tooLarge.status).toBe(413);
  });
});

it("rejects decoded duplicate public map keys before native JSON decode", async () => {
  const app = jsonBodyApp({ deadlineMs: 5_000, globalReaders: 2, ownerReaders: 2 });
  for (const [raw, code] of [
    ['{"metadata":{"team":"first","team":"second"}}', "sandbox.metadata_invalid"],
    ['{"envs":{"A":"first","A":"second"}}', "BAD_REQUEST"],
    ['{"envs":{"A":"first","\\u0041":"second"}}', "BAD_REQUEST"],
  ] as const) {
    const response = await app.request(
      streamingRequest({ chunks: [new TextEncoder().encode(raw)] }),
    );
    expect(response.status).toBe(400);
    const text = await response.text();
    expect(text).toContain(code);
    expect(text).not.toContain("first");
  }
});

it.each(["/v1/sandboxes/sbx-123", "/v1/operations/op-456"])(
  "mounted SDK access logs preserve the full path %s without query strings",
  async (path) => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      const app = new Hono();
      app.route("/v1", createSandboxApi());
      const response = await app.request(`${path}?trace=private-query-value`);
      expect(response.status).toBe(401);
      expect(log).toHaveBeenCalledTimes(2);
      expect(log.mock.calls[0]?.[0]).toMatch(new RegExp(`\\] <-- GET ${path}$`));
      expect(log.mock.calls[1]?.[0]).toContain(`--> GET ${path} 401`);
      expect(JSON.stringify(log.mock.calls)).not.toContain("private-query-value");
      expect(JSON.stringify(log.mock.calls)).not.toContain("?trace");
    } finally {
      log.mockRestore();
    }
  },
);
