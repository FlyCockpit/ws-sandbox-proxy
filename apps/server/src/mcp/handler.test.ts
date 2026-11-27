import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import {
  CLIENT_CAPABILITIES_META_KEY,
  CLIENT_INFO_META_KEY,
  PROTOCOL_VERSION_META_KEY,
} from "@modelcontextprotocol/server";
import { ORPCError } from "@orpc/server";
import type { ServicePrincipal } from "@wssp/api/lib/sdk-key-access";
import { beforeEach, expect, it, vi } from "vitest";

const dispatchMock = vi.hoisted(() => vi.fn(async () => ({ state: "running" })));
vi.mock("./tool-dispatch.js", () => ({
  dispatchMcpTool: dispatchMock,
}));
vi.mock("../mcp-rate-limit.js", () => ({
  consumeMcpCreateQuota: vi.fn(),
  consumeMcpHostCommandQuota: vi.fn(),
}));
vi.mock("@wssp/env/server", () => ({ env: { CAPACITY_RETRY_AFTER_SECONDS: 5 } }));

import { createMcpTransport, MCP_TRANSPORT_OPTIONS } from "./handler";

beforeEach(() => {
  dispatchMock.mockReset().mockResolvedValue({ state: "running" });
});

const p: ServicePrincipal = {
  kind: "sdkKey",
  credentialKind: "AGENT_TOKEN",
  keyId: "key",
  ownerId: "owner",
  expiresAt: null,
  resourceMode: "ALL_OWNED",
  ownSandboxesOnly: true,
  scopes: new Set(["hosts:execute"]),
  allowedHostIds: "allOwned",
  allowedRevisionIds: "allOwned",
  allowedPoolIds: "allUsable",
};
function request(method: string, params: Record<string, unknown> = {}) {
  return new Request("https://public.example/mcp", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "mcp-method": method,
      "mcp-protocol-version": "2026-07-28",
      ...(typeof params.name === "string" ? { "mcp-name": params.name } : {}),
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method,
      params: {
        ...params,
        _meta: {
          [PROTOCOL_VERSION_META_KEY]: "2026-07-28",
          [CLIENT_INFO_META_KEY]: { name: "test", version: "1" },
          [CLIENT_CAPABILITIES_META_KEY]: {},
        },
      },
    }),
  });
}
function legacyRequest(
  body: unknown,
  headers: Record<string, string> = { "mcp-protocol-version": "2025-06-18" },
) {
  return new Request("https://public.example/mcp", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...headers,
    },
    body: JSON.stringify(body),
  });
}
async function readSseJsonRpc(response: Response): Promise<unknown[]> {
  const text = await response.text();
  return text.split(/\r?\n\r?\n/).flatMap((block) =>
    block
      .split(/\r?\n/)
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trim())
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as unknown),
  );
}
const authInfo = {
  token: "synthetic",
  clientId: "key",
  scopes: [...p.scopes],
  extra: { principal: p },
};
it("uses stateless modern JSON plus legacy stateless transport and lists only complete scope matches", async () => {
  expect(MCP_TRANSPORT_OPTIONS).toEqual({
    legacy: "stateless",
    responseMode: "json",
    maxSubscriptions: 0,
    maxRequestBodySize: 1_048_576,
    keepAliveMs: 15_000,
  });
  const transport = createMcpTransport();
  try {
    const response = await transport.fetch(request("tools/list"), { authInfo });
    expect(response.status).toBe(200);
    expect(response.headers.get("mcp-session-id")).toBeNull();
    const json = (await response.json()) as {
      result: { tools: { name: string; annotations: Record<string, boolean> }[] };
    };
    expect(json.result.tools.map((tool: { name: string }) => tool.name)).toEqual([
      "host_command_run",
      "host_command_get",
      "host_command_cancel",
      "host_command_queue",
    ]);
    expect(
      json.result.tools.find((tool) => tool.name === "host_command_run")?.annotations,
    ).toMatchObject({ readOnlyHint: false, destructiveHint: true, idempotentHint: false });
  } finally {
    await transport.close();
  }
});
it("makes hidden and unknown calls indistinguishable on the actual transport", async () => {
  const transport = createMcpTransport();
  try {
    for (const name of ["sandbox_destroy", "nonexistent"]) {
      const response = await transport.fetch(request("tools/call", { name, arguments: {} }), {
        authInfo,
      });
      expect(await response.json()).toMatchObject({
        error: { code: -32602, message: `Tool ${name} not found` },
      });
    }
  } finally {
    await transport.close();
  }
});
it("returns a retry key through actual tool invocation", async () => {
  const transport = createMcpTransport();
  try {
    const response = await transport.fetch(
      request("tools/call", {
        name: "host_command_run",
        arguments: { hostId: "host", script: "true" },
      }),
      { authInfo },
    );
    expect(await response.json()).toMatchObject({
      result: {
        structuredContent: { idempotencyKey: expect.any(String), result: { state: "running" } },
      },
    });
  } finally {
    await transport.close();
  }
});

it("serves stateless 2025-06-18 initialize, initialized notification, tools/list, and tools/call with identical scope enforcement and redaction", async () => {
  const transport = createMcpTransport();
  try {
    const init = await transport.fetch(
      legacyRequest(
        {
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2025-06-18",
            capabilities: {},
            clientInfo: { name: "codex-mcp-client", version: "0.172.0" },
          },
        },
        {},
      ),
      { authInfo },
    );
    expect(init.status).toBe(200);
    expect(init.headers.get("content-type")).toContain("text/event-stream");
    expect(init.headers.get("mcp-session-id")).toBeNull();
    expect(await readSseJsonRpc(init)).toEqual([
      expect.objectContaining({
        jsonrpc: "2.0",
        id: 1,
        result: expect.objectContaining({
          protocolVersion: "2025-06-18",
          serverInfo: { name: "wssp", version: "1.0.0" },
        }),
      }),
    ]);

    const initialized = await transport.fetch(
      legacyRequest({ jsonrpc: "2.0", method: "notifications/initialized" }),
      { authInfo },
    );
    expect(initialized.status).toBe(202);
    expect(initialized.headers.get("mcp-session-id")).toBeNull();

    const listed = await transport.fetch(
      legacyRequest({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }),
      { authInfo },
    );
    expect(listed.status).toBe(200);
    const [listMsg] = (await readSseJsonRpc(listed)) as [{ result: { tools: { name: string }[] } }];
    expect(listMsg.result.tools.map((tool) => tool.name)).toEqual([
      "host_command_run",
      "host_command_get",
      "host_command_cancel",
      "host_command_queue",
    ]);

    const called = await transport.fetch(
      legacyRequest({
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: {
          name: "host_command_run",
          arguments: { hostId: "host", script: "true", idempotencyKey: "legacy-retry" },
        },
      }),
      { authInfo },
    );
    expect(called.status).toBe(200);
    expect(await readSseJsonRpc(called)).toEqual([
      expect.objectContaining({
        id: 3,
        result: expect.objectContaining({
          structuredContent: { idempotencyKey: "legacy-retry", result: { state: "running" } },
        }),
      }),
    ]);
    expect(dispatchMock).toHaveBeenCalledWith(
      p,
      "host_command_run",
      expect.objectContaining({ hostId: "host", script: "true", idempotencyKey: "legacy-retry" }),
      expect.any(AbortSignal),
    );

    // Hidden vs unknown tools remain indistinguishable on the legacy leg.
    dispatchMock.mockClear();
    for (const name of ["sandbox_destroy", "nonexistent"]) {
      const hidden = await transport.fetch(
        legacyRequest({
          jsonrpc: "2.0",
          id: 4,
          method: "tools/call",
          params: { name, arguments: {} },
        }),
        { authInfo },
      );
      expect(await readSseJsonRpc(hidden)).toEqual([
        expect.objectContaining({
          id: 4,
          error: expect.objectContaining({ code: -32602, message: `Tool ${name} not found` }),
        }),
      ]);
    }
    expect(dispatchMock).not.toHaveBeenCalled();

    // Error redaction holds identically on legacy tool calls.
    dispatchMock.mockRejectedValueOnce(
      new ORPCError("INTERNAL_SERVER_ERROR", {
        message: "private-sql-leak",
        data: { reason: "internal_secret_reason" },
      }),
    );
    const failed = await transport.fetch(
      legacyRequest({
        jsonrpc: "2.0",
        id: 5,
        method: "tools/call",
        params: {
          name: "host_command_run",
          arguments: { hostId: "host", script: "true", idempotencyKey: "legacy-err" },
        },
      }),
      { authInfo },
    );
    const failedText = await failed.text();
    expect(failedText).not.toMatch(/private-sql-leak|internal_secret_reason/);
    expect(failedText).toContain("INTERNAL_SERVER_ERROR");
  } finally {
    await transport.close();
  }
});

it("rejects JSON-RPC batch arrays, oversized bodies, API principals, and non-POST methods", async () => {
  const transport = createMcpTransport();
  try {
    for (const body of [
      [],
      [
        { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} },
        { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
      ],
    ]) {
      const response = await transport.fetch(legacyRequest(body), { authInfo });
      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({
        jsonrpc: "2.0",
        id: null,
        error: { code: -32600, message: "Invalid Request: JSON-RPC batching is not supported" },
      });
    }

    const preParsedBatch = await transport.fetch(
      new Request("https://public.example/mcp", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
        },
      }),
      { authInfo, parsedBody: [{ jsonrpc: "2.0", id: 1, method: "tools/list" }] },
    );
    expect(preParsedBatch.status).toBe(400);
    expect(await preParsedBatch.json()).toMatchObject({ error: { code: -32600 } });

    // Malformed UTF-8 bytes in a JSON-RPC batch array must be rejected instead of
    // falling through to the SDK's non-fatal TextDecoder (which would replace 0xFF and run the batch).
    const prefix = Buffer.from(
      '[{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"x":"',
      "utf8",
    );
    const suffix = Buffer.from(
      '"}}},{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}]',
      "utf8",
    );
    const malformedBatchBytes = new Uint8Array(prefix.length + 1 + suffix.length);
    malformedBatchBytes.set(prefix, 0);
    malformedBatchBytes[prefix.length] = 0xff;
    malformedBatchBytes.set(suffix, prefix.length + 1);
    const malformedBatch = await transport.fetch(
      new Request("https://public.example/mcp", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          "mcp-protocol-version": "2025-06-18",
        },
        body: malformedBatchBytes,
      }),
      { authInfo },
    );
    expect(malformedBatch.status).toBe(400);
    expect(await malformedBatch.json()).toEqual({
      jsonrpc: "2.0",
      id: null,
      error: { code: -32700, message: "Parse error: Invalid UTF-8" },
    });

    const oversized = await transport.fetch(
      new Request("https://public.example/mcp", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
        },
        body: `"${"x".repeat(1_048_577)}"`,
      }),
      { authInfo },
    );
    expect(oversized.status).toBe(413);

    for (const method of ["GET", "DELETE"]) {
      const methodRes = await transport.fetch(
        new Request("https://public.example/mcp", { method }),
        { authInfo },
      );
      expect(methodRes.status).toBe(405);
      expect(methodRes.headers.get("allow")).toBe("POST");
    }

    const apiKeyRes = await transport.fetch(
      legacyRequest({ jsonrpc: "2.0", id: 9, method: "tools/list", params: {} }),
      {
        authInfo: {
          ...authInfo,
          extra: { principal: { ...p, credentialKind: "API" } },
        },
      },
    );
    expect(apiKeyRes.status).toBe(500);
    expect(await apiKeyRes.json()).toEqual({
      jsonrpc: "2.0",
      id: 9,
      error: { code: -32603, message: "Internal server error" },
    });
    expect(dispatchMock).not.toHaveBeenCalled();
  } finally {
    await transport.close();
  }
});

it("emits SSE keep-alive frames during long legacy tool calls", async () => {
  const transport = createMcpTransport({ keepAliveMs: 15 });
  dispatchMock.mockImplementationOnce(
    () =>
      new Promise((resolve) => {
        setTimeout(() => resolve({ state: "done" }), 50);
      }),
  );
  try {
    const response = await transport.fetch(
      legacyRequest({
        jsonrpc: "2.0",
        id: 10,
        method: "tools/call",
        params: { name: "host_command_run", arguments: { hostId: "host", script: "true" } },
      }),
      { authInfo },
    );
    expect(response.status).toBe(200);
    const text = await response.text();
    expect(text).toContain(": keepalive\n\n");
    expect(text).toContain('"state":"done"');
  } finally {
    await transport.close();
  }
});

it("interoperates with the pinned MCP 2.4 client without an HTTP listener", async () => {
  const transport = createMcpTransport();
  const client = new Client(
    { name: "wssp-e2e", version: "1" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } },
  );
  try {
    await client.connect(
      new StreamableHTTPClientTransport(new URL("https://public.example/mcp"), {
        fetch: (url, init) => transport.fetch(new Request(url, init), { authInfo }),
      }),
    );
    expect((await client.listTools()).tools.map((tool) => tool.name)).toContain("host_command_run");
    expect(
      await client.callTool({
        name: "host_command_run",
        arguments: { hostId: "host", script: "true", idempotencyKey: "sdk-client-retry" },
      }),
    ).toMatchObject({
      structuredContent: { idempotencyKey: "sdk-client-retry", result: { state: "running" } },
    });
  } finally {
    await client.close();
    await transport.close();
  }
});
