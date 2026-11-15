import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import {
  CLIENT_CAPABILITIES_META_KEY,
  CLIENT_INFO_META_KEY,
  PROTOCOL_VERSION_META_KEY,
} from "@modelcontextprotocol/server";
import type { ServicePrincipal } from "@wssp/api/lib/sdk-key-access";
import { expect, it, vi } from "vitest";

vi.mock("./tool-dispatch.js", () => ({
  dispatchMcpTool: vi.fn(async () => ({ state: "running" })),
}));
vi.mock("../mcp-rate-limit.js", () => ({
  consumeMcpCreateQuota: vi.fn(),
  consumeMcpHostCommandQuota: vi.fn(),
}));
vi.mock("@wssp/env/server", () => ({ env: { CAPACITY_RETRY_AFTER_SECONDS: 5 } }));

import { createMcpTransport, MCP_TRANSPORT_OPTIONS } from "./handler";

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
const authInfo = {
  token: "synthetic",
  clientId: "key",
  scopes: [...p.scopes],
  extra: { principal: p },
};
it("uses stateless modern JSON transport and lists only complete scope matches", async () => {
  expect(MCP_TRANSPORT_OPTIONS).toEqual({
    legacy: "reject",
    responseMode: "json",
    maxSubscriptions: 0,
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
