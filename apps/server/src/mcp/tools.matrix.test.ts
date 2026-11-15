import { ORPCError } from "@orpc/server";
import type { ServicePrincipal } from "@wssp/api/lib/sdk-key-access";
import { SERVICE_SCOPES } from "@wssp/api/lib/service-scopes";
import { MCP_TOOLS, visibleMcpTools } from "@wssp/api/mcp/tool-contracts";
import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: await (await import("@wssp/api/test/mock-prisma")).createMockPrisma(),
}));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeSandboxWriteBudget: async () => {},
  consumeCreateConnectBudget: async () => {},
}));
vi.mock("./tool-dispatch.js", () => ({ dispatchMcpTool: vi.fn() }));
vi.mock("../mcp-rate-limit.js", () => ({
  consumeMcpCreateQuota: vi.fn(),
  consumeMcpHostCommandQuota: vi.fn(),
}));
vi.mock("@wssp/env/server", () => ({
  env: { CAPACITY_RETRY_AFTER_SECONDS: 5, BETTER_AUTH_SECRET: "tool-matrix-fixture" },
}));

import { callMcpTool } from "./tools";

const { default: prisma } = await import("@wssp/db");
const db = prisma as import("@wssp/api/test/mock-prisma").MockPrisma;
const { authorizeServiceIntent } = await import("@wssp/api/lib/sdk-key-access");

function principal(scopes: readonly string[]): ServicePrincipal {
  return {
    kind: "sdkKey",
    credentialKind: "AGENT_TOKEN",
    keyId: "key",
    ownerId: "owner",
    expiresAt: null,
    resourceMode: "ALL_OWNED",
    ownSandboxesOnly: true,
    scopes: new Set(SERVICE_SCOPES.filter((s) => scopes.includes(s))),
    allowedHostIds: "allOwned",
    allowedRevisionIds: "allOwned",
    allowedPoolIds: "allUsable",
  };
}
const input = {
  id: "sandbox",
  hostId: "host",
  commandId: "abcdefghijklmnopqrstuv",
  operationId: "operation",
  sandboxHostId: "host",
  template: "revision/template",
  script: "true",
  path: "/workspace/test",
  content: "hello",
  contentBase64: "aGk=",
  data: "aGk=",
  eof: true,
  command: "true",
  reason: "review",
  edits: [{ oldText: "hello", newText: "world" }],
  waitMs: 0,
  idempotencyKey: "matrix-retry",
};
describe.each(MCP_TOOLS)("$name authorization matrix", (tool) => {
  it("is listed with exactly its scopes and reaches the service gate", async () => {
    const p = principal(tool.scopes);
    expect(visibleMcpTools(p.scopes).map((t) => t.name)).toContain(tool.name);
    db.appSetting.findMany.mockResolvedValue([]);
    db.sdkKey.findUnique.mockResolvedValue({
      id: "key",
      userId: "owner",
      kind: "AGENT_TOKEN",
      ownSandboxesOnly: true,
      scopes: [...tool.scopes],
      resourceMode: "ALL_OWNED",
      poolMode: "ALL_USABLE",
      expiresAt: new Date(Date.now() + 86400000),
      revokedAt: null,
      HostAllowlist: [],
      RevisionAllowlist: [],
      PoolAllowlist: [],
      User: {
        banned: false,
        banExpires: null,
        deletionRequestedAt: null,
        twoFactorEnabled: true,
        role: "user",
        createdAt: new Date(0),
      },
    } as never);
    const gate = vi.fn(async (principal: ServicePrincipal) =>
      authorizeServiceIntent(principal, tool.actions[0]!),
    );
    const dispatch = vi.fn(async (principal: ServicePrincipal) => {
      // Mock service work after the actual native authorization boundary.
      await gate(principal);
      throw new ORPCError("FORBIDDEN");
    });
    const args = Object.fromEntries(
      Object.keys(tool.input.shape)
        .filter((key) => key in input)
        .map((key) => [key, input[key as keyof typeof input]]),
    );
    expect(tool.input.safeParse(args)).toMatchObject({ success: true });
    const response = await callMcpTool(p, tool.name, args, { dispatch });
    expect(dispatch).toHaveBeenCalledOnce();
    expect(gate).toHaveResolvedWith({});
    expect(dispatch.mock.calls[0]?.[0]).toBe(p);
    expect(response).toMatchObject({
      isError: true,
      structuredContent: { error: { code: "FORBIDDEN" } },
    });
  });
  it.each([...tool.scopes])(
    "removing %s hides it and returns exactly unknown-tool behavior",
    async (missing) => {
      const p = principal(tool.scopes.filter((scope) => scope !== missing));
      const dispatch = vi.fn();
      expect(visibleMcpTools(p.scopes).map((t) => t.name)).not.toContain(tool.name);
      const result = await callMcpTool(p, tool.name, input, { dispatch });
      const unknown = await callMcpTool(p, "unknown_tool", input, { dispatch });
      expect(result).toEqual({
        ...unknown,
        content: [{ type: "text", text: `Tool ${tool.name} not found` }],
      });
      expect(dispatch).not.toHaveBeenCalled();
    },
  );
});

it("lists exact scope matches and hides every missing-scope tool on the real JSON-RPC transport", async () => {
  const { createMcpTransport } = await import("./handler");
  const { CLIENT_CAPABILITIES_META_KEY, CLIENT_INFO_META_KEY, PROTOCOL_VERSION_META_KEY } =
    await import("@modelcontextprotocol/server");
  const transport = createMcpTransport();
  try {
    for (const tool of MCP_TOOLS)
      for (const missing of [null, ...tool.scopes]) {
        const p = principal(tool.scopes.filter((scope) => scope !== missing));
        const authInfo = {
          token: "fixture",
          clientId: "key",
          scopes: [...p.scopes],
          extra: { principal: p },
        };
        const request = (method: string, params: Record<string, unknown> = {}) =>
          new Request("https://example.test/mcp", {
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
                  [CLIENT_INFO_META_KEY]: { name: "matrix", version: "1" },
                  [CLIENT_CAPABILITIES_META_KEY]: {},
                },
              },
            }),
          });
        const listed = await transport.fetch(request("tools/list"), { authInfo });
        const body = (await listed.json()) as { result: { tools: { name: string }[] } };
        expect(body.result.tools.map((t) => t.name).sort()).toEqual(
          visibleMcpTools(p.scopes)
            .map((t) => t.name)
            .sort(),
        );
        expect(body.result.tools.some((t) => t.name === tool.name)).toBe(missing === null);
        if (missing !== null) {
          const hidden = await transport.fetch(
            request("tools/call", { name: tool.name, arguments: {} }),
            { authInfo },
          );
          const unknown = await transport.fetch(
            request("tools/call", { name: "unknown", arguments: {} }),
            { authInfo },
          );
          const a = (await hidden.json()) as { error: { message: string } },
            b = (await unknown.json()) as { error: { message: string } };
          expect(a).toEqual({
            ...b,
            error: { ...b.error, message: `Tool ${tool.name} not found` },
          });
        }
      }
  } finally {
    await transport.close();
  }
});
