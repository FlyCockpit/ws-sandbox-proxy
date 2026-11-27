import { createHash } from "node:crypto";
import type { ServicePrincipal } from "@wssp/api/lib/sdk-key-access";
import { beforeEach, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  create: vi.fn(),
  write: vi.fn(),
  commit: vi.fn(),
  listHosts: vi.fn(),
  runCommand: vi.fn(),
  getCommandOutput: vi.fn(),
  getResult: vi.fn(),
  ports: vi.fn(),
}));
vi.mock("../sandbox-transfers/runtime.js", () => ({ transferStore: () => mocks }));
vi.mock("../sandbox-transfers/http-admission.js", () => ({
  admitted: (_principal: unknown, work: () => Promise<unknown>) => work(),
}));
vi.mock("@wssp/api/sandbox/sdk-reads", () => ({
  sdkGetSandbox: vi.fn(),
  sdkListSandboxes: vi.fn(),
  sdkListHosts: mocks.listHosts,
  toHostDto: vi.fn(),
  sdkGetOperation: vi.fn(),
}));
vi.mock("@wssp/api/sandbox/sdk-mutations", () => ({
  writeStdinReceipt: vi.fn(),
  cancelOperationReceipt: vi.fn(),
  mutationOperationReceipt: vi.fn(),
}));
vi.mock("@wssp/api/sandbox/operation-results", () => ({ getOperationResult: mocks.getResult }));
vi.mock("@wssp/api/sandbox/services/sandboxes", () => ({
  createSandbox: vi.fn(),
  stopSandbox: vi.fn(),
  killSandbox: vi.fn(),
  runCommand: mocks.runCommand,
  getCommandOutput: mocks.getCommandOutput,
  readFile: vi.fn(),
  listDir: vi.fn(),
}));
vi.mock("@wssp/api/sandbox/services/hosts", () => ({ getHost: vi.fn() }));
vi.mock("@wssp/api/sandbox/tunnels/service", () => ({ updateSandboxTunnelPorts: mocks.ports }));
vi.mock("@wssp/api/sandbox/services/host-commands", () => ({
  runHostCommand: vi.fn(),
  getHostCommand: vi.fn(),
  cancelHostCommand: vi.fn(),
}));
vi.mock("@wssp/api/sandbox/services/host-queued", () => ({ queueHostCommand: vi.fn() }));
vi.mock("@wssp/api/sandbox/services/host-files", () => ({
  readHostFile: vi.fn(),
  listHostDir: vi.fn(),
  writeHostFile: vi.fn(),
  editHostFile: vi.fn(),
}));
vi.mock("@wssp/api/lib/sdk-key-access", () => ({
  AgentTokenPolicyBlockedError: class AgentTokenPolicyBlockedError extends Error {},
  authenticateAgentTokenSecret: vi.fn(),
  principalForMcpGrant: vi.fn(),
}));
vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_URL: "https://public.example", CAPACITY_RETRY_AFTER_SECONDS: 5 },
}));
vi.mock("../mcp-rate-limit.js", () => ({
  consumeMcpCredentialQuota: vi.fn(),
  consumeMcpCreateQuota: vi.fn(),
  consumeMcpHostCommandQuota: vi.fn(),
}));

import { createMcpAuthenticator } from "./auth";
import { createMcpTransport } from "./handler";
import { dispatchMcpTool } from "./tool-dispatch";

const p: ServicePrincipal = {
  kind: "sdkKey",
  credentialKind: "AGENT_TOKEN",
  keyId: "key",
  ownerId: "owner",
  expiresAt: null,
  resourceMode: "ALL_OWNED",
  ownSandboxesOnly: true,
  scopes: new Set([
    "hosts:read",
    "files:write",
    "commands:execute",
    "commands:read",
    "operations:read",
  ]),
  allowedHostIds: "allOwned",
  allowedRevisionIds: "allOwned",
  allowedPoolIds: "allUsable",
};
beforeEach(() => {
  vi.clearAllMocks();
  mocks.create.mockResolvedValue({ id: "transfer", receivedBytes: 0 });
  mocks.write.mockResolvedValue({});
  mocks.commit.mockResolvedValue({ operationId: "operation" });
});
it("uses the native upload store with separate reservation and commit keys and recovers a completed upload", async () => {
  const input = {
    id: "sandbox",
    path: "/workspace/file",
    content: "hello",
    idempotencyKey: "stable",
  };
  expect(await dispatchMcpTool(p, "file_write", input)).toEqual({ operationId: "operation" });
  expect(mocks.create).toHaveBeenCalledWith(
    p,
    expect.objectContaining({ idempotencyKey: "stable", totalBytes: 5, direction: "UPLOAD" }),
  );
  const commitKey = `mcp:${createHash("sha256").update("mcp-file-write-commit\0stable").digest("hex")}`;
  expect(mocks.commit).toHaveBeenCalledWith(
    p,
    "transfer",
    commitKey,
    createHash("sha256").update("hello").digest("hex"),
  );
  mocks.create.mockResolvedValue({ id: "transfer", receivedBytes: 5 });
  mocks.write.mockClear();
  await dispatchMcpTool(p, "file_write", input);
  expect(mocks.write).not.toHaveBeenCalled();
  expect(mocks.commit.mock.calls[1]![2]).toBe(commitKey);
});
it("filters host_list to owned hosts and retains native pagination", async () => {
  mocks.listHosts.mockResolvedValue({
    items: [
      { id: "own", agentAccess: { owned: true, hostCommands: true, hostFiles: false } },
      { id: "shared", agentAccess: { owned: false } },
    ],
    nextCursor: "cursor",
  });
  expect(await dispatchMcpTool(p, "host_list", { limit: 20 })).toEqual({
    items: [{ id: "own", agentAccess: { owned: true, hostCommands: true, hostFiles: false } }],
    nextCursor: "cursor",
  });
  expect(mocks.listHosts).toHaveBeenCalledWith(p, { limit: 20 });
});

it("runs the legacy auth matrix through real tool dispatch and filters shared hosts", async () => {
  const hostPage = {
    items: [
      { id: "own", agentAccess: { owned: true, hostCommands: true, hostFiles: false } },
      { id: "shared-private", agentAccess: { owned: false } },
    ],
    nextCursor: null,
  };
  mocks.listHosts.mockResolvedValue(hostPage);
  const transport = createMcpTransport({ keepAliveMs: 0 });
  const lookup = vi.fn(async (token: string): Promise<ServicePrincipal | null> => {
    if (token === "wssp_agent_valid") return p;
    if (token === "wssp_agent_no_grant") return { ...p, scopes: new Set() };
    return null;
  });
  const quota = vi.fn(async () => {});
  const authenticate = createMcpAuthenticator({
    authInstance: {} as Parameters<typeof createMcpAuthenticator>[0]["authInstance"],
    transport,
    authenticateAgent: lookup,
    quota,
  });
  const requests = [
    {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "legacy-security-test", version: "1" },
      },
    },
    { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
    {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "host_list", arguments: { limit: 20 } },
    },
  ];
  const send = async (body: unknown, token?: string) => {
    const response = await authenticate(
      new Request("https://public.example/mcp", {
        method: "POST",
        headers: {
          host: "public.example",
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify(body),
      }),
    );
    return { response, text: await response.text() };
  };
  try {
    for (const token of [undefined, "wssp_agent_revoked"]) {
      mocks.listHosts.mockClear();
      quota.mockClear();
      for (const body of requests) {
        const { response, text } = await send(body, token);
        expect(response.status).toBe(401);
        expect(text).not.toMatch(/shared-private|"own"/);
      }
      expect(mocks.listHosts).not.toHaveBeenCalled();
      expect(quota).not.toHaveBeenCalled();
    }

    const noGrantInit = await send(requests[0], "wssp_agent_no_grant");
    expect(noGrantInit.response.status).toBe(200);
    expect(noGrantInit.text).toContain('"protocolVersion":"2025-06-18"');
    const noGrantList = await send(requests[1], "wssp_agent_no_grant");
    expect(noGrantList.response.status).toBe(200);
    expect(noGrantList.text).not.toContain('"name":"host_list"');
    const noGrantCall = await send(requests[2], "wssp_agent_no_grant");
    expect(noGrantCall.text).toContain("Tool host_list not found");
    expect(mocks.listHosts).not.toHaveBeenCalled();

    const init = await send(requests[0], "wssp_agent_valid");
    expect(init.response.status).toBe(200);
    expect(init.text).toContain('"protocolVersion":"2025-06-18"');
    const list = await send(requests[1], "wssp_agent_valid");
    expect(list.text).toContain('"name":"host_list"');
    const call = await send(requests[2], "wssp_agent_valid");
    expect(call.response.status).toBe(200);
    expect(call.response.headers.get("mcp-session-id")).toBeNull();
    expect(call.text).toContain('"id":"own"');
    expect(call.text).not.toContain("shared-private");
    expect(mocks.listHosts).toHaveBeenCalledExactlyOnceWith(p, { limit: 20 });
    expect(quota).toHaveBeenLastCalledWith(p.keyId);
  } finally {
    await transport.close();
  }
});
it("starts command_run once and returns its final output and exit result", async () => {
  mocks.runCommand.mockResolvedValue({ operationId: "command", state: "QUEUED" });
  mocks.getCommandOutput.mockResolvedValue({
    chunks: [],
    gaps: [],
    complete: true,
    nextCursor: null,
    hasMore: false,
  });
  mocks.getResult.mockResolvedValue({ result: { type: "command", exitCode: 0 } });
  expect(
    await dispatchMcpTool(p, "command_run", {
      id: "sandbox",
      script: "true",
      idempotencyKey: "stable",
      waitMs: 0,
    }),
  ).toMatchObject({ complete: true, result: { result: { exitCode: 0 } } });
  expect(mocks.runCommand).toHaveBeenCalledOnce();
  expect(mocks.getResult).toHaveBeenCalledWith(p, { operationId: "command" });
});

it("returns host_get from the shared host DTO projection", async () => {
  const { getHost } = await import("@wssp/api/sandbox/services/hosts");
  const { toHostDto } = await import("@wssp/api/sandbox/sdk-reads");
  const dto = {
    id: "own",
    agentAccess: {
      owned: true,
      hostCommands: true,
      hostFiles: false,
    },
  };
  vi.mocked(getHost).mockResolvedValue(dto as never);
  vi.mocked(toHostDto).mockReturnValue(dto as never);
  expect(await dispatchMcpTool(p, "host_get", { hostId: "own" })).toEqual(dto);
  expect(toHostDto).toHaveBeenCalledWith(dto);
});

it("sandbox_tunnel_ports calls the native port update and validates its body", async () => {
  const dto = { sandboxId: "sbx", ports: [3000, 5173], revision: 2, state: "pending" };
  mocks.ports.mockResolvedValue(dto);
  expect(await dispatchMcpTool(p, "sandbox_tunnel_ports", { id: "sbx", add: [5173] })).toEqual(dto);
  expect(mocks.ports).toHaveBeenCalledWith(p, { id: "sbx", add: [5173] });
  await expect(
    dispatchMcpTool(p, "sandbox_tunnel_ports", { id: "sbx", add: [3000], remove: [3000] }),
  ).rejects.toThrow();
  await expect(dispatchMcpTool(p, "sandbox_tunnel_ports", { id: "sbx" })).rejects.toThrow();
  expect(mocks.ports).toHaveBeenCalledTimes(1);
});
