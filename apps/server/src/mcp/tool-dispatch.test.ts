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
