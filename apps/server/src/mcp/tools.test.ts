import { ORPCError } from "@orpc/server";
import type { ServicePrincipal } from "@wssp/api/lib/sdk-key-access";
import { beforeEach, expect, it, vi } from "vitest";

vi.mock("./tool-dispatch.js", () => ({ dispatchMcpTool: vi.fn() }));
vi.mock("../mcp-rate-limit.js", () => ({
  consumeMcpCreateQuota: vi.fn(),
  consumeMcpHostCommandQuota: vi.fn(),
}));
vi.mock("@wssp/env/server", () => ({ env: { CAPACITY_RETRY_AFTER_SECONDS: 5 } }));

import { dispatchMcpTool } from "./tool-dispatch";
import { callMcpTool } from "./tools";

const dispatch = vi.mocked(dispatchMcpTool);
const p: ServicePrincipal = {
  kind: "sdkKey",
  credentialKind: "AGENT_TOKEN",
  keyId: "key",
  ownerId: "owner",
  expiresAt: null,
  resourceMode: "ALL_OWNED",
  ownSandboxesOnly: true,
  scopes: new Set(["sandboxes:create", "hosts:execute"]),
  allowedHostIds: "allOwned",
  allowedRevisionIds: "allOwned",
  allowedPoolIds: "allUsable",
};
beforeEach(() => {
  dispatch.mockReset().mockResolvedValue({ ok: true });
});
it("answers hidden tools exactly like unknown tools", async () => {
  const hidden = await callMcpTool(p, "sandbox_destroy", {});
  expect(hidden).toEqual({
    content: [{ type: "text", text: "Tool sandbox_destroy not found" }],
    isError: true,
  });
  expect(await callMcpTool(p, "missing", {})).toEqual({
    content: [{ type: "text", text: "Tool missing not found" }],
    isError: true,
  });
  expect(dispatch).not.toHaveBeenCalled();
});
it("generates a retry key once and preserves a supplied key in service input and result", async () => {
  const first = await callMcpTool(p, "host_command_run", { hostId: "host", script: "true" });
  expect(first).toMatchObject({ structuredContent: { idempotencyKey: expect.any(String) } });
  const sent = dispatch.mock.calls[0]![2] as { idempotencyKey: string };
  expect(first).toMatchObject({ structuredContent: { idempotencyKey: sent.idempotencyKey } });
  await callMcpTool(p, "host_command_run", {
    hostId: "host",
    script: "true",
    idempotencyKey: "stable-retry",
  });
  expect(dispatch.mock.calls[1]![2]).toMatchObject({ idempotencyKey: "stable-retry" });
});
it("preserves a generated key and retry hints on service errors without exposing internal error text", async () => {
  dispatch.mockRejectedValue(
    new ORPCError("CONFLICT", {
      message: "private SQL",
      data: { code: "host.node_offline", retryable: true, retryAfterSeconds: 7 },
    }),
  );
  const result = await callMcpTool(p, "host_command_run", {
    hostId: "host",
    script: "true",
    idempotencyKey: "retry",
  });
  expect(result).toMatchObject({
    isError: true,
    structuredContent: {
      error: {
        code: "host.node_offline",
        retryable: true,
        retryAfterSeconds: 7,
        idempotencyKey: "retry",
      },
    },
  });
  expect(JSON.stringify(result)).not.toContain("private SQL");
});
it("charges per-tool budgets before service dispatch and returns retryable rate errors", async () => {
  const result = await callMcpTool(
    p,
    "host_command_run",
    { hostId: "host", script: "true" },
    {
      hostCommandQuota: async () => {
        throw new ORPCError("TOO_MANY_REQUESTS", { data: { retryAfterSeconds: 10 } });
      },
    },
  );
  expect(result).toMatchObject({
    structuredContent: {
      error: { code: "TOO_MANY_REQUESTS", retryable: true, retryAfterSeconds: 10 },
    },
  });
  expect(dispatch).not.toHaveBeenCalled();
});

it("returns BAD_REQUEST for malformed retry keys without echoing them", async () => {
  const response = await callMcpTool(p, "host_command_run", {
    hostId: "host",
    script: "true",
    idempotencyKey: "bad key",
  });
  expect(response).toMatchObject({
    structuredContent: { error: { code: "BAD_REQUEST" } },
    isError: true,
  });
  expect(JSON.stringify(response)).not.toContain("bad key");
  expect(dispatch).not.toHaveBeenCalled();
});
