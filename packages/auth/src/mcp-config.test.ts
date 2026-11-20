import { SDK_SCOPES } from "@wssp/sandbox-contracts";
import { expect, it } from "vitest";
import {
  MCP_CLIENT_REGISTRATION_ALLOWED_EXTRA_SCOPES,
  MCP_RESOURCE_SCOPES,
  MCP_SCOPES,
} from "./mcp-config";

it("CLI shells (sandboxes:connect) are never an MCP scope; every other SDK scope is", () => {
  for (const list of [
    MCP_SCOPES,
    MCP_RESOURCE_SCOPES,
    MCP_CLIENT_REGISTRATION_ALLOWED_EXTRA_SCOPES,
  ])
    expect(list as readonly string[]).not.toContain("sandboxes:connect");
  expect([...MCP_RESOURCE_SCOPES].sort()).toEqual(
    SDK_SCOPES.filter((scope) => scope !== "sandboxes:connect").sort(),
  );
  expect(MCP_SCOPES).toContain("offline_access");
});
