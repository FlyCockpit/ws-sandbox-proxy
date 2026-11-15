import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import type { ServicePrincipal } from "@wssp/api/lib/sdk-key-access";
import { registerMcpTools } from "./tools.js";
export const MCP_TRANSPORT_OPTIONS = {
  legacy: "reject",
  responseMode: "json",
  maxSubscriptions: 0,
} as const;
export function createMcpTransport() {
  return createMcpHandler(
    (ctx) => {
      const principal = ctx.authInfo?.extra?.principal as ServicePrincipal | undefined;
      if (!principal || principal.credentialKind === "API" || ctx.requestInfo?.signal?.aborted)
        throw new Error("MCP principal unavailable");
      const server = new McpServer(
        { name: "wssp", version: "1.0.0" },
        { capabilities: { tools: { listChanged: false } } },
      );
      registerMcpTools(server, principal, ctx.requestInfo?.signal);
      return server;
    },
    { ...MCP_TRANSPORT_OPTIONS, onerror: () => console.error("[mcp] transport failed") },
  );
}
