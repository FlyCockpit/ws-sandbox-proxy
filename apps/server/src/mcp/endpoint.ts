import type { HttpBindings } from "@hono/node-server";
import { canonicalMcpResource } from "@wssp/auth/mcp-config";
import { env } from "@wssp/env/server";
import { Hono } from "hono";
import { resolveClientIp } from "../client-ip.js";
import { consumeMcpIpQuota } from "../mcp-rate-limit.js";
import { createMcpAuthenticator, type McpAuthInstance } from "./auth.js";
import { mcpJsonBodyLimit } from "./body-limit.js";
import { mcpQuotaResponse, mcpUnauthorized } from "./errors.js";
import { createMcpTransport } from "./handler.js";

export function createMcpApi(authInstance: McpAuthInstance) {
  const app = new Hono<{ Bindings: Partial<HttpBindings> }>();
  const transport = createMcpTransport();
  const authenticate = createMcpAuthenticator({ authInstance, transport });
  app.onError(() =>
    Response.json(
      { jsonrpc: "2.0", id: null, error: { code: -32603, message: "Internal error" } },
      { status: 500 },
    ),
  );
  app.all("/mcp", async (c, next) => {
    if (env.MCP_ENABLED === false) return c.notFound();
    if (c.req.method !== "POST") return c.newResponse(null, 405, { Allow: "POST" });
    if (new URL(c.req.url).search) return c.newResponse(null, 400);
    try {
      await consumeMcpIpQuota(resolveClientIp(c));
    } catch (error) {
      return mcpQuotaResponse(error);
    }
    const rawHeaders = c.env?.incoming?.rawHeaders ?? [];
    let authorizationHeaders = 0;
    for (let index = 0; index < rawHeaders.length; index += 2)
      if (rawHeaders[index]?.toLowerCase() === "authorization") authorizationHeaders++;
    if (authorizationHeaders > 1) return mcpUnauthorized(canonicalMcpResource(env.BETTER_AUTH_URL));
    // Cheap credential gate before buffering even a bounded JSON body. No cookie lookup.
    if (!/^(Bearer|DPoP) [A-Za-z0-9._~-]+$/i.test(c.req.header("authorization") ?? ""))
      return mcpUnauthorized(canonicalMcpResource(env.BETTER_AUTH_URL));
    if (
      (c.req.header("content-type") ?? "").toLowerCase().split(";")[0]?.trim() !==
      "application/json"
    )
      return c.newResponse(null, 415);
    return next();
  });
  app.post("/mcp", mcpJsonBodyLimit(), (c) => authenticate(c.req.raw));
  return app;
}
