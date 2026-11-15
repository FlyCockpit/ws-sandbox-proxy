import { ORPCError } from "@orpc/server";
import { env } from "@wssp/env/server";
import type { MiddlewareHandler } from "hono";
import { bodyLimit } from "hono/body-limit";
import { resolveClientIp } from "./client-ip.js";
import { isMcpOauthRawPath } from "./mcp-oauth-route-match.js";
import { mcpBudget } from "./mcp-rate-limit.js";

const oauthBudget = mcpBudget("oauth", 120);
const registerBudget = mcpBudget("register", 5);
const consentBudget = mcpBudget("consent", 30);
/** Additive to existing auth throttles; no existing auth budget is relaxed. */
export const mcpOauthRateLimits: MiddlewareHandler = async (c, next) => {
  if (!env.MCP_ENABLED || !isMcpOauthRawPath(new URL(c.req.raw.url).pathname)) return next();
  const path = new URL(c.req.raw.url).pathname;
  const consume =
    path === "/api/auth/oauth2/register"
      ? registerBudget
      : path === "/api/auth/oauth2/consent" || path === "/api/auth/oauth2/continue"
        ? consentBudget
        : oauthBudget;
  try {
    await consume(resolveClientIp(c));
  } catch (error) {
    const limited = error instanceof ORPCError && error.code === "TOO_MANY_REQUESTS";
    const seconds =
      limited &&
      error.data &&
      typeof error.data === "object" &&
      "retryAfterSeconds" in error.data &&
      typeof error.data.retryAfterSeconds === "number"
        ? Math.max(1, Math.ceil(error.data.retryAfterSeconds))
        : 5;
    return c.json(
      { error: limited ? "slow_down" : "temporarily_unavailable" },
      limited ? 429 : 503,
      { "Retry-After": String(seconds) },
    );
  }
  return bodyLimit({
    maxSize: path === "/api/auth/oauth2/consent" ? 64 * 1024 : 16 * 1024,
    onError: (c) => c.newResponse(null, 413),
  })(c, next);
};
