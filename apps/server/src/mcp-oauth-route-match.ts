import type { Context, MiddlewareHandler } from "hono";

/**
 * RAW method+path boundary for the MCP OAuth flag gate (L18).
 *
 * Two routers disagree on path spelling: Hono's `c.req.path` (and its route
 * matching) percent-DECODES unreserved triples, while better-call — the
 * router inside the installed Better Auth handler — routes on the RAW,
 * still-encoded `new URL(request.url).pathname` and 404s anything else. A
 * request for `/api/%61uth/oauth2/token` therefore MATCHES Hono's
 * `/api/auth/*` mounts but is NOT the token route downstream, so the gate
 * below decides on the raw pathname, never on `c.req.path`.
 */

/**
 * The server's ENTIRE OAuth surface while MCP_ENABLED is on: the oauth2
 * namespace (`mcp()` IS the OAuth provider; it serves authorize, token,
 * consent, continue, revoke, introspect, public-client,
 * public-client-prelogin, delete-consent, register (DCR), userinfo, and the
 * client/resource CRUD family under /oauth2/*) plus the jwt() plugin's JWKS
 * endpoint. There is no other OAuth provider in this app, so the flag-off
 * gate below may own the whole namespace.
 */
const MCP_OAUTH_PATH_PREFIX = "/api/auth/oauth2/";
const MCP_OAUTH_JWKS_PATH = "/api/auth/jwks";

/** RAW (still percent-encoded) request pathname — better-call's spelling. */
function mcpOauthRawPath(c: Context): string {
  return new URL(c.req.raw.url).pathname;
}

/**
 * Flag-off applicability test for the OAuth 404 gate: the RAW, still-encoded
 * pathname is the JWKS path exactly, or lies under the raw /api/auth/oauth2/
 * prefix. RAW comparison mirrors better-call's routing (L18): a
 * percent-encoded spelling like `/api/%61uth/oauth2/token` does NOT match and
 * keeps stock handling (general limiter + the provider's own 404).
 */
export function isMcpOauthRawPath(rawPathname: string): boolean {
  return rawPathname === MCP_OAUTH_JWKS_PATH || rawPathname.startsWith(MCP_OAUTH_PATH_PREFIX);
}

/**
 * MCP OAuth flag-off 404 gate (Phase 9 / invariant 13: while
 * MCP_ENABLED is off, MCP OAuth routes return REAL 404s — authorization
 * remains flag-gated even when the installed provider is present, e.g. a
 * flag flip without a rebuilt plugin list or a test instance that always
 * carries the plugins). Mounted in the SAME pre-CORS/pre-global-body-limit
 * block as the discovery aliases and the web-page gate (the L23 lesson: the
 * gate must own EVERY method — OPTIONS included — before CORS can answer
 * 204) and before the MCP OAuth limiters / general auth limiter, so a gated
 * 404 never consumes limiter budget. While the flag is ON this is a pure
 * pass-through: scope guard, limiters, body caps, session middleware, and
 * the provider handler all run exactly as before.
 */
export function createMcpOauthFlagGate({ enabled }: { enabled: () => boolean }): MiddlewareHandler {
  return async (c, next) => {
    if (!enabled() && isMcpOauthRawPath(mcpOauthRawPath(c))) {
      return c.notFound();
    }
    return next();
  };
}
