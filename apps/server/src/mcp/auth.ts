import { requireMcpAuth } from "@better-auth/mcp";
import type { McpHttpHandler } from "@modelcontextprotocol/server";
import {
  AgentTokenPolicyBlockedError,
  authenticateAgentTokenSecret,
  principalForMcpGrant,
  type ServicePrincipal,
} from "@wssp/api/lib/sdk-key-access";
import {
  canonicalMcpIssuer,
  canonicalMcpResource,
  MCP_RESOURCE_SCOPES,
  parseMcpScopes,
} from "@wssp/auth/mcp-config";
import { onAuthorityCommitted } from "@wssp/db/authority";
import { env } from "@wssp/env/server";
import { consumeMcpCredentialQuota } from "../mcp-rate-limit.js";
import { cloneRequestOntoPublicOrigin } from "../public-request-url.js";
import { mcpAgentTokenPolicyBlocked, mcpQuotaResponse, mcpUnauthorized } from "./errors.js";

export type McpAuthInstance = Parameters<typeof requireMcpAuth>[0];
function extractPresentedCredential(header: string | null) {
  const match = /^(Bearer|DPoP) ([A-Za-z0-9._~-]+)$/i.exec(header ?? "");
  return match ? { scheme: match[1]!.toLowerCase(), token: match[2]! } : null;
}
export function createMcpAuthenticator(options: {
  authInstance: McpAuthInstance;
  transport: Pick<McpHttpHandler, "fetch">;
  authenticateAgent?: typeof authenticateAgentTokenSecret;
  grantPrincipal?: typeof principalForMcpGrant;
  quota?: (key: string) => Promise<void>;
}) {
  return async (request: Request): Promise<Response> => {
    const resource = canonicalMcpResource(env.BETTER_AUTH_URL);
    let canonical: Request;
    try {
      canonical = cloneRequestOntoPublicOrigin(request);
    } catch {
      return new Response(null, { status: 400 });
    }
    // Cookie authentication is never consulted on this plane, including inside the verifier.
    const headers = new Headers(canonical.headers);
    headers.delete("cookie");
    canonical = new Request(canonical, { headers });
    const presented = extractPresentedCredential(headers.get("authorization"));
    if (!presented) return mcpUnauthorized(resource);
    async function admitted(principal: ServicePrincipal | null, tokenScopes?: string[]) {
      if (!principal || canonical.signal.aborted) return mcpUnauthorized(resource);
      if (tokenScopes)
        principal = {
          ...principal,
          scopes: new Set([...principal.scopes].filter((scope) => tokenScopes.includes(scope))),
        };
      try {
        await (options.quota ?? consumeMcpCredentialQuota)(principal.keyId);
      } catch (error) {
        return mcpQuotaResponse(error);
      }
      if (canonical.signal.aborted) return new Response(null, { status: 499 });
      const controller = new AbortController();
      const off = onAuthorityCommitted((scope) => {
        if (
          scope.kind === "global" ||
          scope.credentialId === principal.keyId ||
          (scope.ownerId === principal.ownerId && !scope.credentialId)
        )
          controller.abort();
      });
      const activeRequest = new Request(canonical, {
        signal: AbortSignal.any([canonical.signal, controller.signal]),
      });
      try {
        return await options.transport.fetch(activeRequest, {
          authInfo: {
            token: presented!.token,
            clientId: principal.keyId,
            scopes: [...principal.scopes],
            resource: new URL(resource),
            extra: { principal },
          },
        });
      } finally {
        off();
      }
    }
    try {
      if (presented.token.startsWith("wssp_agent_")) {
        if (presented.scheme !== "bearer") return mcpUnauthorized(resource);
        let p: ServicePrincipal | null;
        try {
          p = await (options.authenticateAgent ?? authenticateAgentTokenSecret)(presented.token);
        } catch (error) {
          if (error instanceof AgentTokenPolicyBlockedError)
            return mcpAgentTokenPolicyBlocked(resource);
          throw error;
        }
        return await admitted(p?.credentialKind === "AGENT_TOKEN" ? p : null);
      }
      if (/^wssp_(?:sdk|host|device)_/.test(presented.token)) return mcpUnauthorized(resource);
      return await requireMcpAuth(
        options.authInstance,
        async (_request, claims) => {
          if (
            typeof claims.sub !== "string" ||
            typeof claims.client_id !== "string" ||
            typeof claims.wssp_grant_id !== "string"
          )
            return mcpUnauthorized(resource);
          const p = await (options.grantPrincipal ?? principalForMcpGrant)(
            claims.wssp_grant_id,
            claims.sub,
            claims.client_id,
          );
          const scope =
            typeof claims.scope === "string"
              ? claims.scope
              : Array.isArray(claims.scope) && claims.scope.every((s) => typeof s === "string")
                ? (claims.scope as string[])
                : [];
          return admitted(p?.credentialKind === "OAUTH_GRANT" ? p : null, parseMcpScopes(scope));
        },
        {
          issuer: canonicalMcpIssuer(env.BETTER_AUTH_URL),
          resource,
          requiredScopes: [],
          challengeScopes: [...MCP_RESOURCE_SCOPES],
        },
      )(canonical);
    } catch {
      return Response.json(
        { jsonrpc: "2.0", id: null, error: { code: -32603, message: "Internal error" } },
        { status: 500 },
      );
    }
  };
}
