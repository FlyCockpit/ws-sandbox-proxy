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
import { type CommittedAuthorityScope, onAuthorityCommitted } from "@wssp/db/authority";
import { env } from "@wssp/env/server";
import { consumeMcpCredentialQuota } from "../mcp-rate-limit.js";
import { cloneRequestOntoPublicOrigin } from "../public-request-url.js";
import {
  mcpAgentTokenPolicyBlocked,
  mcpQuotaResponse,
  mcpUnauthorized,
  withMcpResponseHeaders,
} from "./errors.js";

export type McpAuthInstance = Parameters<typeof requireMcpAuth>[0];
function extractPresentedCredential(header: string | null) {
  const match = /^(Bearer|DPoP) ([A-Za-z0-9._~-]+)$/i.exec(header ?? "");
  return match ? { scheme: match[1]!.toLowerCase(), token: match[2]! } : null;
}

function matchesAuthorityScope(
  scope: CommittedAuthorityScope,
  principal: ServicePrincipal,
): boolean {
  return (
    scope.kind === "global" ||
    scope.credentialId === principal.keyId ||
    (scope.ownerId === principal.ownerId && !scope.credentialId)
  );
}

/**
 * Hold `onDone` until the response body completes, errors, or is cancelled.
 * When `endOn` aborts (revocation, ban, or client disconnect), the body is
 * ended immediately and `onDone` runs at once so long SSE tool calls cannot
 * outlive their authority listener.
 */
export function releaseWhenBodyEnds(
  response: Response,
  onDone: () => void,
  endOn?: AbortSignal,
  onCancelOrError?: () => void,
): Response {
  if (response.body === null) {
    onDone();
    return response;
  }
  const reader = response.body.getReader();
  let done = false;
  const finish = () => {
    if (done) return;
    done = true;
    endOn?.removeEventListener("abort", end);
    onDone();
  };
  let end = () => {};
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      end = () => {
        if (done) return;
        onCancelOrError?.();
        try {
          controller.error(endOn?.reason ?? new Error("MCP exchange ended"));
        } catch {
          // Already closed or errored.
        }
        void reader.cancel(endOn?.reason).catch(() => undefined);
        finish();
      };
      if (endOn?.aborted) end();
      else endOn?.addEventListener("abort", end, { once: true });
    },
    async pull(controller) {
      try {
        const chunk = await reader.read();
        if (chunk.done) {
          controller.close();
          finish();
          return;
        }
        controller.enqueue(chunk.value);
      } catch (error) {
        if (!done) onCancelOrError?.();
        controller.error(error);
        finish();
      }
    },
    async cancel(reason) {
      if (!done) onCancelOrError?.();
      finish();
      await reader.cancel(reason).catch(() => undefined);
    },
  });
  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
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
      return withMcpResponseHeaders(new Response(null, { status: 400 }));
    }
    // Cookie authentication is never consulted on this plane, including inside the verifier.
    const headers = new Headers(canonical.headers);
    headers.delete("cookie");
    canonical = new Request(canonical, { headers });
    const presented = extractPresentedCredential(headers.get("authorization"));
    if (!presented) return withMcpResponseHeaders(mcpUnauthorized(resource));

    const controller = new AbortController();
    let activePrincipal: ServicePrincipal | undefined;
    const earlyCommits: CommittedAuthorityScope[] = [];
    const off = onAuthorityCommitted((scope) => {
      if (activePrincipal === undefined) earlyCommits.push(scope);
      else if (matchesAuthorityScope(scope, activePrincipal)) controller.abort();
    });
    let handedOff = false;

    async function admitted(principal: ServicePrincipal | null, tokenScopes?: string[]) {
      if (!principal || canonical.signal.aborted) return mcpUnauthorized(resource);
      const verified = principal;
      if (earlyCommits.some((scope) => matchesAuthorityScope(scope, verified))) {
        controller.abort();
        return mcpUnauthorized(resource);
      }
      earlyCommits.length = 0;
      activePrincipal = verified;
      const scopedPrincipal = tokenScopes
        ? {
            ...verified,
            scopes: new Set([...verified.scopes].filter((scope) => tokenScopes.includes(scope))),
          }
        : verified;
      try {
        await (options.quota ?? consumeMcpCredentialQuota)(scopedPrincipal.keyId);
      } catch (error) {
        return mcpQuotaResponse(error);
      }
      if (canonical.signal.aborted || controller.signal.aborted)
        return new Response(null, { status: 499 });
      const activeSignal = AbortSignal.any([canonical.signal, controller.signal]);
      const activeRequest = new Request(canonical, { signal: activeSignal });
      const response = await options.transport.fetch(activeRequest, {
        authInfo: {
          token: presented!.token,
          clientId: scopedPrincipal.keyId,
          scopes: [...scopedPrincipal.scopes],
          resource: new URL(resource),
          extra: { principal: scopedPrincipal },
        },
      });
      if (activeSignal.aborted && response.body === null)
        return new Response(null, { status: 499 });
      const sanitized = withMcpResponseHeaders(response);
      const wrapped = releaseWhenBodyEnds(sanitized, off, activeSignal, () => controller.abort());
      handedOff = true;
      return wrapped;
    }
    try {
      if (presented.token.startsWith("wssp_agent_")) {
        if (presented.scheme !== "bearer") return withMcpResponseHeaders(mcpUnauthorized(resource));
        let p: ServicePrincipal | null;
        try {
          p = await (options.authenticateAgent ?? authenticateAgentTokenSecret)(presented.token);
        } catch (error) {
          if (error instanceof AgentTokenPolicyBlockedError)
            return withMcpResponseHeaders(mcpAgentTokenPolicyBlocked(resource));
          throw error;
        }
        const response = await admitted(p?.credentialKind === "AGENT_TOKEN" ? p : null);
        return handedOff ? response : withMcpResponseHeaders(response);
      }
      if (/^wssp_(?:sdk|host|device)_/.test(presented.token))
        return withMcpResponseHeaders(mcpUnauthorized(resource));
      const response = await requireMcpAuth(
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
      return handedOff ? response : withMcpResponseHeaders(response);
    } catch {
      return withMcpResponseHeaders(
        Response.json(
          { jsonrpc: "2.0", id: null, error: { code: -32603, message: "Internal error" } },
          { status: 500 },
        ),
      );
    } finally {
      if (!handedOff) off();
    }
  };
}
