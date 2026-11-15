import { getOAuthProviderState } from "@better-auth/oauth-provider";
import type { BetterAuthPlugin } from "better-auth";
import { APIError, createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
import { MCP_SCOPES, parseMcpScopes } from "./mcp-config";
import { deriveMcpConsentReferenceId, mcpGrantServices } from "./mcp-grant";

export const MCP_CONSENT_ENDPOINT_PATH = "/oauth2/consent";
export function consentBody(body: unknown): Record<string, unknown> {
  return typeof body === "object" && body !== null && !Array.isArray(body)
    ? (body as Record<string, unknown>)
    : {};
}
export function validateConsentScopes(body: unknown, query: string): string[] {
  const record = consentBody(body);
  if (typeof record.scope !== "string")
    throw new APIError("BAD_REQUEST", { error: "invalid_scope" });
  const scopes = parseMcpScopes(record.scope);
  const requested = new Set(parseMcpScopes(new URLSearchParams(query).get("scope")));
  if (
    !scopes.length ||
    scopes.some(
      (scope) => !requested.has(scope) || !(MCP_SCOPES as readonly string[]).includes(scope),
    )
  )
    throw new APIError("BAD_REQUEST", { error: "invalid_scope" });
  return scopes;
}
export function consentIssuedCode(returned: unknown): boolean {
  const record = consentBody(returned);
  if (record.redirect !== true || typeof record.url !== "string") return false;
  try {
    const params = new URL(record.url).searchParams;
    return params.has("code") && !params.has("error");
  } catch {
    return false;
  }
}
/** The signed oauth_query is verified by mcp()'s earlier before-hook. */
export function mcpConsent({ secret }: { secret: string }) {
  return {
    id: "wssp-mcp-consent",
    hooks: {
      before: [
        {
          matcher: (ctx) => ctx.path === MCP_CONSENT_ENDPOINT_PATH,
          handler: createAuthMiddleware(async (ctx) => {
            if (consentBody(ctx.body).accept !== true) return;
            const query = (await getOAuthProviderState())?.query;
            const session = await getSessionFromCtx(ctx);
            const clientId = query ? new URLSearchParams(query).get("client_id") : null;
            if (!query || !session || !clientId)
              throw new APIError("BAD_REQUEST", { error: "invalid_request" });
            const scopes = validateConsentScopes(ctx.body, query);
            try {
              // Runs before the provider remembers approval or creates an authorization code.
              // The cookie cache identifies the session; the recording transaction validates it.
              await mcpGrantServices().record({
                userId: session.user.id,
                sessionId: session.session.id,
                clientId,
                referenceId: deriveMcpConsentReferenceId({
                  secret,
                  sessionId: session.session.id,
                  clientId,
                }),
                requestedScopes: parseMcpScopes(new URLSearchParams(query).get("scope")),
                choices: {
                  ...consentBody(ctx.body),
                  scopes: scopes.filter((scope) => scope !== "offline_access"),
                },
              });
            } catch {
              throw new APIError("INTERNAL_SERVER_ERROR", { error: "server_error" });
            }
          }),
        },
      ],
    },
  } satisfies BetterAuthPlugin;
}
