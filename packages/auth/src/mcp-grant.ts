import { createHmac } from "node:crypto";
import { getOAuthProviderState } from "@better-auth/oauth-provider";

export const MCP_GRANT_ID_CLAIM = "wssp_grant_id";
export function deriveMcpConsentReferenceId(input: {
  secret: string;
  sessionId: string;
  clientId: string;
}) {
  return createHmac("sha256", input.secret)
    .update(`mcp-consent-reference-v1\0${input.sessionId}\0${input.clientId}`)
    .digest("hex");
}
/** Bound by the server to credential services, avoiding an auth/API import cycle. */
export type McpGrantServices = {
  record(input: {
    userId: string;
    sessionId: string;
    clientId: string;
    referenceId: string;
    choices: unknown;
    requestedScopes: string[];
  }): Promise<void>;
  revoked(input: { userId: string; clientId: string; referenceId: string }): Promise<boolean>;
  active(input: { userId: string; clientId: string; referenceId: string }): Promise<string | null>;
};
let services: McpGrantServices | undefined;
export function bindMcpGrantServices(value: McpGrantServices) {
  services = value;
}
export function mcpGrantServices(): McpGrantServices {
  if (!services) throw new Error("MCP grant services unavailable");
  return services;
}
export async function issueMcpGrantClaims(input: {
  grantType?: string;
  userId?: string;
  clientId: string;
  referenceId?: string;
  sessionId?: string | null;
  secret: string;
}): Promise<Record<string, unknown>> {
  const referenceId =
    input.referenceId ??
    (input.grantType === "authorization_code" && input.sessionId
      ? deriveMcpConsentReferenceId({
          secret: input.secret,
          sessionId: input.sessionId,
          clientId: input.clientId,
        })
      : undefined);
  if (!input.userId || !referenceId) throw new Error("MCP consent binding required");
  let id: string | null;
  try {
    id = await mcpGrantServices().active({
      userId: input.userId,
      clientId: input.clientId,
      referenceId,
    });
  } catch {
    // The provider logs thrown errors; never forward database/query details.
    throw new Error("MCP grant lookup unavailable");
  }
  if (!id) throw new Error("MCP consent inactive");
  return { [MCP_GRANT_ID_CLAIM]: id };
}
export function createMcpPostLoginOptions({
  secret,
  loginPage,
}: {
  secret: string;
  loginPage: string;
}) {
  return {
    page: loginPage,
    consentReferenceId: async (context: { session?: { id?: string } | null }): Promise<string> => {
      const query = (await getOAuthProviderState())?.query;
      const clientId = query ? new URLSearchParams(query).get("client_id") : null;
      const sessionId = context.session?.id;
      if (!sessionId || !clientId) throw new Error("MCP consent binding unavailable");
      return deriveMcpConsentReferenceId({ secret, sessionId, clientId });
    },
    shouldRedirect: async (context: {
      user?: { id?: string } | null;
      session?: { id?: string } | null;
    }) => {
      const query = (await getOAuthProviderState())?.query;
      const clientId = query ? new URLSearchParams(query).get("client_id") : null;
      if (!clientId || !context.user?.id || !context.session?.id) return false;
      try {
        return await mcpGrantServices().revoked({
          userId: context.user.id,
          clientId,
          referenceId: deriveMcpConsentReferenceId({
            secret,
            sessionId: context.session.id,
            clientId,
          }),
        });
      } catch {
        throw new Error("MCP grant lookup unavailable");
      }
    },
  };
}
