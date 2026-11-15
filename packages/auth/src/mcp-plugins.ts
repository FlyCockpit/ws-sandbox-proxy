import { cimd } from "@better-auth/cimd";
import { fetchClientMetadataResource } from "@better-auth/cimd/node";
import { mcp } from "@better-auth/mcp";
import { env } from "@wssp/env/server";
import { jwt } from "better-auth/plugins";
import {
  canonicalMcpResource,
  MCP_ACCESS_TOKEN_LIFETIME_SECONDS,
  MCP_CIMD_REGISTRATION_POLICY,
  MCP_CLIENT_REGISTRATION_ALLOWED_EXTRA_SCOPES,
  MCP_CLIENT_REGISTRATION_DEFAULT_SCOPES,
  MCP_CONSENT_PAGE_PATH_DEFAULT,
  MCP_LOGIN_PAGE_PATH_DEFAULT,
  MCP_REFRESH_INACTIVITY_LIFETIME_SECONDS,
  MCP_REFRESH_RETRY_WINDOW_SECONDS,
  MCP_SCOPES,
} from "./mcp-config";
import { mcpConsent } from "./mcp-consent";
import { createMcpPostLoginOptions, issueMcpGrantClaims } from "./mcp-grant";

export function resolveMcpPlugins({ enabled, baseUrl }: { enabled: boolean; baseUrl: string }) {
  if (!enabled) return [] as const;

  const resource = canonicalMcpResource(baseUrl);

  const postLogin = createMcpPostLoginOptions({
    secret: env.BETTER_AUTH_SECRET,
    loginPage: MCP_LOGIN_PAGE_PATH_DEFAULT,
  });

  return [
    jwt({
      disableSettingJwtHeader: true,
    }),
    mcp({
      resource,

      loginPage: MCP_LOGIN_PAGE_PATH_DEFAULT,
      consentPage: MCP_CONSENT_PAGE_PATH_DEFAULT,
      postLogin,

      allowPublicClientPrelogin: true,

      scopes: [...MCP_SCOPES],
      clientRegistrationDefaultScopes: [...MCP_CLIENT_REGISTRATION_DEFAULT_SCOPES],
      clientRegistrationAllowedScopes: [...MCP_CLIENT_REGISTRATION_ALLOWED_EXTRA_SCOPES],
      clientRegistrationRequirePKCE: true,

      allowDynamicClientRegistration: true,
      allowUnauthenticatedClientRegistration: true,

      grantTypes: ["authorization_code", "refresh_token"],

      accessTokenExpiresIn: MCP_ACCESS_TOKEN_LIFETIME_SECONDS,
      refreshTokenExpiresIn: MCP_REFRESH_INACTIVITY_LIFETIME_SECONDS,
      refreshTokenReuseInterval: MCP_REFRESH_RETRY_WINDOW_SECONDS,

      enforcePerClientResources: true,

      clientPrivileges: () => false,
      resourcePrivileges: () => false,

      extensions: [
        {
          claims: {
            accessToken: (input: {
              grantType?: string | undefined;
              user?: { id?: string | undefined } | null;
              client: { clientId: string };
              sessionId?: string | null | undefined;
              referenceId?: string | undefined;
            }) =>
              issueMcpGrantClaims({
                grantType: input.grantType,
                userId: input.user?.id,
                clientId: input.client.clientId,
                referenceId: input.referenceId,
                sessionId: input.sessionId,
                secret: env.BETTER_AUTH_SECRET,
              }),
          },
        },
      ],
    }),
    mcpConsent({ secret: env.BETTER_AUTH_SECRET }),
    cimd({
      fetchClientMetadataResource,
      metadataProfile: MCP_CIMD_REGISTRATION_POLICY.metadataProfile,
    }),
  ] as const;
}
