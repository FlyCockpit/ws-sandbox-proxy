import { DEFAULT_LOCALE, type Locale } from "@wssp/config/locales";
import { SDK_SCOPES } from "@wssp/sandbox-contracts";

export const MCP_ACCESS_TOKEN_LIFETIME_SECONDS = 10 * 60;

export const MCP_REFRESH_INACTIVITY_LIFETIME_SECONDS = 72 * 60 * 60;

export const MCP_REFRESH_RETRY_WINDOW_SECONDS = 30;

export const MCP_METADATA_PROFILE = "mcp-2026-07-28";

export const MCP_CIMD_REGISTRATION_POLICY = {
  metadataProfile: MCP_METADATA_PROFILE,
  dynamicClientRegistration: true,
} as const;

export const MCP_SCOPES = [...SDK_SCOPES, "offline_access"] as const;

export type McpScope = (typeof MCP_SCOPES)[number];

export const MCP_RESOURCE_SCOPES = SDK_SCOPES;

export const MCP_CLIENT_REGISTRATION_DEFAULT_SCOPES = [
  "sandboxes:read",
  "hosts:read",
  "offline_access",
] as const;

export const MCP_CLIENT_REGISTRATION_ALLOWED_EXTRA_SCOPES = SDK_SCOPES;

export function canonicalMcpIssuer(baseUrl: string): string {
  return new URL("/api/auth", baseUrl).toString();
}

export function canonicalMcpResource(baseUrl: string): string {
  return new URL("/mcp", baseUrl).toString();
}

export function resolveMcpWebOrigin({
  corsOrigin,
  baseUrl,
}: {
  corsOrigin: string | undefined;
  baseUrl: string;
}): string {
  return corsOrigin ?? baseUrl;
}

export function mcpLoginPagePath(locale: Locale = DEFAULT_LOCALE): string {
  return `/${locale}/mcp-login`;
}

export function mcpConsentPagePath(locale: Locale = DEFAULT_LOCALE): string {
  return `/${locale}/mcp-consent`;
}

export const MCP_LOGIN_PAGE_PATH_DEFAULT: string = mcpLoginPagePath();
export const MCP_CONSENT_PAGE_PATH_DEFAULT: string = mcpConsentPagePath();

export function parseMcpScopes(scope: string | readonly string[] | null | undefined): string[] {
  if (typeof scope === "string") {
    if (scope !== scope.trim()) return [];
    return [...new Set(scope.split(" ").filter((entry) => entry.length > 0))];
  }
  return [...new Set(scope ?? [])];
}
