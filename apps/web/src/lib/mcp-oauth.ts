import { SERVICE_SCOPES, type ServiceScope } from "@/lib/credential-rules";
export function parseMcpRequest(search: Record<string, unknown>) {
  const clientId = typeof search.client_id === "string" ? search.client_id : "";
  const scopes =
    typeof search.scope === "string" ? [...new Set(search.scope.split(" ").filter(Boolean))] : [];
  const sig = Array.isArray(search.sig)
    ? search.sig.some((value) => typeof value === "string" && value.length > 0)
    : typeof search.sig === "string" && search.sig.length > 0;
  return {
    clientId,
    scopes,
    usable:
      !!clientId &&
      sig &&
      scopes.every(
        (scope) => scope === "offline_access" || SERVICE_SCOPES.includes(scope as ServiceScope),
      ),
    serviceScopes: SERVICE_SCOPES.filter((scope) => scopes.includes(scope)),
  };
}
export function oauthRedirect(data: unknown): string | null {
  if (
    !data ||
    typeof data !== "object" ||
    !("redirect" in data) ||
    data.redirect !== true ||
    !("url" in data) ||
    typeof data.url !== "string"
  )
    return null;
  try {
    const url = new URL(data.url);
    return ["http:", "https:"].includes(url.protocol) ? url.href : null;
  } catch {
    return null;
  }
}
