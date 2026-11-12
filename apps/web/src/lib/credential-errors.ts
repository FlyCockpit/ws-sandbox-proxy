/**
 * `credential.*` domain codes the dashboard explains with its own copy (the
 * `errors:credential.*` keys). Anything else falls back to the caller's
 * generic mapping. Codes only: a refusal never carries a value.
 */
export const CREDENTIAL_ERROR_CODES = [
  "not_found",
  "account_not_found",
  "instance_not_found",
  "lease_not_found",
  "definition_not_found",
  "in_use",
  "account_paused",
  "needs_login",
  "limit_reached",
  "unavailable",
  "repin_blocked",
  "repin_confirm_erase",
  "value_invalid",
  "definition_corrupt",
  "name_taken",
  "busy",
  "spec_too_large",
  "pending_drain",
  "recovery_required",
  "capture_in_progress",
  "capture_failed",
  "host_forbidden",
  "env_conflict",
  "path_conflict",
  "proxy_not_enabled",
  "not_attached",
  "already_attached",
  "login_needs_consent",
  "login_requires_upload",
  "login_session_not_found",
  "login_state",
] as const;
export type CredentialErrorCode = (typeof CREDENTIAL_ERROR_CODES)[number];

const KNOWN: ReadonlySet<string> = new Set(CREDENTIAL_ERROR_CODES);

/** The `credential.*` code of a refusal (without the prefix), when the dashboard knows it. */
export function credentialErrorCode(error: unknown): CredentialErrorCode | null {
  if (!error || typeof error !== "object" || !("data" in error)) return null;
  const data = (error as { data?: unknown }).data;
  if (!data || typeof data !== "object" || !("code" in data)) return null;
  const code = (data as { code?: unknown }).code;
  if (typeof code !== "string" || !code.startsWith("credential.")) return null;
  const short = code.slice("credential.".length);
  return KNOWN.has(short) ? (short as CredentialErrorCode) : null;
}

/** The `errors` key for a known credential refusal, else null. */
export function credentialErrorKey(error: unknown): string | null {
  const code = credentialErrorCode(error);
  return code ? `errors:credential.${code}` : null;
}
