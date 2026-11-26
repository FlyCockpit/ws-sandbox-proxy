import { friendly, isRateLimit } from "@/utils/friendly-error";

type Translate = (key: string) => string;

function errorCode(error: unknown): string | undefined {
  if (!error || typeof error !== "object" || !("code" in error)) return undefined;
  const code = (error as { code?: unknown }).code;
  return typeof code === "string" ? code : undefined;
}

/**
 * What to say under the password field when a password-confirmed 2FA step
 * (turning it on or off) fails. Better-Auth answers a wrong password with
 * `INVALID_PASSWORD`, which deserves its own words; anything else keeps the
 * step's own fallback.
 */
export function twoFactorPasswordError(error: unknown, t: Translate, fallbackKey: string): string {
  if (errorCode(error) === "INVALID_PASSWORD") return t("auth:errors.wrongPassword");
  if (isRateLimit(error)) return friendly(error);
  return t(fallbackKey);
}

/** What to say under the code field when an authenticator code is refused. */
export function twoFactorCodeError(error: unknown, t: Translate): string {
  if (isRateLimit(error)) return friendly(error);
  return t("auth:errors.invalidTotp");
}
