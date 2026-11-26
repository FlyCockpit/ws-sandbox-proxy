import { PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH } from "@wssp/auth/password-policy";
import z from "zod";

export { PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH };

/**
 * The Zod rule for every new-password field (signup, reset/setup, change
 * password). It reads the same constants Better-Auth enforces, and the field
 * shows the rule up front with `t("auth:fields.passwordRule", { min:
 * PASSWORD_MIN_LENGTH })` as its `description`, so the user never learns it
 * from an error. Messages come from the locale error map (`@/i18n/zod`).
 */
export function newPasswordSchema() {
  return z.string().min(PASSWORD_MIN_LENGTH).max(PASSWORD_MAX_LENGTH);
}

/**
 * The sign-in password rule: present, nothing more. It deliberately ignores
 * the minimum, so an account whose password predates the current policy can
 * still sign in; the server is the only judge of whether it matches. The
 * caller passes the "required" copy (`validation:required`): the generic map
 * would say "at least 1 characters".
 */
export function currentPasswordSchema(requiredMessage: string) {
  return z.string().min(1, requiredMessage);
}
