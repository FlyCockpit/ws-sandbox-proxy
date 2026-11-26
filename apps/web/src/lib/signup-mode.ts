/**
 * How a visitor gets an account on this server, read from the public
 * `appConfig` (packages/api/src/routers/index.ts). The landing page branches
 * on this one value; sign-in and `/signup` read the same two flags.
 *
 * - `open`: anyone can create an account (effective `signupEnabled`).
 * - `bootstrap`: sign-up is closed except for the addresses in `ADMIN_EMAILS`,
 *   which become administrators, and no active administrator exists yet
 *   (`appConfig` turns the flag off once one does). The visitor is almost
 *   certainly the operator, so the landing page leads with "Set up this
 *   server".
 * - `closed`: invite-only; an administrator creates accounts (or a pool
 *   invitation link opens sign-up for one address).
 */
export type SignupMode = "open" | "bootstrap" | "closed";

type SignupConfig = {
  signupEnabled?: boolean;
  adminBootstrapSignupEnabled?: boolean;
};

export function signupMode(config: SignupConfig): SignupMode {
  if (config.signupEnabled === true) return "open";
  if (config.adminBootstrapSignupEnabled === true) return "bootstrap";
  return "closed";
}
