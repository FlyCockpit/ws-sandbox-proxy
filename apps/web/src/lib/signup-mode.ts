/**
 * How a visitor gets an account on this server, read from the public
 * `appConfig` (packages/api/src/routers/index.ts) and from whether this tab
 * holds a pool invitation (lib/pool-invite.ts). The landing page, the header,
 * sign-in and `/signup` all branch on this one value so they always tell the
 * same story.
 *
 * - `invite`: the visitor opened a pool invitation link, whose secret is held
 *   in memory. Sign-up is open to the invited address whatever the server's
 *   sign-up setting, and the person must reopen the link after verifying.
 * - `open`: anyone can create an account (effective `signupEnabled`).
 * - `bootstrap`: sign-up is closed except for the addresses in `ADMIN_EMAILS`,
 *   which become administrators, and no active administrator exists yet
 *   (`appConfig` turns the flag off once one does). The visitor is almost
 *   certainly the operator, so the landing page leads with "Set up this
 *   server".
 * - `closed`: invite-only; an administrator creates accounts or sends a pool
 *   invitation. `/signup` shows a closed card instead of a form.
 */
export type SignupMode = "invite" | "open" | "bootstrap" | "closed";

type SignupConfig = {
  signupEnabled?: boolean;
  adminBootstrapSignupEnabled?: boolean;
};

export function signupMode(config: SignupConfig, hasPoolInvite = false): SignupMode {
  if (hasPoolInvite) return "invite";
  if (config.signupEnabled === true) return "open";
  if (config.adminBootstrapSignupEnabled === true) return "bootstrap";
  return "closed";
}

/** Whether this mode has a sign-up form to send the visitor to. */
export function signupOffered(mode: SignupMode): boolean {
  return mode !== "closed";
}
