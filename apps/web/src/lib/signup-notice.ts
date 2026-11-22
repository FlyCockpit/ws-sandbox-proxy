/**
 * Which notice the sign-up form shows above its fields:
 * - `invite`: the visitor came from a pool invitation link (its secret is held
 *   in memory, see lib/pool-invite.ts) and must reopen it after verifying;
 * - `limited`: sign-up is closed but the configured administrator addresses
 *   may still bootstrap (public `appConfig`, nothing new is disclosed);
 * - `null`: nothing to say.
 */
export function signupNotice(
  config: { signupEnabled: boolean; adminBootstrapSignupEnabled: boolean } | undefined,
  hasInviteToken: boolean,
): "invite" | "limited" | null {
  if (hasInviteToken) return "invite";
  if (config && !config.signupEnabled && config.adminBootstrapSignupEnabled) return "limited";
  return null;
}
