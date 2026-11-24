/**
 * Operator hint for a deployment with no administrator (M7-S14). This log line
 * is the only signal: the web UI shows users no "no administrator" banner
 * (e2e E-10), and how to fix it names configuration (SETUP_KEY,
 * ADMIN_EMAILS), which belongs to the operator. Once an administrator exists
 * it reminds the operator to remove a SETUP_KEY that is still set; admins see
 * the same reminder on the admin overview's deployment setup card.
 */
export async function logAdminSetupHint(options: {
  hasActiveAdministrator: () => Promise<boolean>;
  adminEmailsConfigured: boolean;
  setupKeyConfigured: boolean;
  warn?: (message: string) => void;
}): Promise<void> {
  const warn = options.warn ?? console.warn;
  let present: boolean;
  try {
    present = await options.hasActiveAdministrator();
  } catch (error) {
    warn(
      `[admin] Could not check for an administrator at startup: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
    return;
  }
  if (present) {
    if (options.setupKeyConfigured) {
      warn(
        "[admin] An administrator exists and SETUP_KEY is still set. It is only needed to " +
          "create the first administrator: remove it from the environment and restart.",
      );
    }
    return;
  }
  if (options.setupKeyConfigured) {
    warn(
      "[admin] No administrator exists yet. SETUP_KEY is set: run `pnpm deploy:generate-admin` " +
        "against this server for a one-time link that creates the first administrator (no " +
        "email needed), then remove SETUP_KEY.",
    );
    return;
  }
  warn(
    options.adminEmailsConfigured
      ? "[admin] No administrator exists yet. Sign up (and verify the email) with an address " +
          "listed in ADMIN_EMAILS to become the first administrator."
      : "[admin] No administrator exists yet and ADMIN_EMAILS is empty. Set SETUP_KEY and run " +
          "`pnpm deploy:generate-admin` (no email needed), or set ADMIN_EMAILS to a " +
          "comma-separated list of operator emails and restart the server, then sign up with " +
          "one of those addresses to become the first administrator.",
  );
}
