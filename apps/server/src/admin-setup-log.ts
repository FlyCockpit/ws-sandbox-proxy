/**
 * Operator hint for a deployment with no administrator (M7-S14). This log line
 * is the only signal: the web UI shows users no "no administrator" banner
 * (e2e E-10), and how to fix it names configuration (ADMIN_EMAILS), which
 * belongs to the operator.
 */
export async function logAdminSetupHint(options: {
  hasActiveAdministrator: () => Promise<boolean>;
  adminEmailsConfigured: boolean;
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
  if (present) return;
  warn(
    options.adminEmailsConfigured
      ? "[admin] No administrator exists yet. Sign up (and verify the email) with an address " +
          "listed in ADMIN_EMAILS to become the first administrator."
      : "[admin] No administrator exists yet and ADMIN_EMAILS is empty. Set ADMIN_EMAILS to a " +
          "comma-separated list of operator emails, restart the server, then sign up with one " +
          "of those addresses to become the first administrator.",
  );
}
