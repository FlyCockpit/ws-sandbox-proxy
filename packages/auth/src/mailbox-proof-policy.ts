import { APIError } from "better-auth/api";

/** Better Auth's endpoint that redeems a mailed verification link. */
const VERIFY_EMAIL_PATH = "/verify-email";

const verifiedByMailOnly = () =>
  new APIError("BAD_REQUEST", {
    message: "An email address is verified only through the link mailed to it.",
    code: "EMAIL_VERIFICATION_BY_MAIL_ONLY",
  });

/**
 * Better Auth never creates a verified user here
 * (`databaseHooks.user.create.before`). wssp has no identity provider whose
 * claim could vouch for an address: sign-up forces `emailVerified: false`
 * itself, admin and pool invitations create unverified users, and the admin
 * plugin's HTTP routes (`/admin/create-user`) are disabled
 * (host-device-login-scope.ts). This refuses a future server call such as
 * `auth.api.createUser({ data: { emailVerified: true } })`. The SETUP_KEY
 * first-admin claim writes through Prisma and does not pass through here.
 */
export function refuseVerifiedUserCreation(user: { emailVerified?: unknown }): void {
  if (user.emailVerified === true) throw verifiedByMailOnly();
}

/**
 * Two rules for every user-row update Better Auth makes
 * (`databaseHooks.user.update.before`):
 *
 * - No update carries `email`. wssp has no email-change feature
 *   (`user.changeEmail` is off; `/update-user` refuses `email` itself;
 *   `/admin/update-user` is disabled). This also covers `/verify-email`'s
 *   `updateTo` branch, which acts on any token signed with the secret, and
 *   any future server call. An app that adds an email change gives it its
 *   own flow that leaves the new address unverified until it is proved.
 * - Only `/verify-email` writes `emailVerified`: opening the link mailed to
 *   the address is the proof. Nothing an administrator or the server asserts
 *   (no endpoint context, or another route) changes it through Better Auth.
 *
 * Prisma writes from app code do not pass through this hook; the writer
 * inventory (email-verification-writers.test.ts) covers those.
 */
export function refuseUnprovedUserUpdate(
  data: Record<string, unknown>,
  context: { path?: string } | null | undefined,
): void {
  if (data.email !== undefined) {
    throw new APIError("BAD_REQUEST", {
      message: "Account email addresses cannot be changed.",
      code: "EMAIL_CHANGE_UNSUPPORTED",
    });
  }
  if (data.emailVerified !== undefined && context?.path !== VERIFY_EMAIL_PATH)
    throw verifiedByMailOnly();
}
