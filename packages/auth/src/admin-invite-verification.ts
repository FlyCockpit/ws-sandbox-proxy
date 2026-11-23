import { createEmailVerificationToken } from "better-auth/api";

import { withVerificationCallback } from "./verification-callback";

/**
 * An admin invitation stays acceptable for a week, like a pool invitation;
 * Better Auth's own verification links (sign-up, sign-in) keep their hour.
 */
export const ADMIN_INVITE_VERIFICATION_TTL_SECONDS = 7 * 24 * 60 * 60;

/**
 * The "Accept invitation" link of the admin invitation mail: Better Auth's own
 * `/verify-email` link for the invited address, bound to the new user, so
 * opening it (which proves control of that mailbox) is the email verification
 * and the invitee's first sign-in is not refused as unverified. The proof
 * write stays Better Auth's: this only mints its signed token, exactly as its
 * `sendVerificationEmail` does, and the link lands on the web verify-email
 * page like every other verification link. Signing in with the temporary
 * password alone never verifies the address: the admin knows that password.
 */
export async function adminInviteAcceptUrl(args: {
  secret: string;
  /** Better Auth's base URL (`BETTER_AUTH_URL`); the handler is under `/api/auth`. */
  authBaseUrl: string;
  /** Web origin on split deployments (`CORS_ORIGIN`). */
  appOrigin?: string;
  userId: string;
  email: string;
  locale: unknown;
}): Promise<string> {
  const token = await createEmailVerificationToken(
    args.secret,
    args.email,
    undefined,
    ADMIN_INVITE_VERIFICATION_TTL_SECONDS,
    { userId: args.userId },
  );
  const url = new URL("/api/auth/verify-email", args.authBaseUrl);
  url.searchParams.set("token", token);
  return withVerificationCallback(url.toString(), args.locale, args.appOrigin);
}
