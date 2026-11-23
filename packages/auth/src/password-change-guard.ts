/**
 * Admin-set temporary password (`User.mustChangePassword`): Better Auth side.
 *
 * The oRPC gates refuse a flagged account everywhere but the password change;
 * this keeps Better Auth's own endpoints in line, so a direct request cannot
 * edit the profile, enroll a second factor, consent an OAuth client or approve
 * a device with the password the administrator knows. Replacing the password
 * must also end every other session (someone may have signed in with the
 * temporary one) and must not reuse it. Only a successful change or reset by
 * the flagged account clears the flag, after Better Auth has written the new
 * password (if clearing fails, the account stays restricted and may change it
 * again).
 */
import prisma from "@wssp/db";
import { APIError, isAPIError } from "better-auth/api";

import { hasSessionCookies } from "./terminal-proof";
import { PASSWORD_CHANGE_REQUIRED_ERROR_CODE } from "./two-factor-policy";

type Identity = { user: { id: string }; session: { id: string } };
type ResolveSession = (headers: Headers) => Promise<Identity | null>;

/** The part of Better Auth's hook context the guard reads. */
export type PasswordChangeGuardContext = {
  path: string;
  body?: unknown;
  query?: Record<string, unknown> | undefined;
  headers?: Headers | undefined;
  request?: Request | undefined;
  context: {
    internalAdapter: {
      findCredentialAccount(userId: string): Promise<{ password?: string | null } | null>;
      findVerificationValue(identifier: string): Promise<{ value: string } | null>;
    };
    password: { verify(input: { hash: string; password: string }): Promise<boolean> };
    /** The endpoint's result, in the after hook. */
    returned?: unknown;
  };
};

/** What a before hook returns to replace the request body. */
export type PasswordChangeGuardResult = { context: { body: Record<string, unknown> } } | undefined;

/**
 * Better Auth paths a flagged session may still use: reading and ending
 * sessions, signing in again, mailbox proof and password recovery, and the
 * password change itself. Everything else is refused for a flagged session,
 * including the second-factor endpoints: with a session they enroll a factor
 * (email OTP), and the sign-in challenge they also serve carries no session.
 */
const OPEN_PATHS = new Set([
  "/get-session",
  "/sign-out",
  "/change-password",
  "/list-sessions",
  "/revoke-session",
  "/revoke-sessions",
  "/revoke-other-sessions",
  "/verify-email",
  "/send-verification-email",
  "/request-password-reset",
  "/reset-password",
  "/ok",
  "/error",
]);
const OPEN_PREFIXES = ["/sign-in/", "/sign-up/", "/reset-password/"];

export function isOpenDuringPasswordChange(path: string): boolean {
  return OPEN_PATHS.has(path) || OPEN_PREFIXES.some((prefix) => path.startsWith(prefix));
}

const refused = () =>
  new APIError("FORBIDDEN", {
    message: "Choose a new password first.",
    code: PASSWORD_CHANGE_REQUIRED_ERROR_CODE,
  });

const reused = () =>
  new APIError("BAD_REQUEST", {
    message: "Choose a password different from the temporary one.",
    code: "PASSWORD_REUSED",
  });

async function mustChangePassword(userId: string): Promise<boolean> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { mustChangePassword: true },
  });
  return user?.mustChangePassword === true;
}

/**
 * `before` runs inside the global Better Auth `hooks.before`; its result (a
 * replaced body for the flagged password change) must be returned from that
 * hook. `after` runs inside `hooks.after` and clears the flag once a flagged
 * change or reset succeeded. Dispatch keeps `ctx.context` across both.
 */
export function createPasswordChangeGuard(resolveSession: ResolveSession) {
  const replacing = new WeakMap<object, string>();
  const before = async (ctx: PasswordChangeGuardContext): Promise<PasswordChangeGuardResult> => {
    const body = (ctx.body ?? {}) as Record<string, unknown>;
    const newPassword = typeof body.newPassword === "string" ? body.newPassword : null;
    const currentHash = async (userId: string) =>
      (await ctx.context.internalAdapter.findCredentialAccount(userId))?.password ?? null;
    const isReuse = async (userId: string) => {
      const hash = await currentHash(userId);
      return Boolean(
        newPassword && hash && (await ctx.context.password.verify({ hash, password: newPassword })),
      );
    };

    // Reset by email: the token names the user. Sessions are revoked by
    // `revokeSessionsOnPasswordReset`; the temporary password stays refused.
    if (ctx.path === "/reset-password") {
      // Exactly Better Auth's own choice: a non-empty body token, else the query's.
      const token = (typeof body.token === "string" && body.token) || ctx.query?.token;
      if (typeof token !== "string" || !token) return;
      const verification = await ctx.context.internalAdapter.findVerificationValue(
        `reset-password:${token}`,
      );
      const userId = verification?.value;
      if (!userId || !(await mustChangePassword(userId))) return;
      if (await isReuse(userId)) throw reused();
      replacing.set(ctx.context, userId);
      return;
    }

    const headers = new Headers(ctx.headers ?? ctx.request?.headers);
    if (!hasSessionCookies(headers)) return;
    const open = isOpenDuringPasswordChange(ctx.path);
    if (open && ctx.path !== "/change-password") return;
    let session: Identity | null;
    try {
      session = await resolveSession(headers);
    } catch {
      session = null;
    }
    if (!session || !(await mustChangePassword(session.user.id))) return;
    if (!open) throw refused();
    // The flagged password change: a new password, and every other session
    // (whoever used the temporary password) ends, whatever the client asked.
    if (await isReuse(session.user.id)) throw reused();
    replacing.set(ctx.context, session.user.id);
    return { context: { body: { ...body, revokeOtherSessions: true } } };
  };
  const after = async (ctx: PasswordChangeGuardContext): Promise<void> => {
    if (ctx.path !== "/change-password" && ctx.path !== "/reset-password") return;
    const userId = replacing.get(ctx.context);
    replacing.delete(ctx.context);
    if (!userId) return;
    // Only the endpoint's own success result proves the password was written:
    // any error (a validation failure is better-call's base APIError, not
    // Better Auth's subclass) or other shape keeps the flag.
    const returned: unknown = ctx.context.returned;
    if (isAPIError(returned) || !returned || typeof returned !== "object") return;
    const written =
      ctx.path === "/reset-password"
        ? "status" in returned && returned.status === true
        : "user" in returned &&
          typeof returned.user === "object" &&
          returned.user !== null &&
          "id" in returned.user &&
          returned.user.id === userId;
    if (!written) return;
    await prisma.user.updateMany({
      where: { id: userId, mustChangePassword: true },
      data: { mustChangePassword: false },
    });
  };
  return { before, after };
}
