import {
  ACCOUNT_DELETION_BLOCKER_KINDS,
  type AccountDeletionBlocker,
  ADMIN_ERROR_CODES,
} from "@wssp/api/lib/admin-error-codes";

/**
 * What went wrong with an admin action, keyed on the `data.code` the admin
 * procedures attach (never on English message text). Each problem has its own
 * translated explanation under `admin:problems`.
 */
export type AdminProblem =
  | { kind: "selfDemotion" }
  | { kind: "selfArchive" }
  | { kind: "selfDelete" }
  | { kind: "lastAdmin" }
  | { kind: "userNotFound" }
  | { kind: "emailTaken" }
  | { kind: "inviteRefused" }
  | { kind: "ownTwoFactorRequired" }
  | { kind: "signupEmailRequired" }
  /** Live resources refuse deletion; the account and everything it owns is kept. */
  | { kind: "deletionBlocked"; blockers: AccountDeletionBlocker[] }
  /** Resources changed while the deletion ran and none block now: retry. */
  | { kind: "deletionChanged" }
  /** A bare NOT_FOUND: the acting admin's own access is gone (hidden gate). */
  | { kind: "accessLost" }
  | { kind: "invalid" }
  | { kind: "rateLimited" }
  | { kind: "generic" };

type ErrorShape = { code?: unknown; status?: unknown; data?: unknown };

function shapeOf(error: unknown): ErrorShape {
  return (error && typeof error === "object" ? error : {}) as ErrorShape;
}

function dataOf(error: unknown): { code?: unknown; blockers?: unknown } {
  const data = shapeOf(error).data;
  return data && typeof data === "object" ? (data as { code?: unknown; blockers?: unknown }) : {};
}

function isBlocker(value: unknown): value is AccountDeletionBlocker {
  return (ACCOUNT_DELETION_BLOCKER_KINDS as readonly unknown[]).includes(value);
}

export function adminProblem(error: unknown): AdminProblem {
  const shape = shapeOf(error);
  const data = dataOf(error);
  switch (data.code) {
    case ADMIN_ERROR_CODES.selfDemotion:
      return { kind: "selfDemotion" };
    case ADMIN_ERROR_CODES.selfArchive:
      return { kind: "selfArchive" };
    case ADMIN_ERROR_CODES.selfDelete:
      return { kind: "selfDelete" };
    case ADMIN_ERROR_CODES.lastAdmin:
      return { kind: "lastAdmin" };
    case ADMIN_ERROR_CODES.userNotFound:
      return { kind: "userNotFound" };
    case ADMIN_ERROR_CODES.emailTaken:
      return { kind: "emailTaken" };
    case ADMIN_ERROR_CODES.inviteRefused:
      return { kind: "inviteRefused" };
    case ADMIN_ERROR_CODES.ownTwoFactorRequired:
      return { kind: "ownTwoFactorRequired" };
    case ADMIN_ERROR_CODES.signupEmailRequired:
      return { kind: "signupEmailRequired" };
    case ADMIN_ERROR_CODES.accountDeletionBlocked: {
      // Unknown kinds are dropped rather than rendered raw; an empty list means
      // the set changed under the deletion and a retry is the right next step.
      const blockers = Array.isArray(data.blockers) ? data.blockers.filter(isBlocker) : [];
      return blockers.length > 0
        ? { kind: "deletionBlocked", blockers: [...new Set(blockers)] }
        : { kind: "deletionChanged" };
    }
  }
  if (shape.code === "NOT_FOUND" || shape.status === 404) return { kind: "accessLost" };
  if (shape.code === "BAD_REQUEST" || shape.status === 400) return { kind: "invalid" };
  if (shape.code === "TOO_MANY_REQUESTS" || shape.status === 429) return { kind: "rateLimited" };
  return { kind: "generic" };
}

/** Translation key (in the `admin` namespace) that explains a problem. */
export function adminProblemKey(problem: AdminProblem): `problems.${AdminProblem["kind"]}` {
  return `problems.${problem.kind}`;
}
