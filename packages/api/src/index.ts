import { ORPCError, os } from "@orpc/server";
import { TWO_FACTOR_REQUIRED_ERROR_CODE } from "@wssp/auth/two-factor-policy";

import prisma from "@wssp/db";
import { accountDeletionConflictAfterForeignKeyRace } from "@wssp/db/account-deletion";
import { LastAdminError, lockAdminGovernance } from "@wssp/db/admin-governance";
import { withAuthorityChange, withGlobalAuthorityChange } from "@wssp/db/authority";
import type { Context } from "./context";
import { ADMIN_ERROR_CODES } from "./lib/admin-error-codes";
import { assertOwnerDeviceSession } from "./lib/owner-device-session-gate";
import {
  isAdminSessionAuthorized,
  isLiveOwnerSessionAuthorized,
  isSensitiveSessionTwoFactorPolicySatisfied,
} from "./lib/sensitive-session-two-factor-gate";
import { invalidateForceTwoFactorSettingsCache } from "./lib/two-factor-policy";

export {
  getForcedTwoFactorSettingsRecord,
  invalidateForceTwoFactorSettingsCache,
  isForcedTwoFactorEnabledForRole,
  isTwoFactorPolicySatisfied,
} from "./lib/two-factor-policy";

const o = os.$context<Context>();

export const publicProcedure = o;

const requireAuth = o.middleware(async ({ context, next }) => {
  if (!context.session?.user) {
    throw new ORPCError("UNAUTHORIZED");
  }
  return next({
    context: {
      session: context.session,
    },
  });
});

export const authenticatedProcedure = publicProcedure.use(requireAuth);

const requireRequiredTwoFactor = o.middleware(async ({ context, next }) => {
  if (!context.session?.user) {
    throw new ORPCError("UNAUTHORIZED");
  }
  if (!(await isSensitiveSessionTwoFactorPolicySatisfied(context.session.user.id))) {
    throw new ORPCError("FORBIDDEN", {
      message: "Two-factor authentication setup is required.",
      data: { code: TWO_FACTOR_REQUIRED_ERROR_CODE },
    });
  }
  return next({
    context: {
      session: context.session,
    },
  });
});

export const protectedProcedure = authenticatedProcedure.use(requireRequiredTwoFactor);

const requireOwnerDeviceSession = o.middleware(async ({ context, next }) => {
  const session = await assertOwnerDeviceSession(context.session);
  return next({
    context: {
      session,
    },
  });
});

/** Single durable live-owner check for IO fences; no handler or exit check runs here. */
export async function checkLiveOwnerSession(session: Context["session"]): Promise<void> {
  if (!(await isLiveOwnerSessionAuthorized(session))) throw new ORPCError("UNAUTHORIZED");
}

// Sensitive browser authority (including C53 terminal tickets): the durable session row
// must be live and not an impersonation — the cookie cache is not authority.
const requireLiveOwnerSession = o.middleware(async ({ context, next }) => {
  const session = context.session;
  if (!session?.user) throw new ORPCError("UNAUTHORIZED");
  const recheck = () => checkLiveOwnerSession(session);
  await recheck();
  // Exit denial is disclosure-only: a handler may already have committed work.
  // Check rejected exits too, so revocation conceals sensitive errors as well.
  try {
    return await next({ context: { session } });
  } finally {
    await recheck();
  }
});

/** Sensitive owner IO: protected policy plus durable entry and exit liveness. */
export const liveOwnerSessionProcedure = authenticatedProcedure
  .use(requireRequiredTwoFactor)
  .use(requireLiveOwnerSession);

/** Device enrollment retains verified-email policy and live entry/exit authority. */
export const ownerDeviceProcedure = authenticatedProcedure
  .use(requireRequiredTwoFactor)
  .use(requireOwnerDeviceSession)
  .use(requireLiveOwnerSession);

// Every admin surface is hidden, including failed policy and missing-user gates.
const requireAdminOr404 = o.middleware(async ({ context, next }) => {
  const notFound = () => new ORPCError("NOT_FOUND", { message: "Not found" });
  const session = context.session;
  if (!session || !(await isAdminSessionAuthorized(session))) throw notFound();
  const result = await next({ context: { session } });
  // Cross-owner metadata must still be authorized when it leaves the handler.
  if (!(await isAdminSessionAuthorized(session))) throw notFound();
  return result;
});

export const adminOr404Procedure = publicProcedure.use(requireAdminOr404);

/** Which in-process authority tickets the write invalidates: every owner's
 * ("global"), the target owner's ("owner"), or none ("none") for writes that
 * change no existing owner's authority, such as creating a new account. */
type AdminWriteAuthority = "global" | "owner" | "none";

/** DB-only administrative writes: lock policy, reauthorize, then commit together.
 * No handler on this builder may perform network IO; it registers such work with
 * `afterCommit`, which runs only once the transaction has committed. Lock order
 * is governance, actor user, target user; account finalization follows the same order.
 */
function adminWriteMiddleware(authority: AdminWriteAuthority) {
  const ownerScoped = authority === "owner";
  return o.middleware(async ({ context, next }, input: unknown) => {
    const committedEffects: Array<() => Promise<void>> = [];
    const afterCommit = (effect: () => Promise<void>) => {
      committedEffects.push(effect);
    };
    const ownerId =
      typeof input === "object" &&
      input !== null &&
      "userId" in input &&
      typeof input.userId === "string"
        ? input.userId
        : undefined;
    if (ownerScoped && !ownerId) throw new ORPCError("BAD_REQUEST");
    const change = async () => {
      try {
        return await prisma.$transaction(async (tx) => {
          await lockAdminGovernance(tx);
          const session = context.session;
          if (!session?.user) throw new ORPCError("NOT_FOUND");
          await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${session.user.id} FOR SHARE`;
          await tx.$queryRaw`SELECT id FROM "session" WHERE id = ${session.session.id} FOR SHARE`;
          if (!(await isAdminSessionAuthorized(session, { db: tx })))
            throw new ORPCError("NOT_FOUND", { message: "Not found" });
          return next({ context: { session, adminTx: tx, afterCommit } });
        });
      } catch (error) {
        if (
          ownerId &&
          typeof error === "object" &&
          error !== null &&
          "code" in error &&
          error.code === "P2003"
        ) {
          const conflict = await accountDeletionConflictAfterForeignKeyRace(ownerId);
          throw new ORPCError("CONFLICT", {
            message: conflict.message,
            data: { code: ADMIN_ERROR_CODES.accountDeletionBlocked, blockers: conflict.kinds },
          });
        }
        if (error instanceof LastAdminError)
          throw new ORPCError("CONFLICT", {
            message: error.message,
            data: { code: ADMIN_ERROR_CODES.lastAdmin },
          });
        throw error;
      } finally {
        if (authority === "global") invalidateForceTwoFactorSettingsCache();
      }
    };
    const result = await (authority === "none"
      ? change()
      : ownerScoped && ownerId
        ? withAuthorityChange({ ownerId }, change)
        : withGlobalAuthorityChange(change));
    for (const effect of committedEffects) await effect();
    return result;
  });
}
const requireAdminWrite = adminWriteMiddleware("global");
/** The same locked admin reauthorization for writes that only create accounts.
 * Exported for chains that must do non-transactional work (budgets, hashing) before it. */
export const requireAdminAccountCreate = adminWriteMiddleware("none");
const requireAdminUserWrite = adminWriteMiddleware("owner");
export const adminWriteProcedure = adminOr404Procedure.use(requireAdminWrite);
export const adminUserWriteProcedure = adminOr404Procedure.use(requireAdminUserWrite);

// -- authorization registry --------------------------------------------------
//
// `pnpm policy:access-matrix` reads these two objects statically (it parses
// this file; it never imports it) and FAILS on any router procedure whose
// chain starts at a builder, or passes `.use()` a middleware, that is not
// listed here. That is deliberate: an authorization check that exists only
// inline in one router is invisible to the gate and to the next daemon, and
// two hand-written copies of the same check drift. So the rule for auth is
// "register at two, not extract at three" — the second router that needs a
// role check gets an entry here (and a builder above), not a local helper.
// Register a middleware here when a second router needs the same gate.
//
// The level is the *minimum* a caller must hold to get past the gate. The
// access matrix in notes/02-users-and-roles.md is checked against it.

export type ProcedureAccessLevel = "public" | "authenticated" | "admin";

/** Builders a router procedure chain may start from. Keep in sync with the exports above. */
export const procedureAccessLevels = {
  publicProcedure: "public",
  authenticatedProcedure: "authenticated",
  protectedProcedure: "authenticated",
  ownerDeviceProcedure: "authenticated",
  liveOwnerSessionProcedure: "authenticated",
  adminWriteProcedure: "admin",
  adminUserWriteProcedure: "admin",
  adminOr404Procedure: "admin",
} as const satisfies Record<string, ProcedureAccessLevel>;

/** Middleware a router procedure may pass to `.use()`. Custom role helpers register here. */
export const middlewareAccessLevels = {
  requireAuth: "authenticated",
  requireRequiredTwoFactor: "authenticated",
  requireOwnerDeviceSession: "authenticated",
  requireLiveOwnerSession: "authenticated",
  requireAdminWrite: "admin",
  requireAdminAccountCreate: "admin",
  requireAdminUserWrite: "admin",
  requireAdminOr404: "admin",
} as const satisfies Record<string, ProcedureAccessLevel>;
