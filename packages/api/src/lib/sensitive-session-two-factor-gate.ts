import { isUserBanned } from "@wssp/auth/ban";
import { isAdminRole } from "@wssp/auth/roles";
import {
  forcedTwoFactorSettingKeyForRole,
  isForcedTwoFactorEnabled,
  isTwoFactorRequirementSatisfied,
  type TwoFactorPolicyUser,
} from "@wssp/auth/two-factor-policy";
import prisma, { type Prisma } from "@wssp/db";

import { getForcedTwoFactorSettingsRecord, isTwoFactorPolicySatisfied } from "./two-factor-policy";

/** Fields load-bearing for forced-2FA and admin session gates — always read from Postgres. */
export const sensitiveSessionGateUserSelect = {
  twoFactorEnabled: true,
  role: true,
  emailVerified: true,
  banned: true,
  banExpires: true,
  createdAt: true,
  deletionRequestedAt: true,
  mustChangePassword: true,
} satisfies Prisma.UserSelect;

export type SensitiveSessionGateUser = Prisma.UserGetPayload<{
  select: typeof sensitiveSessionGateUserSelect;
}>;

export async function loadSensitiveSessionGateUser(
  userId: string,
  db: Pick<Prisma.TransactionClient, "user"> = prisma,
): Promise<SensitiveSessionGateUser | null> {
  return db.user.findUnique({
    where: { id: userId },
    select: sensitiveSessionGateUserSelect,
  });
}

/** Why a sensitive browser session is refused; `null` when it may proceed. */
type SensitiveSessionRefusal = "inactive" | "password_change_required" | "two_factor_required";

/**
 * Authoritative decision for sensitive browser procedures and admin gates:
 * an active account, no pending admin-set temporary password, and the role's
 * forced-2FA policy. Better Auth's cookie cache can lag `twoFactorEnabled`
 * (and related fields); non-sensitive procedures may keep using the cached
 * session user. The password change comes first: enrolling a second factor
 * needs the account's own password, and an admin-set one is not that.
 */
export async function sensitiveSessionRefusal(
  sessionUserId: string,
  now = new Date(),
): Promise<SensitiveSessionRefusal | null> {
  const user = await loadSensitiveSessionGateUser(sessionUserId);
  if (!user || user.deletionRequestedAt != null || isUserBanned(user, now)) return "inactive";
  if (user.mustChangePassword) return "password_change_required";
  return (await isTwoFactorPolicySatisfied(user satisfies TwoFactorPolicyUser & { role?: unknown }))
    ? null
    : "two_factor_required";
}

/** {@link sensitiveSessionRefusal} as a yes/no, for gates with one refusal shape. */
export async function isSensitiveSessionTwoFactorPolicySatisfied(
  sessionUserId: string,
  now = new Date(),
): Promise<boolean> {
  return (await sensitiveSessionRefusal(sessionUserId, now)) === null;
}

export type AdminSessionGateSnapshot = {
  emailVerified: boolean;
  isAdmin: boolean;
  /** An admin-set temporary password is still pending replacement. */
  passwordChangeRequired: boolean;
  twoFactorPolicySatisfied: boolean;
};

/** Same authoritative user row as {@link isSensitiveSessionTwoFactorPolicySatisfied}. */
export async function loadAdminSessionGateSnapshot(
  sessionUserId: string,
  now = new Date(),
  db?: Pick<Prisma.TransactionClient, "user" | "appSetting">,
): Promise<AdminSessionGateSnapshot | null> {
  const user = await loadSensitiveSessionGateUser(sessionUserId, db);
  if (!user || user.deletionRequestedAt != null || isUserBanned(user, now)) {
    return null;
  }
  return {
    emailVerified: user.emailVerified,
    isAdmin: isAdminRole(user.role),
    passwordChangeRequired: user.mustChangePassword,
    twoFactorPolicySatisfied: db
      ? isTwoFactorRequirementSatisfied(
          user,
          isForcedTwoFactorEnabled(
            forcedTwoFactorSettingKeyForRole(user.role),
            (await getForcedTwoFactorSettingsRecord(db))[
              forcedTwoFactorSettingKeyForRole(user.role)
            ],
          ),
          now.getTime(),
        )
      : await isTwoFactorPolicySatisfied(user satisfies TwoFactorPolicyUser & { role?: unknown }),
  };
}

/** Cookie cache is not session authority: revocation and expiry apply immediately. */
export async function isAdminSessionActive(
  session: { user: { id: string }; session: { id: string } },
  db: Pick<Prisma.TransactionClient, "session"> = prisma,
): Promise<boolean> {
  if (!session.session?.id) return false;
  return Boolean(
    await db.session.findUnique({
      where: {
        id: session.session.id,
        userId: session.user.id,
        expiresAt: { gt: new Date() },
        impersonatedBy: null,
      },
      select: { id: true },
    }),
  );
}

/**
 * The durable session row behind a (possibly cookie-cached) session: exists,
 * belongs to the user and is unexpired. Unlike {@link isAdminSessionActive} an
 * admin impersonation passes; `protectedProcedure` keeps that behaviour.
 */
export async function isSessionRowLive(
  session: { user: { id: string }; session?: { id?: string } | null },
  db: Pick<Prisma.TransactionClient, "session"> = prisma,
): Promise<boolean> {
  const id = session.session?.id;
  if (!id) return false;
  return Boolean(
    await db.session.findUnique({
      where: { id, userId: session.user.id, expiresAt: { gt: new Date() } },
      select: { id: true },
    }),
  );
}

export type AdminGateSession = { user: { id: string }; session: { id: string } };

/**
 * THE live-owner-session gate for long-lived browser authority (C53 browser
 * terminal: ticket mint, WebSocket upgrade, post-upgrade re-read and every
 * heartbeat). The cookie cache is not authority: it requires the durable
 * session row to exist, belong to the user, be unexpired and not be an admin
 * impersonation (admins never get terminal authority over another owner), plus
 * the same authoritative ban / deletion / forced-2FA policy as
 * `protectedProcedure`.
 */
export async function isLiveOwnerSessionAuthorized(
  session: AdminGateSession | null | undefined,
  now = new Date(),
): Promise<boolean> {
  if (!session?.user?.id || !session.session?.id) return false;
  if (!(await isAdminSessionActive(session))) return false;
  return isSensitiveSessionTwoFactorPolicySatisfied(session.user.id, now);
}

/**
 * THE administrator gate. Every surface that decides "may this session see the
 * admin area" calls this one function, so they cannot disagree: the oRPC
 * `adminOr404Procedure` (entry and return), the admin write transaction, the
 * Hono API-reference gate, and the web `/admin` route guard. A `false` is
 * always rendered as a plain not-found by the caller, never as "access denied".
 *
 * Requires a live, non-impersonated, unexpired durable session row, and an
 * authoritative user row that is not banned or deleting, has a verified email,
 * the admin role, no pending admin-set temporary password, and satisfies the
 * role's forced-2FA policy. Pass `db` inside
 * a transaction so the check reads the rows the transaction has locked.
 * `pnpm test` inventories call sites of the two primitives below; add new
 * consumers here, not beside them.
 */
export async function isAdminSessionAuthorized(
  session: AdminGateSession | null | undefined,
  options: {
    now?: Date;
    db?: Pick<Prisma.TransactionClient, "session" | "user" | "appSetting">;
  } = {},
): Promise<boolean> {
  if (!session?.user?.id || !session.session?.id) return false;
  const decide = async (db: Pick<Prisma.TransactionClient, "session" | "user" | "appSetting">) => {
    if (!(await isAdminSessionActive(session, db))) return false;
    const gate = await loadAdminSessionGateSnapshot(session.user.id, options.now ?? new Date(), db);
    return Boolean(
      gate?.emailVerified &&
        gate.isAdmin &&
        !gate.passwordChangeRequired &&
        gate.twoFactorPolicySatisfied,
    );
  };
  // Callers passing `db` already hold these row locks. Otherwise the separate
  // session and user reads would let a revocation or demotion commit between
  // them and still be accepted; share locks make the decision atomic (same
  // user-then-session order as the admin write transaction).
  if (options.db) return decide(options.db);
  return prisma.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${session.user.id} FOR SHARE`;
    await tx.$queryRaw`SELECT id FROM "session" WHERE id = ${session.session.id} FOR SHARE`;
    return decide(tx);
  });
}

/**
 * THE account-level administrator check, for authority decided without a
 * browser session: the webhook private-destination allowlist under
 * `WEBHOOK_PRIVATE_ALLOWLIST_SCOPE=admins`, checked when an endpoint is
 * created or updated (browser or SDK key) and again in every delivery claim
 * (worker, no session at all). Same authoritative user-row policy as
 * {@link isAdminSessionAuthorized} minus the session row: not banned, not
 * deleting, verified email, admin role and the role's forced-2FA policy. A
 * demoted, banned or unverified admin loses private delivery on the next
 * attempt. Pass `db` inside a transaction. Call sites are inventoried by
 * `admin-session-authorization.test.ts`.
 */
export async function isAdminAccountAuthorized(
  userId: string,
  options: { now?: Date; db?: Pick<Prisma.TransactionClient, "user" | "appSetting"> } = {},
): Promise<boolean> {
  const gate = await loadAdminSessionGateSnapshot(
    userId,
    options.now ?? new Date(),
    options.db ?? prisma,
  );
  return Boolean(
    gate?.emailVerified &&
      gate.isAdmin &&
      !gate.passwordChangeRequired &&
      gate.twoFactorPolicySatisfied,
  );
}
