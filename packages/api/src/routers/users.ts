import { randomBytes } from "node:crypto";
import { ORPCError, os } from "@orpc/server";
import { auth } from "@wssp/auth";
import {
  ADMIN_INVITE_VERIFICATION_TTL_SECONDS,
  adminInviteAcceptUrl,
} from "@wssp/auth/admin-invite-verification";
import { SUPPORTED_LOCALES } from "@wssp/config/locales";
import prisma, { type Prisma } from "@wssp/db";
import {
  AccountDeletionConflictError,
  deleteAccountInTransaction,
} from "@wssp/db/account-deletion";
import { assertAdminRemains } from "@wssp/db/admin-governance";
import { env } from "@wssp/env/server";
import { renderInviteUser, sendEmail } from "@wssp/mailer";
import { z } from "zod";

import type { Context } from "../context";
import { adminOr404Procedure, adminUserWriteProcedure, requireAdminAccountCreate } from "../index";
import { ADMIN_ERROR_CODES } from "../lib/admin-error-codes";
import { cursorPage, cursorPageInput, pageTake, withCursor } from "../lib/pagination";
import { isPrismaUniqueViolation } from "../lib/prisma-errors";
import { createProcedureBudget } from "../lib/procedure-budget";

// Roles surfaced in the admin UI. Better-auth itself stores `role` as a free-
// form string (and supports comma-separated lists), but the admin dashboard
// only ever assigns one of these two — anything else came from custom code or
// a database edit and we leave it untouched.
const ASSIGNABLE_ROLES = ["user", "admin"] as const;
const assignableRoleSchema = z.enum(ASSIGNABLE_ROLES);

const adminString = z.string().refine((value) => !value.includes("\0"), "NUL is not allowed");
const adminUserId = adminString.min(1).max(64);
const userIdInput = z.object({ userId: adminUserId });

const userNotFound = () =>
  new ORPCError("NOT_FOUND", {
    message: "User not found",
    data: { code: ADMIN_ERROR_CODES.userNotFound },
  });

const userStatusFilter = z.enum(["all", "active", "archived"]);

function generateTempPassword(): string {
  // 24 url-safe bytes → ~32 chars. Long enough to satisfy any reasonable
  // strength check; short enough to read from an email.
  return randomBytes(24).toString("base64url");
}

/**
 * One invitation is one point: a password hash, two rows and an email. 30 per
 * actor per hour covers onboarding a team in one sitting, while the `/rpc`
 * limiter alone (100 batched requests of 10 procedures a minute) would allow
 * ~1,000 an admin per minute. Fail-closed: this budget meters mail and writes.
 */
const consumeInviteBudget = createProcedureBudget({
  keyPrefix: "rl:users-invite-mail",
  points: 30,
  durationSeconds: 3600,
  failClosed: true,
  overBudgetMessage: (retryAfterSeconds) =>
    `Too many invitations. Try again in ${retryAfterSeconds}s.`,
  unavailableMessage: "Invitations are temporarily unavailable. Please try again in a moment.",
  unavailableLog: "[users.invite] invitation budget unavailable, failing closed:",
});

const inviteInput = z.object({
  email: adminString.max(254).email().toLowerCase(),
  name: adminString.trim().min(1).max(100),
  role: assignableRoleSchema.default("user"),
  // The invitee's language, picked by the admin (the form defaults it to the
  // admin's own). Saved as `User.locale` in the same insert, so the invite
  // mail, the accept landing page and every later mail use it.
  locale: z.enum(SUPPORTED_LOCALES),
});

// Runs after the admin entry gate and before the write transaction, so the
// budget's Redis IO and the slow password hash never hold the governance lock.
const prepareInvite = os
  .$context<Context & { session: NonNullable<Context["session"]> }>()
  .middleware(async ({ context, next }) => {
    await consumeInviteBudget(`user:${context.session.user.id}`);
    const tempPassword = generateTempPassword();
    const passwordHash = await (await auth.$context).password.hash(tempPassword);
    return next({ context: { invite: { tempPassword, passwordHash } } });
  });

const USER_SELECT = {
  id: true,
  email: true,
  name: true,
  role: true,
  emailVerified: true,
  createdViaPoolInviteBy: true,
  createdViaPoolInviteId: true,
  banned: true,
  banReason: true,
  banExpires: true,
  twoFactorEnabled: true,
  image: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.UserSelect;

/** Live CLI logins and their instances per user, for one bounded page of users. */
async function cliLoginCounts(
  userIds: readonly string[],
): Promise<Map<string, { logins: number; instances: number }>> {
  const counts = new Map<string, { logins: number; instances: number }>();
  if (userIds.length === 0) return counts;
  const [logins, instances] = await Promise.all([
    prisma.credential.groupBy({
      by: ["userId"],
      where: { userId: { in: [...userIds] }, deletedAt: null },
      _count: { _all: true },
    }),
    prisma.credentialInstance.groupBy({
      by: ["userId"],
      where: { userId: { in: [...userIds] } },
      _count: { _all: true },
    }),
  ]);
  for (const row of logins) counts.set(row.userId, { logins: row._count._all, instances: 0 });
  for (const row of instances) {
    const entry = counts.get(row.userId) ?? { logins: 0, instances: 0 };
    counts.set(row.userId, { ...entry, instances: row._count._all });
  }
  return counts;
}

export const usersRouter = {
  list: adminOr404Procedure
    .input(
      cursorPageInput
        .extend({
          limit: z.number().int().min(1).max(100).default(50),
          search: adminString.trim().max(200).optional(),
          status: userStatusFilter.default("all"),
        })
        .optional(),
    )
    .handler(async ({ input }) => {
      const limit = input?.limit ?? 50;
      const cursor = input?.cursor;
      const search = input?.search;
      const status = input?.status ?? "all";
      // Status is filtered in the database, not on the client: filtering
      // already-paginated pages makes both the empty state and the "load more"
      // affordance lie (an all-archived first page under the "active" tab would
      // look empty even though later pages hold active users). `banned` is a
      // nullable Boolean, so "active" must match both `false` and NULL.
      const searchWhere: Prisma.UserWhereInput | undefined = search
        ? {
            OR: [
              { email: { contains: search, mode: "insensitive" as const } },
              { name: { contains: search, mode: "insensitive" as const } },
            ],
          }
        : undefined;
      const statusWhere: Prisma.UserWhereInput | undefined =
        status === "active"
          ? { OR: [{ banned: false }, { banned: null }] }
          : status === "archived"
            ? { banned: true }
            : undefined;
      // Narrowed (not just filtered): `withCursor` ANDs this into an array,
      // where an `undefined` union member would fail typecheck.
      const conditions = [statusWhere, searchWhere].filter(
        (c): c is Prisma.UserWhereInput => c !== undefined,
      );
      const where: Prisma.UserWhereInput =
        conditions.length > 1 ? { AND: conditions } : (conditions[0] ?? {});
      // Cursor (keyset) pagination: no `skip` scan, no per-page `count()`.
      // The admin UI consumes this as an infinite list (LoadMore), so the
      // header total is dropped — it cost a full filtered count per page for
      // a "showing N" nicety. Tie-break on the unique id: `createdAt` alone
      // is not a stable sort key, so two users created in the same
      // millisecond could repeat or vanish across pages.
      const rows = await prisma.user.findMany({
        // The status/search `where` stays the first `AND` member; the keyset
        // narrows it, it never replaces it.
        where: withCursor(where, "createdAt", cursor, "desc"),
        orderBy: [{ createdAt: "desc" }, { id: "desc" }],
        take: pageTake(limit),
        select: USER_SELECT,
      });
      const page = cursorPage(rows, limit, "createdAt");
      // Per-user CLI-login counts (metadata only: never a name or value).
      const cliLogins = await cliLoginCounts(page.items.map((user) => user.id));
      return {
        users: page.items.map((user) => ({
          ...user,
          cliLogins: cliLogins.get(user.id) ?? { logins: 0, instances: 0 },
        })),
        nextCursor: page.nextCursor,
      };
    }),

  // access:audited prepareInvite — per-actor spend budget and password hashing before the admin write transaction; requireAdminAccountCreate is the gate
  invite: adminOr404Procedure
    .input(inviteInput)
    .use(prepareInvite)
    .use(requireAdminAccountCreate)
    .handler(async ({ input, context }) => {
      const tx = context.adminTx;
      const { tempPassword, passwordHash } = context.invite;
      const conflict = () =>
        new ORPCError("CONFLICT", {
          message: "A user with that email already exists.",
          data: { code: ADMIN_ERROR_CODES.emailTaken },
        });
      if (await tx.user.findUnique({ where: { email: input.email }, select: { id: true } }))
        throw conflict();
      // Written in the governance transaction (not via `auth.api.createUser`,
      // which commits on its own connection) so the actor's reauthorization
      // and the new account commit atomically. Mirrors Better Auth's admin
      // createUser: an unverified user plus a `credential` account.
      let created: { id: string };
      try {
        created = await tx.user.create({
          // The temporary password is known to the admin: the invitee must
          // replace it before anything else (`mustChangePassword` gate).
          data: {
            email: input.email,
            name: input.name,
            role: input.role,
            locale: input.locale,
            mustChangePassword: true,
          },
          select: { id: true },
        });
      } catch (error) {
        if (isPrismaUniqueViolation(error)) throw conflict();
        throw error;
      }
      await tx.account.create({
        data: {
          userId: created.id,
          accountId: created.id,
          providerId: "credential",
          password: passwordHash,
        },
        select: { id: true },
      });

      const result = { userId: created.id, tempPassword, emailSent: false };
      // Email send is best-effort: if SMTP is not configured (or fails) the
      // admin still gets the temp password to share out of band. It runs
      // only after commit, so a refused or rolled-back invite never mails.
      context.afterCommit(async () => {
        try {
          const { subject, html } = renderInviteUser({
            name: input.name,
            email: input.email,
            tempPassword,
            // Accepting (opening the mailed link) verifies the invited
            // address through Better Auth's own verify-email endpoint, then
            // lands on the web verify-email page under the invitee's locale
            // (the web origin, CORS_ORIGIN on split deployments). This is the
            // invitee's only mail: the insert above is not a Better Auth
            // sign-up, so no "verify your email" mail goes out. Only a sign-in
            // before accepting (or after the link expired) gets Better Auth's
            // resend (`sendOnSignIn`), which is the way back in.
            acceptUrl: await adminInviteAcceptUrl({
              secret: env.BETTER_AUTH_SECRET,
              authBaseUrl: env.BETTER_AUTH_URL,
              appOrigin: env.CORS_ORIGIN,
              userId: created.id,
              email: input.email,
              locale: input.locale,
            }),
            expiresInDays: ADMIN_INVITE_VERIFICATION_TTL_SECONDS / (24 * 60 * 60),
            locale: input.locale,
          });
          await sendEmail({ to: input.email, subject, html });
          // The middleware returns this same object after its effects run.
          result.emailSent = true;
        } catch {
          console.warn("[users.invite] failed to send invite email");
        }
      });
      return result;
    }),

  setRole: adminUserWriteProcedure
    .input(
      z.object({
        userId: adminUserId,
        role: assignableRoleSchema,
      }),
    )
    .handler(async ({ input, context }) => {
      // Don't let an admin demote themselves — if they're the only admin
      // they'd lock themselves (and everyone) out of /admin.
      if (input.userId === context.session.user.id && input.role !== "admin") {
        throw new ORPCError("FORBIDDEN", {
          message: "You cannot remove your own admin role.",
          data: { code: ADMIN_ERROR_CODES.selfDemotion },
        });
      }
      const target = await context.adminTx.user.findUnique({
        where: { id: input.userId },
        select: { id: true, role: true },
      });
      if (!target) throw userNotFound();

      if (input.role !== "admin") await assertAdminRemains(context.adminTx, input.userId);
      await context.adminTx.user.update({
        where: { id: input.userId },
        data: { role: input.role },
        select: { id: true },
      });
      if (target.role !== input.role) {
        context.afterCommit(async () => {
          console.info({
            event: "users.role_changed",
            actorId: context.session.user.id,
            userId: input.userId,
            previousRole: target.role,
            role: input.role,
          });
        });
      }
      return { success: true };
    }),

  /** Image store quota overrides for one account (null: deployment ceiling). */
  imageQuota: adminOr404Procedure.input(userIdInput).handler(async ({ input }) => {
    const row = await prisma.accountImagePolicy.findUnique({
      where: { userId: input.userId },
      select: {
        adminStoredGiBMax: true,
        adminDownloadsPerHourMax: true,
        adminConcurrentBuildsMax: true,
        adminBuildMinutesPerMonthMax: true,
        adminOffloadGiBMax: true,
        adminUpdatedAt: true,
      },
    });
    return {
      storedGiBMax: row?.adminStoredGiBMax ?? null,
      downloadsPerHourMax: row?.adminDownloadsPerHourMax ?? null,
      concurrentBuildsMax: row?.adminConcurrentBuildsMax ?? null,
      buildMinutesPerMonthMax: row?.adminBuildMinutesPerMonthMax ?? null,
      offloadGiBMax: row?.adminOffloadGiBMax ?? null,
      updatedAt: row?.adminUpdatedAt ?? null,
    };
  }),

  /** Overrides only lower the deployment ceiling; enforcement takes the minimum. */
  setImageQuota: adminUserWriteProcedure
    .input(
      z.object({
        userId: adminUserId,
        storedGiBMax: z.number().int().min(0).max(1_048_576).nullable(),
        downloadsPerHourMax: z.number().int().min(0).max(100_000).nullable(),
        /** Template builds (§7); omitted keeps the current override. */
        concurrentBuildsMax: z.number().int().min(0).max(1_000).nullable().optional(),
        buildMinutesPerMonthMax: z.number().int().min(0).max(1_000_000).nullable().optional(),
        /** Stored offloaded disks; omitted keeps the current override. */
        offloadGiBMax: z.number().int().min(0).max(1_048_576).nullable().optional(),
      }),
    )
    .handler(async ({ input, context }) => {
      const target = await context.adminTx.user.findUnique({
        where: { id: input.userId },
        select: { id: true },
      });
      if (!target) throw userNotFound();
      const admin = {
        adminStoredGiBMax: input.storedGiBMax,
        adminDownloadsPerHourMax: input.downloadsPerHourMax,
        ...(input.concurrentBuildsMax !== undefined
          ? { adminConcurrentBuildsMax: input.concurrentBuildsMax }
          : {}),
        ...(input.buildMinutesPerMonthMax !== undefined
          ? { adminBuildMinutesPerMonthMax: input.buildMinutesPerMonthMax }
          : {}),
        ...(input.offloadGiBMax !== undefined ? { adminOffloadGiBMax: input.offloadGiBMax } : {}),
        adminUpdatedAt: new Date(),
        adminUpdatedBy: context.session.user.id,
      };
      await context.adminTx.accountImagePolicy.upsert({
        where: { userId: input.userId },
        create: { userId: input.userId, ...admin },
        update: admin,
        select: { userId: true },
      });
      return { success: true };
    }),

  archive: adminUserWriteProcedure
    .input(
      z.object({
        userId: adminUserId,
        reason: adminString.trim().max(500).optional(),
      }),
    )
    .handler(async ({ input, context }) => {
      if (input.userId === context.session.user.id) {
        throw new ORPCError("FORBIDDEN", {
          message: "You cannot archive your own account.",
          data: { code: ADMIN_ERROR_CODES.selfArchive },
        });
      }
      const target = await context.adminTx.user.findUnique({
        where: { id: input.userId },
        select: { id: true },
      });
      if (!target) throw userNotFound();

      // C21 cleanup: the builder fences all authority before IO and notifies
      // the relay after commit. Durable ban + session deletion reject offline
      // reconnection as well. No VM commands or credential resurrection.
      await assertAdminRemains(context.adminTx, input.userId);
      await context.adminTx.user.update({
        where: { id: input.userId },
        data: { banned: true, banReason: input.reason ?? null, banExpires: null },
        select: { id: true },
      });
      await context.adminTx.session.deleteMany({ where: { userId: input.userId } });
      return { success: true };
    }),

  unarchive: adminUserWriteProcedure.input(userIdInput).handler(async ({ input, context }) => {
    const target = await context.adminTx.user.findUnique({
      where: { id: input.userId, deletionRequestedAt: null },
      select: { id: true },
    });
    if (!target) throw userNotFound();

    // Lifts the ban only. If you add a standing credential that `archive`
    // revokes, do NOT flip it back on from here: the row records that a
    // credential IS revoked, not who revoked it, so a blanket re-enable would
    // also resurrect one an admin had deliberately killed earlier (a leaked
    // key, a decommissioned integration). Restoring precisely needs a column
    // recording that archive was the revoker.
    await context.adminTx.user.update({
      where: { id: input.userId, deletionRequestedAt: null },
      data: { banned: false, banReason: null, banExpires: null },
      select: { id: true },
    });
    return { success: true };
  }),

  remove: adminUserWriteProcedure.input(userIdInput).handler(async ({ input, context }) => {
    if (input.userId === context.session.user.id) {
      throw new ORPCError("FORBIDDEN", {
        message: "You cannot delete your own account.",
        data: { code: ADMIN_ERROR_CODES.selfDelete },
      });
    }
    const target = await context.adminTx.user.findUnique({
      where: { id: input.userId },
      select: { id: true },
    });
    if (!target) throw userNotFound();

    try {
      const deleted = await deleteAccountInTransaction(context.adminTx, input.userId);
      return { success: deleted };
    } catch (error) {
      if (error instanceof AccountDeletionConflictError) {
        throw new ORPCError("CONFLICT", {
          message: error.message,
          data: { code: ADMIN_ERROR_CODES.accountDeletionBlocked, blockers: error.kinds },
        });
      }
      throw error;
    }
  }),
};
