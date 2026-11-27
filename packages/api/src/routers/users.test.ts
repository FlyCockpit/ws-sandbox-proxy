vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { createRouterClient, ORPCError } from "@orpc/server";
import type { Session } from "@wssp/auth";
import type { MockInstance } from "vitest";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Context } from "../context";
import { usersRouter } from "./users";

// Mock @wssp/db before importing the module so the router pulls the deep-
// mocked Prisma client.
vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});

const deleteAccountInTransaction = vi.hoisted(() => vi.fn());
vi.mock("@wssp/db/account-deletion", async () => {
  class AccountDeletionConflictError extends Error {
    kinds: string[];
    constructor(kinds: string[]) {
      super(`blocked: ${kinds.join(",")}`);
      this.kinds = kinds;
    }
  }
  return { AccountDeletionConflictError, deleteAccountInTransaction };
});

const envMock = vi.hoisted(() => ({
  BETTER_AUTH_URL: "http://localhost:3000",
  BETTER_AUTH_SECRET: "users-test-secret-long-enough-for-hs256",
  CORS_ORIGIN: undefined as string | undefined,
}));
vi.mock("@wssp/env/server", () => ({
  env: envMock,
  ADMIN_EMAILS: new Set<string>(),
}));

// Mock @wssp/auth so the invite's password hash hits a stub instead of pulling
// in the real better-auth (which needs an env, prisma, etc).
const hashPassword = vi.hoisted(() => vi.fn(async (password: string) => `hashed:${password}`));
vi.mock("@wssp/auth", () => ({
  auth: { $context: Promise.resolve({ password: { hash: hashPassword } }) },
}));

const { inviteBudget, budgetOptions } = vi.hoisted(() => ({
  inviteBudget: vi.fn(async (_key: string) => undefined),
  budgetOptions: [] as unknown[],
}));
vi.mock("../lib/procedure-budget", () => ({
  createProcedureBudget: (options: unknown) => {
    budgetOptions.push(options);
    return inviteBudget;
  },
}));

// Mock @wssp/mailer so invites don't try to open SMTP. Tests assert on the
// call shape via the mock instead. `renderInviteUser` is stubbed to return a
// stable subject/html so the router can pass them straight through to
// `sendEmail` — the actual rendering is tested in the mailer package.
vi.mock("@wssp/mailer", () => ({
  sendEmail: vi.fn(),
  renderInviteUser: vi.fn(() => ({
    subject: "You've been invited",
    html: "<html><body>invite</body></html>",
  })),
}));

it("configures the invite mail budget to fail closed at 30 per hour", () => {
  expect(budgetOptions).toContainEqual(
    expect.objectContaining({
      keyPrefix: "rl:users-invite-mail",
      points: 30,
      durationSeconds: 3600,
      failClosed: true,
    }),
  );
});

const { default: prisma } = await import("@wssp/db");
const { defaultSensitiveSessionGateUser, wireSensitiveSessionGateUser } = await import(
  "@wssp/api/test/mock-prisma"
);
const { sendEmail, renderInviteUser } = await import("@wssp/mailer");
const renderInviteUserMock = renderInviteUser as unknown as MockInstance;

const db = prisma as unknown as {
  user: {
    findUnique: MockInstance;
    findMany: MockInstance;
    count: MockInstance;
    create: MockInstance;
    update: MockInstance;
    delete: MockInstance;
    deleteMany: MockInstance;
  };
  account: { create: MockInstance };
  session: { deleteMany: MockInstance };
  $transaction: MockInstance;
};
const sendEmailMock = sendEmail as unknown as MockInstance;

/** Admin write transactions; the read-only gate transactions take no governance lock. */
function governanceLockCalls() {
  return (db as unknown as { $queryRaw: MockInstance }).$queryRaw.mock.calls
    .map((call, index) => ({
      sql: Array.isArray(call[0]) ? (call[0] as string[]).join("?") : String(call[0]),
      order: (db as unknown as { $queryRaw: MockInstance }).$queryRaw.mock.invocationCallOrder[
        index
      ]!,
    }))
    .filter((call) => call.sql.includes("pg_advisory_xact_lock"));
}

function buildContext(
  sessionOverride?: Partial<{
    user: Partial<Session["user"]>;
    session: Partial<Session["session"]>;
  }> | null,
): Context {
  if (sessionOverride === null) return { session: null };
  const ctx: Context = {
    session: {
      user: {
        id: "admin-user-id",
        email: "admin@example.com",
        name: "Admin",
        emailVerified: true,
        role: "admin",
        // Forced admin 2FA is the shipped default (FORCE_2FA_DEFAULTS), so an
        // unenrolled admin would 404 here before the router ever ran.
        twoFactorEnabled: true,
        image: null,
        banned: false,
        banReason: null,
        banExpires: null,
        createdAt: new Date("2025-01-01"),
        updatedAt: new Date("2025-01-01"),
        ...sessionOverride?.user,
      },
      session: {
        id: "test-session-id",
        userId: sessionOverride?.user?.id ?? "admin-user-id",
        token: "test-token",
        expiresAt: new Date(Date.now() + 86_400_000),
        ipAddress: "127.0.0.1",
        userAgent: "vitest",
        createdAt: new Date("2025-01-01"),
        updatedAt: new Date("2025-01-01"),
        ...sessionOverride?.session,
      },
    } as Session,
  };
  wireSensitiveSessionGateUser(prisma as never, {
    role: ctx.session!.user.role,
    emailVerified: ctx.session!.user.emailVerified,
    twoFactorEnabled: ctx.session!.user.twoFactorEnabled,
    createdAt: ctx.session!.user.createdAt,
    banned: ctx.session!.user.banned,
    banExpires: ctx.session!.user.banExpires,
  });
  return ctx;
}

describe("usersRouter", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("auth gates", () => {
    it("list throws NOT_FOUND when no session", async () => {
      const client = createRouterClient(usersRouter, { context: buildContext(null) });
      await expect(client.list()).rejects.toSatisfy((e: ORPCError) => {
        expect(e.code).toBe("NOT_FOUND");
        return true;
      });
    });

    it("list throws NOT_FOUND for non-admin role", async () => {
      const client = createRouterClient(usersRouter, {
        context: buildContext({ user: { role: "user" } }),
      });
      await expect(client.list()).rejects.toSatisfy((e: ORPCError) => {
        expect(e.code).toBe("NOT_FOUND");
        return true;
      });
    });

    it("invite throws NOT_FOUND for non-admin role", async () => {
      const client = createRouterClient(usersRouter, {
        context: buildContext({ user: { role: "user" } }),
      });
      await expect(
        client.invite({ email: "x@example.com", name: "X", locale: "en-US" }),
      ).rejects.toSatisfy((e: ORPCError) => {
        expect(e.code).toBe("NOT_FOUND");
        return true;
      });
      expect(db.user.create).not.toHaveBeenCalled();
      expect(inviteBudget).not.toHaveBeenCalled();
    });
  });

  describe("list", () => {
    beforeEach(() => {
      // groupBy's overloads defeat the deep mock's inference; the rows are the real shape.
      vi.mocked(db.credential.groupBy).mockResolvedValue([] as never);
      vi.mocked(db.credentialInstance.groupBy).mockResolvedValue([] as never);
    });

    it("adds per-user CLI-login counts (metadata only)", async () => {
      db.user.findMany.mockResolvedValue([
        { id: "1", email: "a@x.com", name: "A", role: "user", createdAt: new Date("2025-01-01") },
        { id: "2", email: "b@x.com", name: "B", role: "user", createdAt: new Date("2025-01-01") },
      ]);
      vi.mocked(db.credential.groupBy).mockResolvedValue([
        { userId: "1", _count: { _all: 2 } },
      ] as never);
      vi.mocked(db.credentialInstance.groupBy).mockResolvedValue([
        { userId: "1", _count: { _all: 3 } },
      ] as never);

      const client = createRouterClient(usersRouter, { context: buildContext() });
      const res = await client.list();

      expect(res.users.map((user) => user.cliLogins)).toEqual([
        { logins: 2, instances: 3 },
        { logins: 0, instances: 0 },
      ]);
      const where = vi.mocked(db.credential.groupBy).mock.calls[0]?.[0].where;
      expect(where).toEqual({ userId: { in: ["1", "2"] }, deletedAt: null });
    });

    it("returns users + nextCursor without a search filter", async () => {
      db.user.findMany.mockResolvedValue([
        { id: "1", email: "a@x.com", name: "A", role: "user", createdAt: new Date("2025-01-01") },
      ]);

      const client = createRouterClient(usersRouter, { context: buildContext() });
      const res = await client.list();

      expect(res.users).toHaveLength(1);
      expect(res.nextCursor).toBeNull();
      // No cursor on the first page: the filter stands alone in the AND.
      expect(db.user.findMany.mock.calls[0]?.[0].where).toEqual({ AND: [{}] });
      // Never a per-page count — the UI is an infinite list.
      expect(db.user.count).not.toHaveBeenCalled();
    });

    it("takes limit + 1 to detect hasMore and mints a cursor for a full page", async () => {
      const rows = Array.from({ length: 11 }, (_, i) => ({
        id: `u-${i}`,
        email: `u${i}@x.com`,
        name: `U ${i}`,
        role: "user",
        createdAt: new Date("2025-01-01"),
      }));
      db.user.findMany.mockResolvedValue(rows);

      const client = createRouterClient(usersRouter, { context: buildContext() });
      const res = await client.list({ limit: 10 });

      const call = db.user.findMany.mock.calls[0]?.[0];
      expect(call.take).toBe(11);
      expect(call.skip).toBeUndefined();
      expect(res.users).toHaveLength(10);
      expect(res.nextCursor).toEqual(expect.any(String));
    });

    it("applies a case-insensitive OR search across name and email", async () => {
      db.user.findMany.mockResolvedValue([]);

      const client = createRouterClient(usersRouter, { context: buildContext() });
      await client.list({ search: "alice", limit: 10 });

      const call = db.user.findMany.mock.calls[0]?.[0];
      expect(call.where).toEqual({
        AND: [
          {
            OR: [
              { email: { contains: "alice", mode: "insensitive" } },
              { name: { contains: "alice", mode: "insensitive" } },
            ],
          },
        ],
      });
      expect(call.take).toBe(11);
      expect(call.skip).toBeUndefined();
    });

    it("rejects a malformed cursor", async () => {
      const client = createRouterClient(usersRouter, { context: buildContext() });
      await expect(client.list({ cursor: "not-a-cursor" })).rejects.toMatchObject({
        code: "BAD_REQUEST",
      });
      expect(db.user.findMany).not.toHaveBeenCalled();
    });

    it("filters archived users in the database (banned=true)", async () => {
      db.user.findMany.mockResolvedValue([]);

      const client = createRouterClient(usersRouter, { context: buildContext() });
      await client.list({ status: "archived" });

      const call = db.user.findMany.mock.calls[0]?.[0];
      expect(call.where).toEqual({ AND: [{ banned: true }] });
    });

    it("treats active as not-banned, including NULL banned", async () => {
      db.user.findMany.mockResolvedValue([]);

      const client = createRouterClient(usersRouter, { context: buildContext() });
      await client.list({ status: "active" });

      const call = db.user.findMany.mock.calls[0]?.[0];
      expect(call.where).toEqual({ AND: [{ OR: [{ banned: false }, { banned: null }] }] });
    });

    it("combines status and search with AND", async () => {
      db.user.findMany.mockResolvedValue([]);

      const client = createRouterClient(usersRouter, { context: buildContext() });
      await client.list({ status: "archived", search: "alice" });

      const call = db.user.findMany.mock.calls[0]?.[0];
      expect(call.where).toEqual({
        AND: [
          {
            AND: [
              { banned: true },
              {
                OR: [
                  { email: { contains: "alice", mode: "insensitive" } },
                  { name: { contains: "alice", mode: "insensitive" } },
                ],
              },
            ],
          },
        ],
      });
    });
  });

  describe("invite", () => {
    function wireInvite() {
      // Gate reads the actor first; the email-taken probe then finds no row.
      db.user.findUnique.mockImplementation(async (args: { where: { email?: string } }) =>
        args.where.email ? null : { ...defaultSensitiveSessionGateUser },
      );
      db.user.create.mockResolvedValue({ id: "new-user-id" });
    }

    it("creates the user and credential in the admin transaction, then emails after commit", async () => {
      const client = createRouterClient(usersRouter, { context: buildContext() });
      wireInvite();
      sendEmailMock.mockResolvedValue(undefined);
      const res = await client.invite({
        email: "NEW@example.com",
        name: "New User",
        role: "user",
        locale: "es-MX",
      });

      expect(res.userId).toBe("new-user-id");
      expect(res.tempPassword).toEqual(expect.any(String));
      expect(res.tempPassword.length).toBeGreaterThan(8);
      expect(res.emailSent).toBe(true);
      expect(inviteBudget).toHaveBeenCalledWith("user:admin-user-id");
      expect(hashPassword).toHaveBeenCalledWith(res.tempPassword);
      // Email should be lowercased by the input zod schema.
      expect(db.user.create).toHaveBeenCalledWith({
        data: {
          email: "new@example.com",
          name: "New User",
          role: "user",
          // The admin's pick is the invitee's locale from the first insert.
          locale: "es-MX",
          mustChangePassword: true,
        },
        select: { id: true },
      });
      expect(db.account.create).toHaveBeenCalledWith({
        data: {
          userId: "new-user-id",
          accountId: "new-user-id",
          providerId: "credential",
          password: `hashed:${res.tempPassword}`,
        },
        select: { id: true },
      });
      expect(sendEmailMock).toHaveBeenCalledWith(
        expect.objectContaining({ to: "new@example.com" }),
      );
      // One mail, in the invitee's language.
      expect(sendEmailMock).toHaveBeenCalledOnce();
      expect(renderInviteUserMock).toHaveBeenCalledWith(
        expect.objectContaining({ locale: "es-MX", expiresInDays: 7 }),
      );
      // The budget and the hash run before the governance transaction opens;
      // mail runs only after it resolves.
      const [lock] = governanceLockCalls();
      const txOrder = lock!.order;
      expect(inviteBudget.mock.invocationCallOrder[0]).toBeLessThan(txOrder);
      expect(hashPassword.mock.invocationCallOrder[0]).toBeLessThan(txOrder);
      expect(sendEmailMock.mock.invocationCallOrder[0]).toBeGreaterThan(
        db.account.create.mock.invocationCallOrder[0]!,
      );
    });

    it.each([
      ["es-MX", undefined, "/es-MX/verify-email?ok=1"],
      ["en-US", "https://app.example.test", "https://app.example.test/en-US/verify-email?ok=1"],
    ] as const)(
      "the accept link verifies the invited address and lands on the web verify-email page (%s, %s)",
      async (locale, corsOrigin, callbackURL) => {
        const client = createRouterClient(usersRouter, { context: buildContext() });
        wireInvite();
        envMock.CORS_ORIGIN = corsOrigin;
        sendEmailMock.mockResolvedValue(undefined);
        try {
          await client.invite({ email: "new@example.com", name: "New User", locale });
          const [args] = renderInviteUserMock.mock.calls.at(-1) as [{ acceptUrl: string }];
          const url = new URL(args.acceptUrl);
          expect(`${url.origin}${url.pathname}`).toBe(
            "http://localhost:3000/api/auth/verify-email",
          );
          expect(url.searchParams.get("callbackURL")).toBe(callbackURL);
          const claims = JSON.parse(
            Buffer.from(url.searchParams.get("token")!.split(".")[1]!, "base64url").toString(),
          );
          expect(claims).toMatchObject({ email: "new@example.com", userId: "new-user-id" });
        } finally {
          envMock.CORS_ORIGIN = undefined;
        }
      },
    );

    it("refuses an invite without a supported email language before any budget or write", async () => {
      const client = createRouterClient(usersRouter, { context: buildContext() });
      wireInvite();
      for (const locale of ["fr-FR", undefined]) {
        await expect(
          client.invite({
            email: "new@example.com",
            name: "New",
            locale: locale as unknown as "en-US",
          }),
        ).rejects.toMatchObject({ code: "BAD_REQUEST" });
      }
      expect(inviteBudget).not.toHaveBeenCalled();
      expect(db.user.create).not.toHaveBeenCalled();
      expect(sendEmailMock).not.toHaveBeenCalled();
    });

    it("returns emailSent=false when SMTP throws but the user was still created", async () => {
      const client = createRouterClient(usersRouter, { context: buildContext() });
      wireInvite();
      sendEmailMock.mockRejectedValue(new Error("SMTP not configured"));
      const res = await client.invite({
        email: "new@example.com",
        name: "New User",
        locale: "en-US",
      });

      expect(res.emailSent).toBe(false);
      expect(res.userId).toBe("new-user-id");
    });

    it("translates an existing or racing email into a CONFLICT without mailing", async () => {
      const client = createRouterClient(usersRouter, { context: buildContext() });
      db.user.findUnique.mockResolvedValue({ ...defaultSensitiveSessionGateUser, id: "taken" });
      await expect(
        client.invite({ email: "dup@example.com", name: "Dup", locale: "en-US" }),
      ).rejects.toMatchObject({
        code: "CONFLICT",
      });
      wireInvite();
      db.user.create.mockRejectedValue(Object.assign(new Error("unique"), { code: "P2002" }));
      await expect(
        client.invite({ email: "dup@example.com", name: "Dup", locale: "en-US" }),
      ).rejects.toMatchObject({
        code: "CONFLICT",
      });
      expect(db.account.create).not.toHaveBeenCalled();
      expect(sendEmailMock).not.toHaveBeenCalled();
    });

    it("spends the invitation budget before any write and refuses when it is exhausted", async () => {
      const client = createRouterClient(usersRouter, { context: buildContext() });
      wireInvite();
      inviteBudget.mockRejectedValueOnce(new ORPCError("TOO_MANY_REQUESTS"));
      await expect(
        client.invite({ email: "new@example.com", name: "New", locale: "en-US" }),
      ).rejects.toMatchObject({
        code: "TOO_MANY_REQUESTS",
      });
      expect(hashPassword).not.toHaveBeenCalled();
      expect(governanceLockCalls()).toHaveLength(0);
      expect(db.user.create).not.toHaveBeenCalled();
      expect(sendEmailMock).not.toHaveBeenCalled();
    });

    it("never mails when the write transaction fails to commit", async () => {
      const client = createRouterClient(usersRouter, { context: buildContext() });
      wireInvite();
      db.$transaction.mockImplementation(async (work: unknown) => {
        if (typeof work !== "function") throw new Error("unexpected batch");
        const output = await work(db);
        // Only the admin write (governance lock) transaction fails at commit.
        if (governanceLockCalls().length > 0) throw new Error("commit failed");
        return output;
      });
      try {
        await expect(
          client.invite({ email: "new@example.com", name: "New", locale: "en-US" }),
        ).rejects.toThrow();
        expect(db.account.create).toHaveBeenCalled();
        expect(sendEmailMock).not.toHaveBeenCalled();
      } finally {
        db.$transaction.mockImplementation(async (work: unknown) =>
          typeof work === "function" ? work(db) : Promise.all(work as unknown[]),
        );
      }
    });

    it("never mails when the transactional reauthorization refuses the actor", async () => {
      const client = createRouterClient(usersRouter, { context: buildContext() });
      wireInvite();
      // Entry gate passes; the in-transaction session lookup sees a revocation.
      (db as unknown as { session: { findUnique: MockInstance } }).session.findUnique
        .mockResolvedValueOnce({ id: "test-session-id" })
        .mockResolvedValueOnce(null);
      await expect(
        client.invite({ email: "new@example.com", name: "New", locale: "en-US" }),
      ).rejects.toMatchObject({
        code: "NOT_FOUND",
      });
      expect(db.user.create).not.toHaveBeenCalled();
      expect(sendEmailMock).not.toHaveBeenCalled();
    });
  });

  describe("setRole", () => {
    it("updates the role on a different user", async () => {
      db.user.findUnique.mockResolvedValue({ id: "other-user-id" });
      db.user.update.mockResolvedValue({});

      const client = createRouterClient(usersRouter, { context: buildContext() });
      const res = await client.setRole({ userId: "other-user-id", role: "admin" });

      expect(res).toEqual({ success: true });
      expect(db.user.update).toHaveBeenCalledWith({
        where: { id: "other-user-id" },
        data: { role: "admin" },
        select: { id: true },
      });
    });

    it("blocks the admin from demoting themselves", async () => {
      const client = createRouterClient(usersRouter, { context: buildContext() });
      await expect(client.setRole({ userId: "admin-user-id", role: "user" })).rejects.toSatisfy(
        (e: ORPCError) => {
          expect(e.code).toBe("FORBIDDEN");
          expect(e.message).toMatch(/own admin role/i);
          return true;
        },
      );
      expect(db.user.update).not.toHaveBeenCalled();
    });

    it("allows promoting yourself to admin (no-op safety net)", async () => {
      // Even though the admin is already admin, the schema allows the call.
      // We only block demotion of self — promoting yourself is harmless.
      db.user.findUnique.mockResolvedValue({ id: "admin-user-id" });
      db.user.update.mockResolvedValue({});

      const client = createRouterClient(usersRouter, { context: buildContext() });
      const res = await client.setRole({ userId: "admin-user-id", role: "admin" });
      expect(res).toEqual({ success: true });
    });

    it("throws NOT_FOUND for an unknown user id", async () => {
      const ctx = buildContext();
      db.user.findUnique.mockImplementation(
        async (args: { where: { id: string }; select?: Record<string, boolean> }) => {
          if (args.where.id === "missing") return null;
          if (args.select?.id && !("twoFactorEnabled" in args.select)) {
            return { id: args.where.id };
          }
          return {
            twoFactorEnabled: ctx.session!.user.twoFactorEnabled,
            role: ctx.session!.user.role,
            emailVerified: ctx.session!.user.emailVerified,
            banned: ctx.session!.user.banned,
            banExpires: ctx.session!.user.banExpires,
            createdAt: ctx.session!.user.createdAt,
          };
        },
      );
      const client = createRouterClient(usersRouter, { context: ctx });
      await expect(client.setRole({ userId: "missing", role: "user" })).rejects.toSatisfy(
        (e: ORPCError) => {
          expect(e.code).toBe("NOT_FOUND");
          return true;
        },
      );
    });
  });

  describe("archive", () => {
    it("bans the user and revokes their sessions in a transaction", async () => {
      db.user.findUnique.mockResolvedValue({ id: "other-user-id" });

      const client = createRouterClient(usersRouter, { context: buildContext() });
      const res = await client.archive({
        userId: "other-user-id",
        reason: "Inactive",
      });

      expect(res).toEqual({ success: true });
      expect(governanceLockCalls()).toHaveLength(1);
    });

    it("blocks self-archive", async () => {
      const client = createRouterClient(usersRouter, { context: buildContext() });
      await expect(client.archive({ userId: "admin-user-id" })).rejects.toSatisfy(
        (e: ORPCError) => {
          expect(e.code).toBe("FORBIDDEN");
          return true;
        },
      );
      expect(db.user.update).not.toHaveBeenCalled();
    });
  });

  describe("unarchive", () => {
    it("clears banned + banReason + banExpires", async () => {
      db.user.findUnique.mockResolvedValue({ id: "other-user-id" });
      db.user.update.mockResolvedValue({});

      const client = createRouterClient(usersRouter, { context: buildContext() });
      const res = await client.unarchive({ userId: "other-user-id" });

      expect(res).toEqual({ success: true });
      expect(db.user.update).toHaveBeenCalledWith({
        where: { id: "other-user-id", deletionRequestedAt: null },
        data: { banned: false, banReason: null, banExpires: null },
        select: { id: true },
      });
    });
  });

  describe("remove", () => {
    it("returns CONFLICT when live resources block deletion", async () => {
      db.user.findUnique.mockResolvedValue({ id: "other-user-id" });
      const { AccountDeletionConflictError } = await import("@wssp/db/account-deletion");
      deleteAccountInTransaction.mockRejectedValue(new AccountDeletionConflictError(["hosts"]));
      const client = createRouterClient(usersRouter, { context: buildContext() });
      await expect(client.remove({ userId: "other-user-id" })).rejects.toSatisfy((e: ORPCError) => {
        expect(e.code).toBe("CONFLICT");
        return true;
      });
    });

    it("deletes an empty account", async () => {
      db.user.findUnique.mockResolvedValue({ id: "other-user-id" });
      deleteAccountInTransaction.mockResolvedValue(true);
      const client = createRouterClient(usersRouter, { context: buildContext() });
      expect(await client.remove({ userId: "other-user-id" })).toEqual({ success: true });
    });

    it("tags every typed refusal with the admin error code the UI explains", async () => {
      const { ADMIN_ERROR_CODES } = await import("../lib/admin-error-codes");
      const { AccountDeletionConflictError } = await import("@wssp/db/account-deletion");
      const client = createRouterClient(usersRouter, { context: buildContext() });
      const codeOf = async (call: Promise<unknown>) => {
        try {
          await call;
        } catch (error) {
          return (error as ORPCError).data as { code?: string; blockers?: string[] };
        }
        throw new Error("expected a refusal");
      };

      expect(await codeOf(client.setRole({ userId: "admin-user-id", role: "user" }))).toEqual({
        code: ADMIN_ERROR_CODES.selfDemotion,
      });
      expect(await codeOf(client.archive({ userId: "admin-user-id" }))).toEqual({
        code: ADMIN_ERROR_CODES.selfArchive,
      });
      expect(await codeOf(client.remove({ userId: "admin-user-id" }))).toEqual({
        code: ADMIN_ERROR_CODES.selfDelete,
      });

      db.user.findUnique.mockResolvedValue({ id: "other-user-id" });
      deleteAccountInTransaction.mockRejectedValue(
        new AccountDeletionConflictError(["hosts", "sandboxes"]),
      );
      const blocked = createRouterClient(usersRouter, { context: buildContext() });
      expect(await codeOf(blocked.remove({ userId: "other-user-id" }))).toEqual({
        code: ADMIN_ERROR_CODES.accountDeletionBlocked,
        blockers: ["hosts", "sandboxes"],
      });

      // The governance check reports that no other active admin would remain.
      (db as unknown as { $queryRaw: MockInstance }).$queryRaw.mockResolvedValue([
        { blocked: true },
      ]);
      const lastAdmin = createRouterClient(usersRouter, { context: buildContext() });
      expect(await codeOf(lastAdmin.setRole({ userId: "other-user-id", role: "user" }))).toEqual({
        code: ADMIN_ERROR_CODES.lastAdmin,
      });
      (db as unknown as { $queryRaw: MockInstance }).$queryRaw.mockResolvedValue([]);

      db.user.findUnique.mockResolvedValue({ ...defaultSensitiveSessionGateUser, id: "taken" });
      expect(
        await codeOf(
          client.invite({
            email: "taken@example.com",
            name: "Taken",
            role: "user",
            locale: "en-US",
          }),
        ),
      ).toEqual({ code: ADMIN_ERROR_CODES.emailTaken });
    });

    it("blocks self-delete", async () => {
      const client = createRouterClient(usersRouter, { context: buildContext() });
      await expect(client.remove({ userId: "admin-user-id" })).rejects.toSatisfy((e: ORPCError) => {
        expect(e.code).toBe("FORBIDDEN");
        return true;
      });
      expect(db.user.delete).not.toHaveBeenCalled();
    });
  });
});
