import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, describe, expect, it, vi } from "vitest";

/**
 * An admin invitation end to end against the REAL Better Auth instance and the
 * disposable PostgreSQL schema: the mailed accept link verifies the invited
 * address through Better Auth's own endpoint (no session, no other writer),
 * the temporary password then signs in, and the invitee's own password change
 * ends the temporary password (password-change-guard.ts's after hook).
 */

const BASE_URL = "http://localhost:3000";

vi.mock("../../api/src/sandbox/terminal-budgets", () => ({
  consumeTerminalMintBudget: async () => {},
  consumeHostProofBudget: async () => {},
}));
vi.mock("../../api/src/sandbox/budgets", () => ({ consumeSandboxWriteBudget: async () => {} }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_URL: BASE_URL,
    SANDBOX_REQUEST_HMAC_SECRET: "0".repeat(64),
    BETTER_AUTH_SECRET: "admin-invite-pg-test-secret-at-least-32-chars",
    NODE_ENV: "test",
  },
  ADMIN_EMAILS: new Set<string>(),
  SIGNUP_ENABLED: true,
}));
vi.mock("@wssp/mailer", () => ({
  isEmailConfigured: () => false,
  renderResetPassword: () => ({ subject: "", html: "" }),
  renderTwoFactorOtp: () => ({ subject: "", html: "" }),
  renderVerifyEmail: () => ({ subject: "", html: "" }),
  sendEmail: vi.fn(async () => undefined),
}));

const db = await pgTestDatabase();
const { auth } = await import("./index");
const { adminInviteAcceptUrl } = await import("./admin-invite-verification");
const { sendEmail } = await import("@wssp/mailer");
/** Mails Better Auth sent to one address (verification resends, resets). */
const mailsTo = (email: string) =>
  vi.mocked(sendEmail).mock.calls.filter(([message]) => message.to === email).length;
afterAll(() => db.close());

const SECRET = "admin-invite-pg-test-secret-at-least-32-chars";
const TEMPORARY = "temporary-password-from-the-admin";
const CHOSEN = "a-password-only-the-invitee-knows";

/** Cookie header carrying every cookie a response set. */
function cookiesFrom(response: Response, previous = ""): string {
  const jar = new Map(
    previous
      .split("; ")
      .filter(Boolean)
      .map((pair) => pair.split("=", 2) as [string, string]),
  );
  for (const header of response.headers.getSetCookie()) {
    const [pair] = header.split(";");
    const index = (pair ?? "").indexOf("=");
    const name = (pair ?? "").slice(0, index);
    const value = (pair ?? "").slice(index + 1);
    if (value === "") jar.delete(name);
    else jar.set(name, value);
  }
  return [...jar].map(([name, value]) => `${name}=${value}`).join("; ");
}

async function post(path: string, body: unknown, cookie = ""): Promise<Response> {
  return auth.handler(
    new Request(`${BASE_URL}/api/auth${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: BASE_URL,
        ...(cookie ? { cookie } : {}),
      },
      body: JSON.stringify(body),
    }),
  );
}

async function invitedUser() {
  const email = `${randomUUID()}@example.test`;
  const user = await db.inspect.user.create({
    data: { email, name: "Invitee", mustChangePassword: true },
    select: { id: true },
  });
  await db.inspect.account.create({
    data: {
      userId: user.id,
      accountId: user.id,
      providerId: "credential",
      password: await (await auth.$context).password.hash(TEMPORARY),
    },
  });
  return { email, userId: user.id };
}

const flags = (userId: string) =>
  db.inspect.user.findUniqueOrThrow({
    where: { id: userId },
    select: { emailVerified: true, mustChangePassword: true },
  });

describe("admin invitation acceptance against the real Better Auth", () => {
  it("the accept link verifies the address, then the invitee replaces the temporary password", async () => {
    const invitee = await invitedUser();
    // The temporary password alone is not mailbox proof.
    const early = await post("/sign-in/email", { email: invitee.email, password: TEMPORARY });
    expect(early.status).toBe(403);
    expect(await flags(invitee.userId)).toEqual({ emailVerified: false, mustChangePassword: true });
    // That refusal re-sends one verification link (sendOnSignIn): the way in
    // when the invite link was lost or expired.
    expect(mailsTo(invitee.email)).toBe(1);

    const accept = new URL(
      await adminInviteAcceptUrl({
        secret: SECRET,
        authBaseUrl: BASE_URL,
        userId: invitee.userId,
        email: invitee.email,
        locale: "en-US",
      }),
    );
    const verified = await auth.handler(new Request(accept, { method: "GET" }));
    expect(verified.status).toBe(302);
    expect(verified.headers.get("location")).toBe("/en-US/verify-email?ok=1");
    // Accepting proves the mailbox; it does not sign anyone in.
    expect(verified.headers.getSetCookie().join(";")).not.toContain("session_token");
    expect(await flags(invitee.userId)).toEqual({ emailVerified: true, mustChangePassword: true });

    const signIn = await post("/sign-in/email", { email: invitee.email, password: TEMPORARY });
    expect(signIn.status, await signIn.clone().text()).toBe(200);
    // Accepting and the sign-in after it mail nothing more.
    expect(mailsTo(invitee.email)).toBe(1);
    const cookie = cookiesFrom(signIn);
    const wrong = await post(
      "/change-password",
      { currentPassword: "not-the-temporary-one", newPassword: CHOSEN, revokeOtherSessions: true },
      cookie,
    );
    expect(wrong.status).toBe(400);
    expect(await flags(invitee.userId)).toEqual({ emailVerified: true, mustChangePassword: true });
    const changed = await post(
      "/change-password",
      { currentPassword: TEMPORARY, newPassword: CHOSEN, revokeOtherSessions: true },
      cookie,
    );
    expect(changed.status, await changed.clone().text()).toBe(200);
    expect(await flags(invitee.userId)).toEqual({ emailVerified: true, mustChangePassword: false });
    // The old session is gone; the temporary password no longer works.
    expect(await db.inspect.session.count({ where: { userId: invitee.userId } })).toBe(1);
    const stale = await post("/sign-in/email", { email: invitee.email, password: TEMPORARY });
    expect(stale.status).toBe(401);
  });

  it("a link for another address, or a tampered one, verifies nothing", async () => {
    const invitee = await invitedUser();
    const other = new URL(
      await adminInviteAcceptUrl({
        secret: "a-different-secret-that-is-long-enough-too",
        authBaseUrl: BASE_URL,
        userId: invitee.userId,
        email: invitee.email,
        locale: "en-US",
      }),
    );
    const refused = await auth.handler(new Request(other, { method: "GET" }));
    expect(refused.headers.get("location")).toContain("error=INVALID_TOKEN");
    expect(await flags(invitee.userId)).toEqual({ emailVerified: false, mustChangePassword: true });
  });

  it("no Better Auth write changes the address or asserts its verification", async () => {
    const invitee = await invitedUser();
    const ctx = await auth.$context;
    const refusedWith = async (write: Promise<unknown>) => {
      const error = await write.then(
        () => null,
        (caught: unknown) => caught,
      );
      return (error as { body?: { code?: string } } | null)?.body?.code;
    };
    const renamed = `${randomUUID()}@example.test`;
    expect(
      await refusedWith(ctx.internalAdapter.updateUser(invitee.userId, { email: renamed })),
    ).toBe("EMAIL_CHANGE_UNSUPPORTED");
    // A server-side write is no mailbox proof either: only /verify-email sets it.
    expect(
      await refusedWith(ctx.internalAdapter.updateUser(invitee.userId, { emailVerified: true })),
    ).toBe("EMAIL_VERIFICATION_BY_MAIL_ONLY");
    const created = `${randomUUID()}@example.test`;
    expect(
      await refusedWith(
        ctx.internalAdapter.createUser({ email: created, name: "Created", emailVerified: true }),
      ),
    ).toBe("EMAIL_VERIFICATION_BY_MAIL_ONLY");
    expect(await db.inspect.user.count({ where: { email: created } })).toBe(0);
    expect(
      await db.inspect.user.findUniqueOrThrow({
        where: { id: invitee.userId },
        select: { email: true, emailVerified: true },
      }),
    ).toEqual({ email: invitee.email, emailVerified: false });
    // The mailed accept link still verifies (the first case signs in after it).
    const accept = new URL(
      await adminInviteAcceptUrl({
        secret: SECRET,
        authBaseUrl: BASE_URL,
        userId: invitee.userId,
        email: invitee.email,
        locale: "en-US",
      }),
    );
    expect((await auth.handler(new Request(accept, { method: "GET" }))).status).toBe(302);
    expect((await flags(invitee.userId)).emailVerified).toBe(true);
  });

  it("a flagged session can only replace the password, never with the temporary one, and every other session ends", async () => {
    const invitee = await invitedUser();
    await db.inspect.user.update({ where: { id: invitee.userId }, data: { emailVerified: true } });
    const signIn = async () => {
      const response = await post("/sign-in/email", { email: invitee.email, password: TEMPORARY });
      expect(response.status, await response.clone().text()).toBe(200);
      return cookiesFrom(response);
    };
    const other = await signIn();
    const cookie = await signIn();
    // Direct Better Auth requests other than the password change are refused.
    const profile = await post("/update-user", { name: "Renamed" }, cookie);
    expect(profile.status).toBe(403);
    expect(await profile.json()).toMatchObject({ code: "auth.password_change_required" });
    const enroll = await post("/two-factor/enable", { password: TEMPORARY }, cookie);
    expect(enroll.status).toBe(403);
    // The second-factor endpoints enroll with a session (email OTP); closed too.
    expect(
      (await post("/two-factor/verify-backup-code", { code: "aaaaa-bbbbb" }, cookie)).status,
    ).toBe(403);
    expect(
      await db.inspect.user.findUniqueOrThrow({
        where: { id: invitee.userId },
        select: { name: true, twoFactorEnabled: true },
      }),
    ).toEqual({ name: "Invitee", twoFactorEnabled: null });
    expect(await db.inspect.twoFactor.count({ where: { userId: invitee.userId } })).toBe(0);
    // A malformed change fails validation and changes nothing.
    for (const body of [{}, { currentPassword: TEMPORARY }, { newPassword: CHOSEN }]) {
      expect((await post("/change-password", body, cookie)).status).toBe(400);
      expect(await flags(invitee.userId)).toEqual({
        emailVerified: true,
        mustChangePassword: true,
      });
    }
    // The temporary password is not a new password (a fresh salt would hide it).
    const reuse = await post(
      "/change-password",
      { currentPassword: TEMPORARY, newPassword: TEMPORARY, revokeOtherSessions: true },
      cookie,
    );
    expect(reuse.status).toBe(400);
    expect(await flags(invitee.userId)).toEqual({ emailVerified: true, mustChangePassword: true });
    // Revocation is enforced whatever the client asks.
    const changed = await post(
      "/change-password",
      { currentPassword: TEMPORARY, newPassword: CHOSEN, revokeOtherSessions: false },
      cookie,
    );
    expect(changed.status, await changed.clone().text()).toBe(200);
    expect(await flags(invitee.userId)).toEqual({ emailVerified: true, mustChangePassword: false });
    expect(await db.inspect.session.count({ where: { userId: invitee.userId } })).toBe(1);
    const fresh = cookiesFrom(changed, cookie);
    expect((await post("/update-user", { name: "Renamed" }, fresh)).status).toBe(200);
    // The other (temporary-password) session's cookie no longer authorizes a
    // durable lookup.
    const stale = await auth.api.getSession({
      headers: new Headers({ cookie: other }),
      query: { disableCookieCache: true },
    });
    expect(stale).toBeNull();
  });

  it("a reset by email signs every session out and refuses the temporary password", async () => {
    const invitee = await invitedUser();
    await db.inspect.user.update({ where: { id: invitee.userId }, data: { emailVerified: true } });
    const signIn = await post("/sign-in/email", { email: invitee.email, password: TEMPORARY });
    expect(signIn.status).toBe(200);
    const reset = async (newPassword: string, inQuery = false) => {
      const token = randomUUID();
      await db.inspect.verification.create({
        data: {
          identifier: `reset-password:${token}`,
          value: invitee.userId,
          expiresAt: new Date(Date.now() + 600_000),
        },
      });
      // Better Auth takes a non-empty body token, else the query's.
      return inQuery
        ? post(`/reset-password?token=${token}`, { token: "", newPassword })
        : post("/reset-password", { token, newPassword });
    };
    expect((await reset(TEMPORARY)).status).toBe(400);
    expect((await reset(TEMPORARY, true)).status).toBe(400);
    // A malformed reset (no new password) fails validation and changes nothing.
    const token = randomUUID();
    await db.inspect.verification.create({
      data: {
        identifier: `reset-password:${token}`,
        value: invitee.userId,
        expiresAt: new Date(Date.now() + 600_000),
      },
    });
    expect((await post("/reset-password", { token })).status).toBe(400);
    expect(await flags(invitee.userId)).toEqual({ emailVerified: true, mustChangePassword: true });
    expect(await db.inspect.session.count({ where: { userId: invitee.userId } })).toBe(1);
    const done = await reset(CHOSEN);
    expect(done.status, await done.clone().text()).toBe(200);
    expect(await flags(invitee.userId)).toEqual({ emailVerified: true, mustChangePassword: false });
    expect(await db.inspect.session.count({ where: { userId: invitee.userId } })).toBe(0);
  });
});
