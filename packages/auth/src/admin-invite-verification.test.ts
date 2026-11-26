import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { verifyEmail } from "better-auth/api";
import { describe, expect, it, vi } from "vitest";

import {
  ADMIN_INVITE_VERIFICATION_TTL_SECONDS,
  adminInviteAcceptUrl,
} from "./admin-invite-verification";

const secret = "admin-invite-test-secret-long-enough-for-hs256";
const decodeJwt = (token: string): Record<string, unknown> & { exp?: number } =>
  JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"));

describe("adminInviteAcceptUrl", () => {
  it("is Better Auth's verify-email link for the invited address, bound to the user, for a week", async () => {
    const before = Math.floor(Date.now() / 1000);
    const url = new URL(
      await adminInviteAcceptUrl({
        secret,
        authBaseUrl: "https://api.example.test",
        appOrigin: "https://app.example.test",
        userId: "user-1",
        email: "Invitee@Example.test",
        locale: "es-MX",
      }),
    );
    expect(`${url.origin}${url.pathname}`).toBe("https://api.example.test/api/auth/verify-email");
    expect(url.searchParams.get("callbackURL")).toBe(
      "https://app.example.test/es-MX/verify-email?ok=1",
    );
    const claims = decodeJwt(url.searchParams.get("token") ?? "");
    expect(claims).toMatchObject({ email: "invitee@example.test", userId: "user-1" });
    expect(claims.updateTo).toBeUndefined();
    expect(claims.exp! - before).toBeGreaterThanOrEqual(ADMIN_INVITE_VERIFICATION_TTL_SECONDS);
    expect(claims.exp! - before).toBeLessThanOrEqual(ADMIN_INVITE_VERIFICATION_TTL_SECONDS + 5);
    // The very endpoint the link names is Better Auth's own proof writer.
    expect(verifyEmail.path).toBe("/verify-email");
  });

  it("falls back to the default locale and a same-origin callback", async () => {
    const url = new URL(
      await adminInviteAcceptUrl({
        secret,
        authBaseUrl: "http://localhost:3000",
        userId: "user-2",
        email: "b@example.test",
        locale: "fr-FR",
      }),
    );
    expect(url.searchParams.get("callbackURL")).toBe("/en-US/verify-email?ok=1");
  });
});

/**
 * One mail per invitation. users.invite inserts the account itself (not a
 * Better Auth sign-up), so nothing mails a "verify your email" link; opening
 * the invite's accept link verifies, and the sign-in after it sends nothing.
 * Better Auth here carries the same email-verification options as index.ts
 * (`requireEmailVerification`, `sendOnSignUp`, `sendOnSignIn`); the pg test
 * (admin-invite-verification.pg.test.ts) repeats the count on the real config.
 */
describe("an accepted admin invitation sends no verification mail", () => {
  const BASE_URL = "http://localhost:3000";
  const TEMPORARY = "temporary-password-from-the-admin";

  async function setup() {
    const db: Record<string, Record<string, unknown>[]> = {
      user: [],
      session: [],
      account: [],
      verification: [],
    };
    const sendVerificationEmail = vi.fn(async () => {});
    const auth = betterAuth({
      baseURL: BASE_URL,
      secret,
      database: memoryAdapter(db),
      rateLimit: { enabled: false },
      emailAndPassword: { enabled: true, requireEmailVerification: true },
      emailVerification: { sendVerificationEmail, sendOnSignUp: true, sendOnSignIn: true },
    });
    const context = await auth.$context;
    // What users.invite writes (rows inserted directly, not a Better Auth
    // sign-up): an unverified user and a credential account.
    async function invite(email: string) {
      const now = new Date();
      const user = { id: `user-${email}`, email, name: "Invitee", emailVerified: false };
      db.user?.push({ ...user, image: null, createdAt: now, updatedAt: now });
      db.account?.push({
        id: `account-${email}`,
        userId: user.id,
        accountId: user.id,
        providerId: "credential",
        password: await context.password.hash(TEMPORARY),
        createdAt: now,
        updatedAt: now,
      });
      return user;
    }
    const signIn = (email: string) =>
      auth.handler(
        new Request(`${BASE_URL}/api/auth/sign-in/email`, {
          method: "POST",
          headers: { "content-type": "application/json", origin: BASE_URL },
          body: JSON.stringify({ email, password: TEMPORARY }),
        }),
      );
    const verified = (id: string) => db.user?.find((row) => row.id === id)?.emailVerified;
    return { auth, invite, signIn, verified, sendVerificationEmail };
  }

  it("accepting verifies, and the sign-in after it mails nothing", async () => {
    const { auth, invite, signIn, verified, sendVerificationEmail } = await setup();
    const user = await invite("accepted@example.test");
    const accept = await adminInviteAcceptUrl({
      secret,
      authBaseUrl: BASE_URL,
      userId: user.id,
      email: user.email,
      locale: "es-MX",
    });
    const opened = await auth.handler(new Request(accept, { method: "GET" }));
    expect(opened.status).toBe(302);
    expect(opened.headers.get("location")).toBe("/es-MX/verify-email?ok=1");
    expect(verified(user.id)).toBe(true);
    expect((await signIn(user.email)).status).toBe(200);
    expect(sendVerificationEmail).not.toHaveBeenCalled();
  });

  it("a sign-in before accepting is refused and gets exactly one fresh link (the way back in)", async () => {
    const { invite, signIn, verified, sendVerificationEmail } = await setup();
    const user = await invite("early@example.test");
    expect((await signIn(user.email)).status).toBe(403);
    expect(verified(user.id)).toBe(false);
    expect(sendVerificationEmail).toHaveBeenCalledOnce();
  });
});
