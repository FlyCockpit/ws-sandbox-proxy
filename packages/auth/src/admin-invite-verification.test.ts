import { verifyEmail } from "better-auth/api";
import { describe, expect, it } from "vitest";

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
