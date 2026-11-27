import { APIError } from "better-auth/api";
import { describe, expect, it } from "vitest";

import { refuseUnprovedUserUpdate, refuseVerifiedUserCreation } from "./mailbox-proof-policy";

function refusal(run: () => void): string | undefined {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(APIError);
    return (error as APIError).body?.code;
  }
  return undefined;
}

describe("refuseVerifiedUserCreation", () => {
  it("refuses a user created verified, whoever asks", () => {
    expect(refusal(() => refuseVerifiedUserCreation({ emailVerified: true }))).toBe(
      "EMAIL_VERIFICATION_BY_MAIL_ONLY",
    );
  });

  it("lets an unverified user through", () => {
    expect(refusal(() => refuseVerifiedUserCreation({ emailVerified: false }))).toBe(undefined);
    expect(refusal(() => refuseVerifiedUserCreation({}))).toBe(undefined);
  });
});

describe("refuseUnprovedUserUpdate", () => {
  it("refuses an email on every Better Auth user update", () => {
    for (const context of [
      { path: "/verify-email" },
      { path: "/update-user" },
      { path: "/admin/update-user" },
      null,
      undefined,
    ])
      expect(refusal(() => refuseUnprovedUserUpdate({ email: "new@example.test" }, context))).toBe(
        "EMAIL_CHANGE_UNSUPPORTED",
      );
  });

  it("refuses emailVerified outside the mailed verify-email link", () => {
    for (const context of [{ path: "/admin/update-user" }, { path: "/update-user" }, null])
      for (const emailVerified of [true, false])
        expect(refusal(() => refuseUnprovedUserUpdate({ emailVerified }, context))).toBe(
          "EMAIL_VERIFICATION_BY_MAIL_ONLY",
        );
  });

  it("lets verify-email and every other update through", () => {
    expect(
      refusal(() => refuseUnprovedUserUpdate({ emailVerified: true }, { path: "/verify-email" })),
    ).toBe(undefined);
    expect(refusal(() => refuseUnprovedUserUpdate({ name: "Ada" }, { path: "/update-user" }))).toBe(
      undefined,
    );
    expect(
      refusal(() =>
        refuseUnprovedUserUpdate({ twoFactorEnabled: true }, { path: "/two-factor/enable" }),
      ),
    ).toBe(undefined);
    expect(refusal(() => refuseUnprovedUserUpdate({ banned: true }, null))).toBe(undefined);
  });
});
