import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: { user: { findUnique: vi.fn() } } }));

const { isOpenDuringPasswordChange } = await import("./password-change-guard");

describe("Better Auth paths open to an account with a temporary password", () => {
  it.each([
    "/get-session",
    "/sign-out",
    "/change-password",
    "/revoke-other-sessions",
    "/sign-in/email",
    "/reset-password",
    "/reset-password/abc",
    "/verify-email",
  ])("%s stays open", (path) => {
    expect(isOpenDuringPasswordChange(path)).toBe(true);
  });
  it.each([
    "/update-user",
    "/change-email",
    "/two-factor/enable",
    "/two-factor/get-totp-uri",
    "/two-factor/send-otp",
    "/two-factor/verify-otp",
    "/two-factor/verify-totp",
    "/two-factor/verify-backup-code",
    "/oauth2/consent",
    "/device/approve",
    "/sign-in",
    "/change-password/extra",
  ])("%s is refused", (path) => {
    expect(isOpenDuringPasswordChange(path)).toBe(false);
  });
});
