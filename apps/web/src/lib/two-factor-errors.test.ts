import { describe, expect, it, vi } from "vitest";

vi.mock("@/utils/friendly-error", () => ({
  friendly: () => "Too many attempts.",
  isRateLimit: (error: { status?: number } | null) => error?.status === 429,
}));

import { twoFactorCodeError, twoFactorPasswordError } from "./two-factor-errors";

const t = (key: string) => key;

describe("2FA step errors", () => {
  it("says a wrong password was wrong instead of 'couldn't start setup'", () => {
    expect(
      twoFactorPasswordError({ code: "INVALID_PASSWORD", status: 400 }, t, "fallback:key"),
    ).toBe("auth:errors.wrongPassword");
    expect(twoFactorPasswordError({ status: 429 }, t, "fallback:key")).toBe("Too many attempts.");
    expect(twoFactorPasswordError({ code: "OTHER", status: 500 }, t, "fallback:key")).toBe(
      "fallback:key",
    );
    expect(twoFactorPasswordError(null, t, "fallback:key")).toBe("fallback:key");
    expect(twoFactorPasswordError(new Error("offline"), t, "fallback:key")).toBe("fallback:key");
  });

  it("names a refused authenticator code, or the rate limit", () => {
    expect(twoFactorCodeError({ code: "INVALID_CODE", status: 401 }, t)).toBe(
      "auth:errors.invalidTotp",
    );
    expect(twoFactorCodeError({ status: 429 }, t)).toBe("Too many attempts.");
  });
});
