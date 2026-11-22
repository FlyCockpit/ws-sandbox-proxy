import { describe, expect, it } from "vitest";
import { signupNotice } from "./signup-notice";

describe("signupNotice", () => {
  it("names the invitation only when its secret is held", () => {
    expect(signupNotice({ signupEnabled: true, adminBootstrapSignupEnabled: false }, true)).toBe(
      "invite",
    );
    expect(signupNotice({ signupEnabled: true, adminBootstrapSignupEnabled: false }, false)).toBe(
      null,
    );
  });

  it("explains closed sign-up when only administrator addresses may bootstrap", () => {
    expect(signupNotice({ signupEnabled: false, adminBootstrapSignupEnabled: true }, false)).toBe(
      "limited",
    );
    expect(signupNotice({ signupEnabled: false, adminBootstrapSignupEnabled: false }, false)).toBe(
      null,
    );
    expect(signupNotice(undefined, false)).toBe(null);
  });
});
