import { describe, expect, it } from "vitest";

import { signupMode } from "./signup-mode";

describe("signupMode", () => {
  it("open wins, then the admin bootstrap, else closed", () => {
    expect(signupMode({ signupEnabled: true, adminBootstrapSignupEnabled: true })).toBe("open");
    expect(signupMode({ signupEnabled: false, adminBootstrapSignupEnabled: true })).toBe(
      "bootstrap",
    );
    expect(signupMode({ signupEnabled: false, adminBootstrapSignupEnabled: false })).toBe("closed");
    expect(signupMode({})).toBe("closed");
  });
});
