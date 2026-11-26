import { describe, expect, it } from "vitest";

import { signupMode, signupOffered } from "./signup-mode";

describe("signupMode", () => {
  it("open wins, then the admin bootstrap, else closed", () => {
    expect(signupMode({ signupEnabled: true, adminBootstrapSignupEnabled: true })).toBe("open");
    expect(signupMode({ signupEnabled: false, adminBootstrapSignupEnabled: true })).toBe(
      "bootstrap",
    );
    expect(signupMode({ signupEnabled: false, adminBootstrapSignupEnabled: false })).toBe("closed");
    expect(signupMode({})).toBe("closed");
  });

  it("a held pool invitation opens sign-up in every server mode", () => {
    expect(signupMode({ signupEnabled: false, adminBootstrapSignupEnabled: false }, true)).toBe(
      "invite",
    );
    expect(signupMode({ signupEnabled: false, adminBootstrapSignupEnabled: true }, true)).toBe(
      "invite",
    );
    expect(signupMode({ signupEnabled: true }, true)).toBe("invite");
    expect(signupMode({}, false)).toBe("closed");
  });

  it("offers a sign-up form in every mode but closed", () => {
    expect(signupOffered("invite")).toBe(true);
    expect(signupOffered("open")).toBe(true);
    expect(signupOffered("bootstrap")).toBe(true);
    expect(signupOffered("closed")).toBe(false);
  });
});
