import { ORPCError } from "@orpc/client";
import { describe, expect, it } from "vitest";

import { isSetupLinkInvalid } from "./setup-link";

describe("isSetupLinkInvalid", () => {
  it("is true for a spent, expired or replaced link", () => {
    expect(isSetupLinkInvalid(new ORPCError("SETUP_LINK_INVALID"))).toBe(true);
  });

  it("is true once SETUP_KEY is removed from the server (NOT_FOUND with data.code SETUP_KEY_UNSET)", () => {
    expect(
      isSetupLinkInvalid(new ORPCError("NOT_FOUND", { data: { code: "SETUP_KEY_UNSET" } })),
    ).toBe(true);
  });

  it("is false for a bare NOT_FOUND (unknown procedure during a version skew, a proxy 404)", () => {
    expect(isSetupLinkInvalid(new ORPCError("NOT_FOUND"))).toBe(false);
    expect(isSetupLinkInvalid(new ORPCError("NOT_FOUND", { data: { code: "OTHER" } }))).toBe(false);
    expect(isSetupLinkInvalid(new ORPCError("NOT_FOUND", { data: null }))).toBe(false);
  });

  it("is false for every other refusal, so its own message is shown", () => {
    expect(isSetupLinkInvalid(new ORPCError("BAD_REQUEST"))).toBe(false);
    expect(isSetupLinkInvalid(new ORPCError("TOO_MANY_REQUESTS"))).toBe(false);
    expect(isSetupLinkInvalid(new Error("network"))).toBe(false);
    expect(isSetupLinkInvalid(null)).toBe(false);
    expect(isSetupLinkInvalid("NOT_FOUND")).toBe(false);
  });
});
