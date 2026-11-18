import { userLoginGrantSchema } from "@wssp/config/user-device-login";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_USER_LOGIN_DRAFT,
  draftMaxLiveSandboxes,
  userLoginGrantFromDraft,
} from "./user-login-grant";

describe("userLoginGrantFromDraft", () => {
  it("maps the defaults to a read-only, all-pools, 30-day grant with no limit", () => {
    const grant = userLoginGrantFromDraft(DEFAULT_USER_LOGIN_DRAFT);
    expect(grant).toEqual({
      access: "read",
      poolMode: "ALL_USABLE",
      poolIds: [],
      ownSandboxesOnly: false,
      maxLiveSandboxes: null,
      expiresInDays: 30,
      name: "wssp login",
    });
    expect(userLoginGrantSchema.safeParse(grant).success).toBe(true);
  });

  it("drops a hidden pool selection from an all-pools grant", () => {
    const grant = userLoginGrantFromDraft({ ...DEFAULT_USER_LOGIN_DRAFT, poolIds: ["pool-1"] });
    expect(grant?.poolIds).toEqual([]);
  });

  it("keeps selected pools, the limit, expiry and a trimmed name", () => {
    expect(
      userLoginGrantFromDraft({
        name: "  laptop  ",
        access: "write",
        poolMode: "SELECTED",
        poolIds: ["pool-1", "pool-2"],
        ownSandboxesOnly: true,
        maxLiveSandboxes: " 3 ",
        expiresInDays: "7",
      }),
    ).toEqual({
      access: "write",
      poolMode: "SELECTED",
      poolIds: ["pool-1", "pool-2"],
      ownSandboxesOnly: true,
      maxLiveSandboxes: 3,
      expiresInDays: 7,
      name: "laptop",
    });
  });

  it.each([
    ["SELECTED with no pools", { poolMode: "SELECTED" as const, poolIds: [] }],
    ["a blank name", { name: "   " }],
    ["a name over 120 characters", { name: "x".repeat(121) }],
    ["a zero limit", { maxLiveSandboxes: "0" }],
    ["a limit over 1000", { maxLiveSandboxes: "1001" }],
    ["a fractional limit", { maxLiveSandboxes: "2.5" }],
    ["a negative limit", { maxLiveSandboxes: "-1" }],
    ["an unoffered expiry", { expiresInDays: "14" }],
    ["no expiry", { expiresInDays: "" }],
  ])("refuses %s", (_label, change) => {
    expect(userLoginGrantFromDraft({ ...DEFAULT_USER_LOGIN_DRAFT, ...change })).toBeNull();
  });
});

describe("draftMaxLiveSandboxes", () => {
  it("reads empty as no limit and rejects non-integers", () => {
    expect(draftMaxLiveSandboxes("")).toBeNull();
    expect(draftMaxLiveSandboxes("  ")).toBeNull();
    expect(draftMaxLiveSandboxes("12")).toBe(12);
    expect(draftMaxLiveSandboxes("1e2")).toBeUndefined();
  });
});
