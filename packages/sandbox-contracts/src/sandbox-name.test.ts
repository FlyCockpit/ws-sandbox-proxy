import { describe, expect, it } from "vitest";
import { isValidSandboxName, SANDBOX_NAME_MAX, sandboxNameSchema } from "./sandbox-name";

describe("sandboxNameSchema", () => {
  it.each([
    "a",
    "0",
    "quiet-otter",
    "quiet-otter-3k9z",
    "a-b",
    "a--b",
    "x".repeat(SANDBOX_NAME_MAX),
    "sandbox-0123456789ab",
    "wssp",
    "my-wssp-box",
  ])("accepts %j", (name) => {
    expect(sandboxNameSchema.safeParse(name).success).toBe(true);
    expect(isValidSandboxName(name)).toBe(true);
  });

  it.each([
    "",
    "x".repeat(SANDBOX_NAME_MAX + 1),
    "-lead",
    "trail-",
    "-",
    "Upper",
    "QUIET-OTTER",
    "under_score",
    "dot.ted",
    "spa ce",
    "ünïcode",
    "a‮b",
    "wssp-sbx-1",
    "wssp-anything",
    "123e4567-e89b-12d3-a456-426614174000",
  ])("refuses %j without transforming it", (name) => {
    const parsed = sandboxNameSchema.safeParse(name);
    expect(parsed.success).toBe(false);
    expect(isValidSandboxName(name)).toBe(false);
  });

  it("never normalizes: the parsed value is the input", () => {
    expect(sandboxNameSchema.parse("quiet-otter")).toBe("quiet-otter");
  });
});
