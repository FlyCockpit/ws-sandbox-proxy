import { PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH } from "@wssp/auth/password-policy";
import { describe, expect, it } from "vitest";

import { currentPasswordSchema, newPasswordSchema } from "./password-policy";

describe("newPasswordSchema", () => {
  it("accepts exactly the server's length range", () => {
    expect(PASSWORD_MIN_LENGTH).toBe(12);
    const schema = newPasswordSchema();
    expect(schema.safeParse("a".repeat(PASSWORD_MIN_LENGTH - 1)).success).toBe(false);
    expect(schema.safeParse("a".repeat(PASSWORD_MIN_LENGTH)).success).toBe(true);
    expect(schema.safeParse("a".repeat(PASSWORD_MAX_LENGTH)).success).toBe(true);
    expect(schema.safeParse("a".repeat(PASSWORD_MAX_LENGTH + 1)).success).toBe(false);
  });
});

describe("currentPasswordSchema", () => {
  it("only requires a password, so an older, shorter one can still sign in", () => {
    const schema = currentPasswordSchema("Required");
    const empty = schema.safeParse("");
    expect(empty.success).toBe(false);
    expect(empty.error?.issues[0]?.message).toBe("Required");
    expect(schema.safeParse("short").success).toBe(true);
  });
});
