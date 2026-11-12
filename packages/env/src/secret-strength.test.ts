import { expect, it } from "vitest";
import { isWeakSecret } from "./secret-strength";

it("preserves the existing auth placeholder/weakness policy when reused by HMAC validation", () => {
  for (const value of [
    "a".repeat(64),
    "ab".repeat(32),
    "012345678".repeat(8),
    "ABC-PLACEHOLDER-0123456789",
  ]) {
    expect(isWeakSecret(value)).not.toBeNull();
  }
  expect(isWeakSecret("0123456789abcdef".repeat(4))).toBeNull();
  expect(isWeakSecret("kV3mQ7xZ2bN9wL5pR8tY4cJ6hF1dS0gU")).toBeNull();
});
