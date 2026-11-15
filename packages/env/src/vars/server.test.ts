import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { serverVars } from "./server";

describe("staged create/connect budget and timeout settings", () => {
  it.each([
    ["SANDBOX_CREATE_CONNECT_BUDGET_POINTS", 300, 1, 10_000],
    ["SANDBOX_CREATE_CONNECT_BUDGET_WINDOW_SECONDS", 60, 60, 3600],
  ] as const)("bounds %s with a finite integer default", (key, fallback, minimum, maximum) => {
    const schema = serverVars[key];
    expect(schema.parse(undefined)).toBe(fallback);
    expect(schema.parse(String(minimum))).toBe(minimum);
    expect(schema.parse(String(maximum))).toBe(maximum);
    for (const value of [
      minimum - 1,
      maximum + 1,
      0,
      -1,
      1.5,
      NaN,
      Infinity,
      -Infinity,
      "many",
      "1e9",
    ]) {
      expect(schema.safeParse(value).success).toBe(false);
    }
  });
});

describe("SANDBOX_MAX_TIMEOUT_MS (deployment lease layer)", () => {
  const schema = serverVars.SANDBOX_MAX_TIMEOUT_MS;
  it("defaults to 24 hours and accepts 5 minutes through 24 days", () => {
    expect(schema.parse(undefined)).toBe(86_400_000);
    expect(schema.parse("300000")).toBe(300_000);
    expect(schema.parse("2073600000")).toBe(2_073_600_000);
  });
  it("parses the literal unlimited to null", () => {
    expect(schema.parse("unlimited")).toBeNull();
  });
  it("refuses out-of-range, non-integer and other words", () => {
    for (const value of [
      299_999,
      2_073_600_001,
      0,
      -1,
      1.5,
      NaN,
      Infinity,
      -Infinity,
      "many",
      "Unlimited",
      "3e9",
    ]) {
      expect(schema.safeParse(value).success).toBe(false);
    }
  });
});

describe("capacity queue limits", () => {
  it.each([
    ["SANDBOX_CAPACITY_WAIT_MAX_MS", 3_600_000, 2_073_600_000],
    ["SANDBOX_CAPACITY_QUEUE_MAX_PER_KEY", 16, 100_000],
    ["SANDBOX_CAPACITY_QUEUE_MAX_PER_OWNER", 64, 100_000],
  ] as const)(
    "%s defaults, accepts 0..max and unlimited, refuses other values",
    (key, fallback, max) => {
      const schema = serverVars[key];
      expect(schema.parse(undefined)).toBe(fallback);
      expect(schema.parse("0")).toBe(0);
      expect(schema.parse(String(max))).toBe(max);
      expect(schema.parse("unlimited")).toBeNull();
      for (const value of [-1, max + 1, 1.5, "Unlimited", "many", NaN])
        expect(schema.safeParse(value).success).toBe(false);
    },
  );
});

describe("CAPACITY_RETRY_AFTER_SECONDS", () => {
  it("defaults to 30 and accepts 1..86400 whole seconds only", () => {
    const schema = serverVars.CAPACITY_RETRY_AFTER_SECONDS;
    expect(schema.parse(undefined)).toBe(30);
    expect(schema.parse("1")).toBe(1);
    expect(schema.parse("86400")).toBe(86_400);
    for (const value of ["0", "-1", "86401", "1.5", "soon"])
      expect(schema.safeParse(value).success).toBe(false);
  });
});

describe("sandbox HMAC secret schema", () => {
  const schema = serverVars.SANDBOX_REQUEST_HMAC_SECRET;
  it("accepts secret32 fixtures and at least 32 decoded bytes", () => {
    for (let i = 0; i < 4; i++) {
      const fixture = randomBytes(32 + i).toString("hex");
      expect(schema.parse(fixture)).toBe(fixture);
    }
    // The inherited checker is not a general repeated-block/entropy proof.
    expect(schema.safeParse("0123456789abcdef".repeat(4)).success).toBe(true);
  });
  it("rejects absent, short, odd, nonhex, placeholder, period-1/2 and low-distinct inputs", () => {
    for (const value of [
      undefined,
      "",
      "0123456789abcdef".repeat(2),
      `${"0123456789abcdef".repeat(4)}0`,
      `${"0123456789abcdef".repeat(4)}gg`,
      "replace-me".repeat(8),
      "a".repeat(64),
      "ab".repeat(32),
      "012345678".repeat(8),
    ]) {
      const result = schema.safeParse(value);
      expect(result.success).toBe(false);
      if (typeof value === "string" && value.length > 0) {
        expect(JSON.stringify(result.error)).not.toContain(value);
      }
    }
  });
});

describe("agent token expiry policy", () => {
  it("allows no expiry by default and parses only strict boolean flags", () => {
    const schema = serverVars.WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY;
    expect(schema.parse(undefined)).toBe(true);
    expect(schema.parse("true")).toBe(true);
    expect(schema.parse("false")).toBe(false);
    for (const value of ["", "TRUE", "False", "1", "0", "yes", true, false])
      expect(schema.safeParse(value).success).toBe(false);
  });
  it("defaults to 90 days and bounds integer lifetimes to 1..3650", () => {
    const schema = serverVars.WSSP_AGENT_TOKEN_MAX_LIFETIME_DAYS;
    expect(schema.parse(undefined)).toBe(90);
    expect(schema.parse("1")).toBe(1);
    expect(schema.parse("3650")).toBe(3650);
    for (const value of ["", "0", "3651", "-1", "1.5", "many", Infinity, NaN])
      expect(schema.safeParse(value).success).toBe(false);
  });
});
