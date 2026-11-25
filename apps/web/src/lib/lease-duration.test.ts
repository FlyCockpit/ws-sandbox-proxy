import { describe, expect, it } from "vitest";
import { formatLeaseDuration, leaseLimitText, parseLeaseLimit } from "./lease-duration";

describe("lease limit text (same grammar as wssp host config set-max-lease)", () => {
  it("parses blank as no limit and bounded durations exactly", () => {
    expect(parseLeaseLimit("")).toBeNull();
    expect(parseLeaseLimit("  ")).toBeNull();
    expect(parseLeaseLimit("5m")).toBe(300_000);
    expect(parseLeaseLimit("90m")).toBe(5_400_000);
    expect(parseLeaseLimit("6h")).toBe(21_600_000);
    expect(parseLeaseLimit("24d")).toBe(2_073_600_000);
    for (const invalid of ["4m", "25d", "6", "6H", "1.5h", "-1h", "unlimited", "6 h", "0h"])
      expect(parseLeaseLimit(invalid), invalid).toBeUndefined();
  });
  it("round-trips the editable form and formats a localized duration", () => {
    for (const ms of [300_000, 5_400_000, 21_600_000, 86_400_000, 604_800_000])
      expect(parseLeaseLimit(leaseLimitText(ms))).toBe(ms);
    expect(leaseLimitText(86_400_000)).toBe("24h");
    expect(leaseLimitText(null)).toBe("");
    expect(formatLeaseDuration(21_600_000, "en-US")).toBe("6 hours");
    expect(formatLeaseDuration(604_800_000, "en-US")).toBe("7 days");
  });
  it("shows a lease that is not a whole minute to the second, never rounded to minutes", () => {
    expect(formatLeaseDuration(20_000, "en-US")).toBe("20 seconds");
    expect(formatLeaseDuration(90_000, "en-US")).toBe("90 seconds");
    expect(formatLeaseDuration(120_000, "en-US")).toBe("2 minutes");
  });
});
