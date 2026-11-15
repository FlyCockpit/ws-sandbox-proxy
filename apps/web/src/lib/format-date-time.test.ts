import { describe, expect, it } from "vitest";
import { dateTimeTitle, formatDateTime } from "./format-date-time";

// ICU separates the time and the day period with a narrow no-break space.
const plain = (text: string) => text.replace(/[  ]/g, " ");

const WINTER = "2026-01-15T09:28:04Z";
const SUMMER = "2026-07-15T09:28:04Z";

describe("formatDateTime", () => {
  it("always names the zone, following daylight saving time", () => {
    expect(plain(formatDateTime(WINTER, "en-US", { timeZone: "America/Chicago" }))).toBe(
      "Jan 15, 2026, 3:28 AM CST",
    );
    expect(plain(formatDateTime(SUMMER, "en-US", { timeZone: "America/Chicago" }))).toBe(
      "Jul 15, 2026, 4:28 AM CDT",
    );
    expect(plain(formatDateTime(WINTER, "en-US", { timeZone: "UTC" }))).toBe(
      "Jan 15, 2026, 9:28 AM UTC",
    );
  });

  it("uses a GMT offset where the locale has no abbreviation", () => {
    expect(plain(formatDateTime(SUMMER, "en-US", { timeZone: "Europe/Berlin" }))).toBe(
      "Jul 15, 2026, 11:28 AM GMT+2",
    );
    expect(plain(formatDateTime(WINTER, "es-MX", { timeZone: "America/Chicago" }))).toBe(
      "15 ene 2026, 3:28 a.m. GMT-6",
    );
  });

  it("adds seconds on request and accepts dates, strings and epoch milliseconds", () => {
    const expected = "Jan 15, 2026, 9:28:04 AM UTC";
    for (const value of [WINTER, new Date(WINTER), Date.parse(WINTER)]) {
      expect(plain(formatDateTime(value, "en-US", { seconds: true, timeZone: "UTC" }))).toBe(
        expected,
      );
    }
  });

  it("never throws on a value that is not a date", () => {
    expect(formatDateTime("not a date", "en-US")).toBe("—");
    expect(formatDateTime(Number.NaN, "en-US")).toBe("—");
  });
});

describe("dateTimeTitle", () => {
  it("is the absolute time with seconds and zone, or no title without a valid moment", () => {
    expect(plain(dateTimeTitle(WINTER, "en-US", "America/Chicago") ?? "")).toBe(
      "Jan 15, 2026, 3:28:04 AM CST",
    );
    expect(dateTimeTitle(null, "en-US")).toBeUndefined();
    expect(dateTimeTitle(undefined, "en-US")).toBeUndefined();
    expect(dateTimeTitle("garbage", "en-US")).toBeUndefined();
  });
});
