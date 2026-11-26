import { expect, it } from "vitest";
import { formatGraceDuration, formatWait } from "./format-duration";

it.each([
  [259200, "en-US", "3 days"],
  [90060, "en-US", "1 day, 1 hour, 1 minute"],
  [0, "en-US", "0 seconds"],
  [259200, "es-MX", "3 días"],
  [90000, "es-MX", "1 día, 1 hora"],
] as const)(
  "formats %s seconds in %s without shortening the promise",
  (seconds, locale, expected) => {
    expect(formatGraceDuration(seconds, locale)).toBe(expected);
  },
);

it("a retry wait is one unit, rounded up", () => {
  expect(formatWait(0, "en-US")).toBe("1 second");
  expect(formatWait(45, "en-US")).toBe("45 seconds");
  expect(formatWait(61, "en-US")).toBe("2 minutes");
  expect(formatWait(3600, "en-US")).toBe("1 hour");
  expect(formatWait(86_399, "en-US")).toBe("24 hours");
  expect(formatWait(86_401, "es-MX")).toBe("2 días");
});
