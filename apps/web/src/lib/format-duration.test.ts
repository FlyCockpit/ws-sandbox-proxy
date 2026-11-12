import { expect, it } from "vitest";
import { formatGraceDuration } from "./format-duration";

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
