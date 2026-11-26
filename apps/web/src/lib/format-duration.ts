/** Pool grace is a promise: retain every nonzero unit rather than rounding it down. */
export function formatGraceDuration(seconds: number, locale: string): string {
  const parts: string[] = [];
  let remaining = seconds;
  for (const [unit, size] of [
    ["day", 86400],
    ["hour", 3600],
    ["minute", 60],
    ["second", 1],
  ] as const) {
    const value = Math.floor(remaining / size);
    remaining %= size;
    if (value || (unit === "second" && !parts.length))
      parts.push(
        new Intl.NumberFormat(locale, { style: "unit", unit, unitDisplay: "long" }).format(value),
      );
  }
  return parts.join(", ");
}

/**
 * How long to wait before trying again ("3 minutes", "1 day"): the largest
 * unit only, rounded up, so the person never comes back too early.
 */
export function formatWait(seconds: number, locale: string): string {
  const wait = Math.max(1, Math.ceil(seconds));
  const [unit, value] =
    wait < 60
      ? (["second", wait] as const)
      : wait < 3600
        ? (["minute", Math.ceil(wait / 60)] as const)
        : wait < 86400
          ? (["hour", Math.ceil(wait / 3600)] as const)
          : (["day", Math.ceil(wait / 86400)] as const);
  return new Intl.NumberFormat(locale, { style: "unit", unit, unitDisplay: "long" }).format(value);
}
