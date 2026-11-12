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
