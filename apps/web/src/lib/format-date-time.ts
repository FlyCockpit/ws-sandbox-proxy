/**
 * The dashboard's one absolute date-time format. Every absolute time carries
 * its time zone ("Nov 15, 2026, 3:28 AM CST"), so a reader never has to guess
 * whether a server timestamp is local or UTC. The zone is the browser's
 * (`timeZone` is for tests and deliberate overrides); its abbreviation or
 * GMT offset comes from `Intl` for that instant, so it follows daylight
 * saving time (CST in January, CDT in July).
 *
 * Relative times ("3 minutes ago") put this string, with seconds, in their
 * `title` so the exact moment and zone are one hover away.
 */
type DateTimeInput = Date | string | number;

/** Shown for a value that is not a valid date (`Intl` would throw `RangeError`). */
const INVALID = "—";

export function formatDateTime(
  value: DateTimeInput,
  locale: string,
  options: { seconds?: boolean; timeZone?: string } = {},
): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return INVALID;
  return new Intl.DateTimeFormat(locale, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    ...(options.seconds ? { second: "2-digit" } : {}),
    timeZoneName: "short",
    ...(options.timeZone ? { timeZone: options.timeZone } : {}),
  }).format(date);
}

/**
 * The `title` for a relative time: the absolute moment with seconds and zone,
 * or no title when there is no moment (or it is not a valid date).
 */
export function dateTimeTitle(
  value: DateTimeInput | null | undefined,
  locale: string,
  timeZone?: string,
): string | undefined {
  if (value == null || Number.isNaN(new Date(value).getTime())) return undefined;
  return formatDateTime(value, locale, { seconds: true, timeZone });
}
