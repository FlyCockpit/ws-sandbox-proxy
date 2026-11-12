/**
 * The one byte-size format of the dashboard (M7-S19): binary multiples with
 * their IEC symbols (B, KiB, MiB, GiB, TiB), so the sandbox Files card, the
 * command output view and admin settings all read "1 GiB" for 1024³ bytes.
 * The number follows the UI locale; the symbols are language-neutral.
 */
const UNITS = ["B", "KiB", "MiB", "GiB", "TiB"] as const;

export function formatBytes(bytes: number, locale: string): string {
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const number = new Intl.NumberFormat(locale, {
    maximumFractionDigits: unit === 0 ? 0 : 1,
  }).format(value);
  return `${number} ${UNITS[unit]}`;
}
