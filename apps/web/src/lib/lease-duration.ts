import {
  isUnlimitedLeaseEnd,
  LEASE_FINITE_MAX_MS,
  LEASE_LIMIT_MIN_MS,
} from "@wssp/api/sandbox/lease-limits";

export { isUnlimitedLeaseEnd };

const UNITS = [
  ["d", 86_400_000, "day"],
  ["h", 3_600_000, "hour"],
  ["m", 60_000, "minute"],
] as const;

/**
 * A lease limit as typed in the dashboard: the same grammar as
 * `wssp host config set-max-lease` (`90m`, `6h`, `7d`; 5 minutes to 24 days).
 * Blank means "no limit from this layer" (null); anything else invalid is
 * `undefined`, never a guess.
 */
export function parseLeaseLimit(text: string): number | null | undefined {
  const value = text.trim();
  if (value === "") return null;
  const match = /^(\d{1,9})([mhd])$/.exec(value);
  if (!match) return undefined;
  const unit = UNITS.find(([suffix]) => suffix === match[2]);
  if (!unit) return undefined;
  const ms = Number(match[1]) * unit[1];
  return ms >= LEASE_LIMIT_MIN_MS && ms <= LEASE_FINITE_MAX_MS ? ms : undefined;
}

/** The editable form of a limit (`24h` reads better than `1d`). */
export function leaseLimitText(ms: number | null): string {
  if (ms === null) return "";
  for (const [suffix, scale] of UNITS)
    if (ms % scale === 0 && (suffix !== "d" || ms >= 2 * scale)) return `${ms / scale}${suffix}`;
  return `${Math.round(ms / 60_000)}m`;
}

/** A localized duration such as "6 hours" or "7 days". */
export function formatLeaseDuration(ms: number, locale: string): string {
  for (const [suffix, scale, unit] of UNITS)
    if (ms % scale === 0 && (suffix !== "d" || ms >= 2 * scale))
      return new Intl.NumberFormat(locale, { style: "unit", unit, unitDisplay: "long" }).format(
        ms / scale,
      );
  return new Intl.NumberFormat(locale, {
    style: "unit",
    unit: "minute",
    unitDisplay: "long",
  }).format(Math.round(ms / 60_000));
}
