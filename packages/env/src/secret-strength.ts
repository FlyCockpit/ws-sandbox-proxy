// Shared format/placeholder floor, not a measured entropy guarantee.
const WEAK_PLACEHOLDERS = [
  "changeme",
  "secret",
  "password",
  "your-secret-here",
  "replace-me",
  "placeholder",
];

/** @beta Retain for pools-create-api.md slice 2B; exact Knip export ignore. */
export function isWeakSecret(secret: string): string | null {
  // All-same-character strings (e.g. "aaaaaaaaaa…")
  if (new Set(secret).size === 1) {
    return "all characters are identical";
  }
  // Repeating hex-like patterns (e.g. "xxxxxxxx…", "00000000…")
  if (/^(.)\1+$/.test(secret) || /^(..)\1+$/.test(secret)) {
    return "repeating pattern detected";
  }
  // Known placeholder words (case-insensitive)
  const lower = secret.toLowerCase();
  for (const placeholder of WEAK_PLACEHOLDERS) {
    if (lower === placeholder || lower.includes(placeholder)) {
      return `contains placeholder word "${placeholder}"`;
    }
  }
  // Fewer than 10 distinct characters → low entropy
  if (new Set(secret).size < 10) {
    return `only ${new Set(secret).size} distinct characters (need at least 10)`;
  }
  return null;
}
