const INCUS_IMAGE_MAX_LENGTH = 128;

/** Shared with `crates/sandbox-runtime/src/image.rs` malicious fixtures. */
export const MALICIOUS_INCUS_IMAGE_REFS: readonly string[] = [
  "--project=default",
  "-csecurity.privileged=true",
  "--storage=attacker",
  "-ubuntu",
  "--vm",
  "images:ubuntu/24.04/cloud%00",
  " images:ubuntu/24.04/cloud",
];

function looksLikeContentDigest(value: string): boolean {
  return /^sha(1|256|512):[0-9a-fA-F]+$/.test(value);
}

/** Charset/length mirror instance names, plus `:`/`/` for `remote:alias/path`. */
function isStrictIncusImageCharset(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed !== value) return false;
  if (trimmed.length === 0 || trimmed.length > INCUS_IMAGE_MAX_LENGTH) return false;
  if (trimmed.startsWith("-") || trimmed.includes("%") || trimmed.includes("\\")) return false;
  return /^[A-Za-z0-9][A-Za-z0-9:/_.-]*$/.test(trimmed);
}

/** Operator alias references accepted at template registration (not content digests). */
export function isIncusImageRef(value: string): boolean {
  if (value.length === 0 || value.toLowerCase() === "unknown") {
    return false;
  }
  if (looksLikeContentDigest(value)) {
    return false;
  }
  if (isIncusFingerprint(value)) {
    return false;
  }
  return isStrictIncusImageCharset(value);
}

/** Canonical application/wire identity; raw Incus hex is adapted by the host. */
export function isIncusFingerprint(value: string): boolean {
  return /^sha256:[0-9a-f]{64}$/.test(value);
}

export function normalizeIncusFingerprint(value: string): string {
  if (!isIncusFingerprint(value)) throw new Error("invalid Incus fingerprint");
  return value;
}

/** Launch/dispatch uses the pinned fingerprint; aliases are not replay authority. */
export function resolveIncusLaunchFingerprint(incusFingerprint: string): string | undefined {
  if (!isIncusFingerprint(incusFingerprint)) return undefined;
  return normalizeIncusFingerprint(incusFingerprint);
}
