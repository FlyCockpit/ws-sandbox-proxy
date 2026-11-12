import limits from "./limits.json";

/**
 * Login definition and bundle v1 bounds. `limits.json` is the single source:
 * the Rust crate (`crates/login-definition`) asserts its constants against the
 * same file, so a bound cannot drift between the two languages.
 */
export const LOGIN_DEFINITION_LIMITS = limits;

/** Exact upper bound of an encoded bundle v1 for a definition's `maxBytes`. */
export function bundleMaxEncodedBytes(maxBytes: number): number {
  return limits.bundleFixedMaxBytes + maxBytes;
}
