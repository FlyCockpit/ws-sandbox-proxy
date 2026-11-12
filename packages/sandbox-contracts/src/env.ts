import limits from "./env-limits.json";
import { envShapeSchema } from "./env-shape";

export const ENV_LIMITS = Object.freeze(limits);
const encoder = new TextEncoder();

/** ASCII POSIX names sort identically in TS, Rust and Python. */
export function canonicalEnvJson(envs: Record<string, string>): string {
  return JSON.stringify(
    Object.fromEntries(
      Object.keys(envs)
        .sort()
        .map((key) => [key, envs[key]]),
    ),
  );
}

export const envSchema = envShapeSchema
  .refine((envs) => {
    const entries = Object.entries(envs);
    return (
      entries.length <= ENV_LIMITS.maxEntries &&
      entries.every(
        ([key, value]) =>
          encoder.encode(key).byteLength <= ENV_LIMITS.keyBytes &&
          encoder.encode(value).byteLength <= ENV_LIMITS.valueBytes,
      ) &&
      encoder.encode(canonicalEnvJson(envs)).byteLength <= ENV_LIMITS.jsonBytes
    );
  }, "sandbox.env_invalid")
  .meta({
    maxProperties: ENV_LIMITS.maxEntries,
    "x-wssp-maxKeyBytes": ENV_LIMITS.keyBytes,
    "x-wssp-maxValueBytes": ENV_LIMITS.valueBytes,
    "x-wssp-maxCanonicalJsonBytes": ENV_LIMITS.jsonBytes,
    description:
      "Unique POSIX names and string values; limits count UTF-8 bytes of sorted escaped JSON. NUL, malformed Unicode and prototype names are rejected. Command HOME/SHELL overrides are ignored.",
  });

export const defaultEnvSchema = envSchema
  .refine(
    (value) => !["HOME", "SHELL", "TERM"].some((key) => Object.hasOwn(value, key)),
    "sandbox.env_invalid",
  )
  .meta({
    ...envSchema.meta(),
    description:
      "Unique POSIX names and string values; limits count UTF-8 bytes of sorted escaped JSON. NUL, malformed Unicode and prototype names are rejected. Stored defaults and create envs reject reserved HOME, SHELL and TERM names.",
  });

/** Size the private four-field tuple envelope without changing the public map. */
export function commandPayloadBytes(parts: {
  argv?: string[];
  script?: string;
  cwd?: string;
  envs?: Record<string, string>;
}): number {
  const envs = parts.envs ?? {};
  const mapBytes = encoder.encode(canonicalEnvJson(envs)).byteLength;
  return (
    encoder.encode(
      JSON.stringify({
        argv: parts.argv ?? null,
        script: parts.script ?? null,
        cwd: parts.cwd ?? null,
        env: [],
      }),
    ).byteLength +
    mapBytes -
    2 +
    2 * Object.keys(envs).length
  );
}
