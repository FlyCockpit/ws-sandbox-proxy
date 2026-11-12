import { sharedVars } from "./vars/shared.js";

/**
 * Cross-variable rules for the template image store. Side-effect free so the
 * env schema, tests and the API's image-store module share one definition.
 */
export interface ImageStoreEnv {
  IMAGE_DISTRIBUTION?: "auto" | "off";
  IMAGE_S3_ENDPOINT?: string;
  IMAGE_S3_BUCKET?: string;
  IMAGE_S3_ACCESS_KEY_ID?: string;
  IMAGE_S3_SECRET_ACCESS_KEY?: string;
  IMAGE_STORE_ENCRYPTION?: "on" | "off";
  IMAGE_STORE_ENCRYPTION_KEY?: string;
}

export type ImageStoreMode = "off" | "peer" | "s3";

/** Problems that refuse boot. Never includes a value, only variable names. */
export function imageStoreConfigProblems(env: ImageStoreEnv): string[] {
  const problems: string[] = [];
  const keys = [env.IMAGE_S3_ACCESS_KEY_ID, env.IMAGE_S3_SECRET_ACCESS_KEY].filter(Boolean).length;
  if (env.IMAGE_S3_BUCKET && keys !== 2)
    problems.push(
      "IMAGE_S3_BUCKET requires both IMAGE_S3_ACCESS_KEY_ID and IMAGE_S3_SECRET_ACCESS_KEY.",
    );
  if (!env.IMAGE_S3_BUCKET && keys > 0)
    problems.push(
      "IMAGE_S3_ACCESS_KEY_ID/IMAGE_S3_SECRET_ACCESS_KEY are set without IMAGE_S3_BUCKET.",
    );
  if (env.IMAGE_S3_BUCKET && !env.IMAGE_S3_ENDPOINT)
    problems.push("IMAGE_S3_BUCKET requires IMAGE_S3_ENDPOINT.");
  if (env.IMAGE_STORE_ENCRYPTION === "on" && !env.IMAGE_STORE_ENCRYPTION_KEY)
    problems.push("IMAGE_STORE_ENCRYPTION=on requires IMAGE_STORE_ENCRYPTION_KEY.");
  return problems;
}

export function imageStoreMode(env: ImageStoreEnv): ImageStoreMode {
  if (env.IMAGE_DISTRIBUTION === "off") return "off";
  return env.IMAGE_S3_BUCKET && env.IMAGE_S3_ACCESS_KEY_ID && env.IMAGE_S3_SECRET_ACCESS_KEY
    ? "s3"
    : "peer";
}

/**
 * The image-store variables, parsed with their declared schemas from the
 * process environment. Side-effect free (no whole-environment validation),
 * so API modules shared with the worker and tests can read them; the boot
 * modules (`./shared`, `./server`) still validate everything at startup.
 */
export function readImageStoreEnv(source: Record<string, string | undefined> = process.env) {
  const read = <K extends keyof typeof sharedVars>(key: K) =>
    sharedVars[key].parse(source[key] === "" ? undefined : source[key]) as ReturnType<
      (typeof sharedVars)[K]["parse"]
    >;
  return {
    IMAGE_DISTRIBUTION: read("IMAGE_DISTRIBUTION"),
    IMAGE_S3_ENDPOINT: read("IMAGE_S3_ENDPOINT"),
    IMAGE_S3_REGION: read("IMAGE_S3_REGION"),
    IMAGE_S3_BUCKET: read("IMAGE_S3_BUCKET"),
    IMAGE_S3_ACCESS_KEY_ID: read("IMAGE_S3_ACCESS_KEY_ID"),
    IMAGE_S3_SECRET_ACCESS_KEY: read("IMAGE_S3_SECRET_ACCESS_KEY"),
    IMAGE_S3_FORCE_PATH_STYLE: read("IMAGE_S3_FORCE_PATH_STYLE"),
    IMAGE_S3_PUBLIC_ENDPOINT: read("IMAGE_S3_PUBLIC_ENDPOINT"),
    IMAGE_S3_PREFIX: read("IMAGE_S3_PREFIX"),
    IMAGE_S3_PRESIGN_TTL_SECONDS: read("IMAGE_S3_PRESIGN_TTL_SECONDS"),
    IMAGE_STORE_ENCRYPTION: read("IMAGE_STORE_ENCRYPTION"),
    IMAGE_STORE_ENCRYPTION_KEY: read("IMAGE_STORE_ENCRYPTION_KEY"),
    IMAGE_GC_GRACE_DAYS: read("IMAGE_GC_GRACE_DAYS"),
    IMAGE_STORE_MAX_GIB_PER_ACCOUNT: read("IMAGE_STORE_MAX_GIB_PER_ACCOUNT"),
    IMAGE_DOWNLOADS_PER_HOUR_MAX: read("IMAGE_DOWNLOADS_PER_HOUR_MAX"),
  };
}

/**
 * The stopped-sandbox disk offload variables, parsed like
 * `readImageStoreEnv` (side-effect free, declared schemas, empty = unset).
 */
export function readSandboxOffloadEnv(source: Record<string, string | undefined> = process.env) {
  const read = <K extends keyof typeof sharedVars>(key: K) =>
    sharedVars[key].parse(source[key] === "" ? undefined : source[key]) as ReturnType<
      (typeof sharedVars)[K]["parse"]
    >;
  return {
    SANDBOX_OFFLOAD: read("SANDBOX_OFFLOAD"),
    SANDBOX_OFFLOAD_MAX_GIB_PER_ACCOUNT: read("SANDBOX_OFFLOAD_MAX_GIB_PER_ACCOUNT"),
    SANDBOX_OFFLOAD_GIB_PER_DAY: read("SANDBOX_OFFLOAD_GIB_PER_DAY"),
    SANDBOX_OFFLOAD_SHRED_GRACE_HOURS: read("SANDBOX_OFFLOAD_SHRED_GRACE_HOURS"),
  };
}
