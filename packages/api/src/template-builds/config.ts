import type { Prisma } from "@wssp/db";
import { env } from "@wssp/env/server";
import { imageDistributionMode, layerQuota } from "../sandbox/image-store/config";
import { deploymentFiniteMaxMs } from "../sandbox/lease-policy";

/**
 * Template-build deployment configuration (plan template-builds §3.3, §7).
 * Resolved from the environment on every call (cheap, pure arithmetic) and
 * never throws: a missing prerequisite makes builds unavailable with a reason
 * instead of failing boot, and inconsistent byte budgets are clamped down.
 */

/** Slack between the end of the capture window and the build VM's lease. */
export const TEMPLATE_BUILD_LEASE_SLACK_MINUTES = 15;
/** Longest a sealed context may wait for placement (code constant, §3.7). */
export const TEMPLATE_BUILD_CONTEXT_SEALED_MAX_MS = 6 * 60 * 60 * 1000;

/**
 * Deployment-level reasons. `no_builder` is decided per request at placement
 * (no eligible builder node), never here. `storage_unavailable` is set at
 * runtime when the server could not open its build-context root.
 */
export type TemplateBuildsDisabledReason =
  | "off"
  | "image_distribution_off"
  | "lease_ceiling"
  | "storage_unavailable";

let storageUnavailable = false;

/**
 * The server marks builds unavailable when its build-context store could not
 * start (an optional feature never fails boot). Process-local: the server is
 * the only process that accepts builds and owns the context root.
 */
export function markTemplateBuildStorageUnavailable(unavailable = true): void {
  storageUnavailable = unavailable;
}

export type TemplateBuildsConfig = {
  enabled: boolean;
  reason: TemplateBuildsDisabledReason | null;
  /** Effective max minutes per build after the lease clamp (0 when disabled by it). */
  maxMinutes: number;
  /** TEMPLATE_BUILD_MAX_MINUTES as configured. */
  configuredMaxMinutes: number;
  /** True when the lease ceiling lowered `maxMinutes` below the configured value. */
  maxMinutesClamped: boolean;
  captureWindowMinutes: number;
  /** Deployment ceilings; null is unlimited. Admins may only lower them. */
  maxConcurrentPerAccount: number | null;
  minutesPerMonth: number | null;
  contextMaxBytes: number;
  contextStagedBytesPerAccount: number;
  contextStagedBytes: number;
  /** Clamp on a COPY build's waitForCapacityMs (reported as contextWaitMaxMs). */
  contextWaitMaxMs: number;
  /** The deployment's largest finite lease the clamp was computed from. */
  leaseCeilingMs: number;
  /** Human-readable clamp notes (variable names only, never values of secrets). */
  adjustments: string[];
};

export type TemplateBuildsEnv = {
  TEMPLATE_BUILDS: "auto" | "off";
  TEMPLATE_BUILD_MAX_MINUTES: number;
  TEMPLATE_BUILD_MAX_CONCURRENT_PER_ACCOUNT: number | null;
  TEMPLATE_BUILD_MINUTES_PER_MONTH: number | null;
  TEMPLATE_BUILD_CAPTURE_WINDOW_MINUTES: number;
  TEMPLATE_BUILD_CONTEXT_MAX_BYTES: number;
  TEMPLATE_BUILD_CONTEXT_STAGED_BYTES_PER_ACCOUNT: number;
  TEMPLATE_BUILD_CONTEXT_STAGED_BYTES: number;
  TRANSFER_MAX_BYTES: number;
};

/** Pure resolution, shared by the env wrapper and unit tests. */
export function resolveTemplateBuildsConfig(input: {
  env: TemplateBuildsEnv;
  imageDistribution: "off" | "peer" | "s3";
  leaseCeilingMs: number;
}): TemplateBuildsConfig {
  const { env: vars } = input;
  const adjustments: string[] = [];
  const captureWindowMinutes = vars.TEMPLATE_BUILD_CAPTURE_WINDOW_MINUTES;
  const configuredMaxMinutes = vars.TEMPLATE_BUILD_MAX_MINUTES;
  const room =
    Math.floor(input.leaseCeilingMs / 60_000) -
    captureWindowMinutes -
    TEMPLATE_BUILD_LEASE_SLACK_MINUTES;
  const fits = room >= 1;
  const maxMinutes = fits ? Math.min(configuredMaxMinutes, room) : 0;
  const maxMinutesClamped = fits && maxMinutes < configuredMaxMinutes;
  if (maxMinutesClamped)
    adjustments.push(
      `TEMPLATE_BUILD_MAX_MINUTES lowered to ${maxMinutes} so build + TEMPLATE_BUILD_CAPTURE_WINDOW_MINUTES + ${TEMPLATE_BUILD_LEASE_SLACK_MINUTES} min fits SANDBOX_MAX_TIMEOUT_MS`,
    );

  const contextStagedBytes = vars.TEMPLATE_BUILD_CONTEXT_STAGED_BYTES;
  const contextStagedBytesPerAccount = Math.min(
    vars.TEMPLATE_BUILD_CONTEXT_STAGED_BYTES_PER_ACCOUNT,
    contextStagedBytes,
  );
  if (contextStagedBytesPerAccount < vars.TEMPLATE_BUILD_CONTEXT_STAGED_BYTES_PER_ACCOUNT)
    adjustments.push(
      "TEMPLATE_BUILD_CONTEXT_STAGED_BYTES_PER_ACCOUNT lowered to TEMPLATE_BUILD_CONTEXT_STAGED_BYTES",
    );
  const contextMaxBytes = Math.min(
    vars.TEMPLATE_BUILD_CONTEXT_MAX_BYTES,
    vars.TRANSFER_MAX_BYTES,
    contextStagedBytesPerAccount,
  );
  if (contextMaxBytes < vars.TEMPLATE_BUILD_CONTEXT_MAX_BYTES)
    adjustments.push(
      "TEMPLATE_BUILD_CONTEXT_MAX_BYTES lowered to fit TRANSFER_MAX_BYTES and the staged-context budgets",
    );

  const reason: TemplateBuildsDisabledReason | null =
    vars.TEMPLATE_BUILDS === "off"
      ? "off"
      : input.imageDistribution === "off"
        ? "image_distribution_off"
        : !fits
          ? "lease_ceiling"
          : null;
  return {
    enabled: reason === null,
    reason,
    maxMinutes,
    configuredMaxMinutes,
    maxMinutesClamped,
    captureWindowMinutes,
    maxConcurrentPerAccount: vars.TEMPLATE_BUILD_MAX_CONCURRENT_PER_ACCOUNT,
    minutesPerMonth: vars.TEMPLATE_BUILD_MINUTES_PER_MONTH,
    contextMaxBytes,
    contextStagedBytesPerAccount,
    contextStagedBytes,
    contextWaitMaxMs: TEMPLATE_BUILD_CONTEXT_SEALED_MAX_MS,
    leaseCeilingMs: input.leaseCeilingMs,
    adjustments,
  };
}

/** Schema defaults, for a test env that omits a variable. */
const DEFAULTS: TemplateBuildsEnv = {
  TEMPLATE_BUILDS: "auto",
  TEMPLATE_BUILD_MAX_MINUTES: 60,
  TEMPLATE_BUILD_MAX_CONCURRENT_PER_ACCOUNT: 2,
  TEMPLATE_BUILD_MINUTES_PER_MONTH: 1000,
  TEMPLATE_BUILD_CAPTURE_WINDOW_MINUTES: 60,
  TEMPLATE_BUILD_CONTEXT_MAX_BYTES: 1024 ** 3,
  TEMPLATE_BUILD_CONTEXT_STAGED_BYTES_PER_ACCOUNT: 2 * 1024 ** 3,
  TEMPLATE_BUILD_CONTEXT_STAGED_BYTES: 8 * 1024 ** 3,
  TRANSFER_MAX_BYTES: 1024 ** 3,
};

function templateBuildsEnv(): TemplateBuildsEnv {
  const read = <K extends keyof TemplateBuildsEnv>(key: K): TemplateBuildsEnv[K] => {
    const value = (env as Partial<TemplateBuildsEnv>)[key];
    return value === undefined ? DEFAULTS[key] : value;
  };
  return {
    TEMPLATE_BUILDS: read("TEMPLATE_BUILDS"),
    TEMPLATE_BUILD_MAX_MINUTES: read("TEMPLATE_BUILD_MAX_MINUTES"),
    TEMPLATE_BUILD_MAX_CONCURRENT_PER_ACCOUNT: read("TEMPLATE_BUILD_MAX_CONCURRENT_PER_ACCOUNT"),
    TEMPLATE_BUILD_MINUTES_PER_MONTH: read("TEMPLATE_BUILD_MINUTES_PER_MONTH"),
    TEMPLATE_BUILD_CAPTURE_WINDOW_MINUTES: read("TEMPLATE_BUILD_CAPTURE_WINDOW_MINUTES"),
    TEMPLATE_BUILD_CONTEXT_MAX_BYTES: read("TEMPLATE_BUILD_CONTEXT_MAX_BYTES"),
    TEMPLATE_BUILD_CONTEXT_STAGED_BYTES_PER_ACCOUNT: read(
      "TEMPLATE_BUILD_CONTEXT_STAGED_BYTES_PER_ACCOUNT",
    ),
    TEMPLATE_BUILD_CONTEXT_STAGED_BYTES: read("TEMPLATE_BUILD_CONTEXT_STAGED_BYTES"),
    TRANSFER_MAX_BYTES: read("TRANSFER_MAX_BYTES"),
  };
}

const logged = new Set<string>();

/**
 * The deployment's template-build configuration. Never throws; each clamp or
 * disable reason is logged once per process (the server calls this at start).
 */
export function templateBuildsConfig(): TemplateBuildsConfig {
  const resolved = resolveTemplateBuildsConfig({
    env: templateBuildsEnv(),
    imageDistribution: imageDistributionMode(),
    leaseCeilingMs: deploymentFiniteMaxMs(),
  });
  const config: TemplateBuildsConfig =
    storageUnavailable && resolved.enabled
      ? { ...resolved, enabled: false, reason: "storage_unavailable" }
      : resolved;
  const notes = [
    ...config.adjustments,
    ...(config.reason && config.reason !== "off"
      ? [`template builds unavailable: ${config.reason}`]
      : []),
  ];
  for (const note of notes)
    if (!logged.has(note)) {
      logged.add(note);
      console.warn(`[template-builds] ${note}`);
    }
  return config;
}

export type TemplateBuildQuotas = {
  maxConcurrent: number | null;
  minutesPerMonth: number | null;
};

/** Per-account build quotas: admin overrides only ever lower the deployment ceiling. */
export async function accountTemplateBuildQuotas(
  tx: Pick<Prisma.TransactionClient, "accountImagePolicy">,
  ownerId: string,
  config: TemplateBuildsConfig = templateBuildsConfig(),
): Promise<TemplateBuildQuotas> {
  const policy = await tx.accountImagePolicy.findUnique({
    where: { userId: ownerId },
    select: { adminConcurrentBuildsMax: true, adminBuildMinutesPerMonthMax: true },
  });
  return {
    maxConcurrent: layerQuota(config.maxConcurrentPerAccount, policy?.adminConcurrentBuildsMax),
    minutesPerMonth: layerQuota(config.minutesPerMonth, policy?.adminBuildMinutesPerMonthMax),
  };
}

/** `capabilities.limits.templateBuilds` for one caller's owner. */
export async function templateBuildCapabilities(
  tx: Pick<Prisma.TransactionClient, "accountImagePolicy">,
  ownerId: string,
) {
  const config = templateBuildsConfig();
  const quotas = await accountTemplateBuildQuotas(tx, ownerId, config);
  return {
    enabled: config.enabled,
    reason: config.reason,
    maxMinutes: config.maxMinutes,
    maxConcurrent: quotas.maxConcurrent,
    minutesPerMonth: quotas.minutesPerMonth,
    contextMaxBytes: config.contextMaxBytes,
    contextWaitMaxMs: config.contextWaitMaxMs,
    // Builds follow the default-open egress plan (§6.3).
    openEgress: true,
  };
}
