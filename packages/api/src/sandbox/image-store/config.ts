import type { Prisma } from "@wssp/db";
import {
  type ImageStoreMode,
  imageStoreMode,
  readImageStoreEnv,
} from "@wssp/env/image-store-config";

export type { ImageStoreMode };

/** off / peer / s3, from the deployment environment (never per request). */
export function imageDistributionMode(): ImageStoreMode {
  return imageStoreMode(readImageStoreEnv());
}

/** Lease-from-READY follows the kill switch: `off` keeps today's behaviour exactly. */
export function leaseFromReadyEnabled(): boolean {
  return imageDistributionMode() !== "off";
}

export type EffectivePlacement = "ANY_NODE" | "OWNED_NODES_ONLY";

/**
 * Where fetched copies of a template's images may go: the template's own
 * setting, or the owner's account default when the template inherits.
 */
export async function effectiveImagePlacement(
  tx: Prisma.TransactionClient,
  ownerId: string,
  templateId: string,
): Promise<EffectivePlacement> {
  const template = await tx.sandboxTemplate.findFirst({
    where: { id: templateId, userId: ownerId },
    select: { imagePlacement: true },
  });
  if (template && template.imagePlacement !== "INHERIT") return template.imagePlacement;
  const policy = await tx.accountImagePolicy.findUnique({
    where: { userId: ownerId },
    select: { imagePlacement: true },
  });
  return policy?.imagePlacement ?? "ANY_NODE";
}

export type ImageQuotas = { maxStoredGiB: number | null; downloadsPerHour: number | null };

/** Admin overrides only ever lower the deployment ceiling (null = unlimited). */
export function layerQuota(
  ceiling: number | null,
  admin: number | null | undefined,
): number | null {
  if (admin == null) return ceiling;
  return ceiling == null ? admin : Math.min(ceiling, admin);
}

export async function accountImageQuotas(
  tx: Pick<Prisma.TransactionClient, "accountImagePolicy">,
  ownerId: string,
): Promise<ImageQuotas> {
  const policy = await tx.accountImagePolicy.findUnique({
    where: { userId: ownerId },
    select: { adminStoredGiBMax: true, adminDownloadsPerHourMax: true },
  });
  return {
    maxStoredGiB: layerQuota(
      readImageStoreEnv().IMAGE_STORE_MAX_GIB_PER_ACCOUNT,
      policy?.adminStoredGiBMax,
    ),
    downloadsPerHour: layerQuota(
      readImageStoreEnv().IMAGE_DOWNLOADS_PER_HOUR_MAX,
      policy?.adminDownloadsPerHourMax,
    ),
  };
}

/**
 * S3 bytes counted against the stored-GiB quota (in flight or stored).
 * PostgreSQL `sum(bigint)` is `numeric` (a Prisma Decimal in JS), so the
 * aggregate is cast back to an exact `bigint` in SQL and re-checked here.
 */
export async function accountStoredImageBytes(
  tx: Pick<Prisma.TransactionClient, "$queryRaw">,
  ownerId: string,
): Promise<bigint> {
  const rows = await tx.$queryRaw<{ total: unknown }[]>`
    SELECT COALESCE(sum("sizeBytes"), 0)::bigint AS total FROM sandbox_image_artifact
    WHERE "userId" = ${ownerId} AND "storeKind" = 'S3'
      AND state IN ('UPLOADING', 'VERIFYING', 'STORED')`;
  return exactBigint(rows[0]?.total);
}

/** An aggregate column as an exact bigint (never a Decimal or a float). */
export function exactBigint(value: unknown): bigint {
  if (value == null) return 0n;
  if (typeof value === "bigint") return value;
  if (typeof value === "number" && Number.isSafeInteger(value)) return BigInt(value);
  const text = String(value);
  if (!/^-?\d+$/.test(text)) throw new TypeError("aggregate is not an exact integer");
  return BigInt(text);
}

/**
 * Serializes an account's image quota decisions across all hosts (P2-6): the
 * owner placement advisory lock, which precedes every host lock (H) in the
 * lock order. Count-and-reserve (download grants, stored-byte uploads) runs
 * under it, so two hosts can never both take the last allowance.
 */
export async function lockImageQuota(
  tx: Pick<Prisma.TransactionClient, "$queryRaw">,
  ownerId: string,
) {
  await tx.$queryRaw`SELECT 1 AS locked FROM pg_advisory_xact_lock(hashtextextended(${ownerId}, 31))`;
}

let schedulerWake: (() => void) | null = null;
/** The server binds its image scheduler's wake-up (null on shutdown). */
export function bindImageSchedulerWake(wake: (() => void) | null): void {
  schedulerWake = wake;
}
/** Run the image scheduler now (no-op outside the server process). */
export function wakeImageScheduler(): void {
  schedulerWake?.();
}

/** Admitted image features a host reported for its current connection. */
export type HostImageFeatures = {
  fetch: boolean;
  serve: boolean;
  publish: boolean;
  capture: boolean;
  acceptForeign: boolean;
  leaseFromReady: boolean;
  /** Template builds (D2: on unless the node sets `builder = false`). */
  build: boolean;
  /** Builds for other accounts (opt-in on the node). */
  acceptForeignBuilds: boolean;
  captureStorageMarkers: string[];
};

export function hostImageFeatures(
  daemonFeatures: Prisma.JsonValue | null,
): HostImageFeatures | null {
  if (!daemonFeatures || typeof daemonFeatures !== "object" || Array.isArray(daemonFeatures))
    return null;
  const image = daemonFeatures.image;
  if (!image || typeof image !== "object" || Array.isArray(image)) return null;
  const flag = (key: string) => image[key] === true;
  const markers = Array.isArray(image.captureStorageMarkers)
    ? image.captureStorageMarkers.filter((m): m is string => typeof m === "string")
    : [];
  return {
    fetch: flag("fetch"),
    serve: flag("serve"),
    publish: flag("publish"),
    capture: flag("capture"),
    acceptForeign: flag("acceptForeign"),
    leaseFromReady: flag("leaseFromReady"),
    build: flag("build"),
    acceptForeignBuilds: flag("acceptForeignBuilds"),
    captureStorageMarkers: markers,
  };
}
