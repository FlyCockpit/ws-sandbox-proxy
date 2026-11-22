import { HOST_HEARTBEAT_STALE_AFTER_MS } from "@wssp/config/host-status";
import type { Prisma } from "@wssp/db";
import { Prisma as PrismaValue } from "@wssp/db/client";
import {
  type EffectivePlacement,
  effectiveImagePlacement,
  hostImageFeatures,
  imageDistributionMode,
} from "./image-store/config";

/**
 * Image-fetch placement (docs/operations/templates.md#image-distribution).
 *
 * These are ADDITIVE predicate fragments: a host passes the "template known"
 * stage when it has an availability row OR the image is fetchable to it, and
 * the "template current" stage when the row is AVAILABLE on its current
 * epoch OR the fetch is currently admissible. Nothing here re-splits stages.
 */
type StoredFetchPlan = {
  mode: "peer" | "s3";
  fingerprint: string;
  architecture: string;
  sizeBytes: bigint;
  policy: EffectivePlacement;
};
/** The pinned split files of an UPSTREAM revision (community-base S7). The
 * daemon downloads them itself from the fixed index host. */
export type UpstreamImageFacts = {
  metaPath: string;
  metaSha256: string;
  metaSize: bigint;
  diskPath: string;
  diskSha256: string;
  diskSize: bigint;
};
type UpstreamFetchPlan = {
  mode: "upstream";
  fingerprint: string;
  architecture: string;
  /** meta + disk bytes (the cache reservation). */
  sizeBytes: bigint;
  policy: EffectivePlacement;
  upstream: UpstreamImageFacts;
};
export type ImageFetchPlan = StoredFetchPlan | UpstreamFetchPlan;

type PlanRevision = {
  id: string;
  templateId: string;
  incusFingerprint: string;
  architecture: string;
  sourceKind: string;
};

const ACTIVE_STATES = PrismaValue.sql`('QUEUED','DISPATCHED','ACCEPTED','RUNNING','CANCEL_REQUESTED')`;

/**
 * The database clock at the statement that evaluates it, at the columns'
 * millisecond precision: the upper bound of a freshness window ("reported no
 * later than now"). A placement samples its `now` early and runs several
 * statements after it, and a host's report (storage health every 5 s, a
 * heartbeat) committed in between carries a later `clock_timestamp()`: compared
 * with the early `now` it looked future-dated and the host was dropped
 * (`pool_full` reason `storage`). Any row a statement can see committed before
 * that statement, so its stamp is never after this clock; a row really dated
 * in the future (a clock stepped back) is still refused. Lower bounds stay on
 * the sampled `now`.
 */
export const STATEMENT_NOW = PrismaValue.sql`(clock_timestamp() AT TIME ZONE 'UTC')::timestamp(3)`;

/** The one fetch plan for this owner's revision, or null when nothing is fetchable. */
export async function imageFetchPlan(
  tx: Prisma.TransactionClient,
  ownerId: string,
  revision: PlanRevision,
): Promise<ImageFetchPlan | null> {
  const mode = imageDistributionMode();
  if (mode === "off") return null;
  const policy = await effectiveImagePlacement(tx, ownerId, revision.templateId);
  // An UPSTREAM revision is never served from the store or a peer: its only
  // copy source is the fixed index host, fetched by a builder (I12, S7).
  // Only a community build VM create materializes this plan.
  if (revision.sourceKind === "UPSTREAM") {
    const image = await tx.sandboxUpstreamImage.findFirst({
      where: { revisionId: revision.id, userId: ownerId, fingerprint: revision.incusFingerprint },
      select: {
        metaPath: true,
        metaSha256: true,
        metaSize: true,
        diskPath: true,
        diskSha256: true,
        diskSize: true,
      } satisfies Prisma.SandboxUpstreamImageSelect,
    });
    return image
      ? {
          mode: "upstream",
          fingerprint: revision.incusFingerprint,
          architecture: revision.architecture,
          sizeBytes: image.metaSize + image.diskSize,
          policy,
          upstream: image,
        }
      : null;
  }
  if (mode === "s3") {
    const artifact = await tx.sandboxImageArtifact.findFirst({
      where: {
        userId: ownerId,
        fingerprint: revision.incusFingerprint,
        architecture: revision.architecture,
        state: "STORED",
        storeKind: "S3",
      },
      select: { sizeBytes: true },
    });
    return artifact
      ? {
          mode,
          fingerprint: revision.incusFingerprint,
          architecture: revision.architecture,
          sizeBytes: artifact.sizeBytes,
          policy,
        }
      : null;
  }
  // Peer: sources are always the image owner's own hosts (I2), and only
  // unified (or not-yet-known) images with a reported size are fetchable.
  const rows = await tx.$queryRaw<{ size: bigint | null }[]>`
    SELECT max(a."sizeBytes") AS size FROM sandbox_template_availability a
    WHERE a."userId" = ${ownerId} AND a."hostOwnerId" = ${ownerId}
      AND a."localFingerprint" = ${revision.incusFingerprint}
      AND a.architecture = ${revision.architecture}
      AND a.status = 'AVAILABLE' AND a."sizeBytes" IS NOT NULL
      AND (a."imageFormat" IS NULL OR a."imageFormat" = 'unified')`;
  const size = rows[0]?.size;
  return size
    ? {
        mode,
        fingerprint: revision.incusFingerprint,
        architecture: revision.architecture,
        sizeBytes: size,
        policy,
      }
    : null;
}

/** Bytes other in-flight fetch-planned creates reserved on host `h` (M6). */
function pendingOtherSql(plan: ImageFetchPlan, host: Prisma.Sql) {
  return PrismaValue.sql`COALESCE((SELECT sum(x.b) FROM (
      SELECT DISTINCT ON (p.artifact) p."imageFetchBytes" AS b
      FROM sandbox_placement p JOIN sandbox_mutation_operation o ON o.id = p."operationId"
      WHERE p."originHostId" = ${host}.id AND p."imageFetchBytes" IS NOT NULL
        AND p.artifact <> ${plan.fingerprint} AND o.state IN ${ACTIVE_STATES}
      ORDER BY p.artifact) x), 0)::bigint`;
}

/**
 * Other accounts' image bytes already planned onto host `h` by in-flight
 * fetch-planned creates (P2-7): one count per distinct (owner, image), only
 * images not owned by the host owner, excluding this request's own image.
 * The pool member cap holds reported foreign bytes plus these plus this one.
 */
function pendingForeignSql(plan: ImageFetchPlan, ownerId: string, host: Prisma.Sql) {
  return PrismaValue.sql`COALESCE((SELECT sum(x.b) FROM (
      SELECT DISTINCT ON (p."userId", p.artifact) p."imageFetchBytes" AS b
      FROM sandbox_placement p JOIN sandbox_mutation_operation o ON o.id = p."operationId"
      WHERE p."originHostId" = ${host}.id AND p."imageFetchBytes" IS NOT NULL
        AND p."userId" <> ${host}."userId"
        AND NOT (p."userId" = ${ownerId} AND p.artifact = ${plan.fingerprint})
        AND o.state IN ${ACTIVE_STATES}
      ORDER BY p."userId", p.artifact) x), 0)::bigint`;
}

/** Where the plan's bytes come from: a peer source, the store, or (upstream)
 * the index host, which only a builder fetches from. */
function sourceSql(
  plan: ImageFetchPlan,
  ownerId: string,
  host: Prisma.Sql,
  current: { now: Date } | null,
): Prisma.Sql {
  switch (plan.mode) {
    case "peer":
      return peerSourceSql(plan, ownerId, host, current);
    case "upstream":
      return PrismaValue.sql`(${host}."daemonFeatures"->'image'->'build') = 'true'::jsonb`;
    default:
      return PrismaValue.sql`true`;
  }
}

/** Owned, image-serving source hosts of a peer fetch (excluding the target). */
function peerSourceSql(
  plan: ImageFetchPlan,
  ownerId: string,
  host: Prisma.Sql,
  current: { now: Date } | null,
) {
  const freshness = current
    ? PrismaValue.sql`AND src.status = 'CONNECTED'
        AND src."lastHeartbeatAt" BETWEEN ${new Date(current.now.getTime() - HOST_HEARTBEAT_STALE_AFTER_MS)} AND ${STATEMENT_NOW}
        AND src."imageCacheEpoch" = src."connectionEpoch"
        AND a."verifiedConnectionEpoch" = src."connectionEpoch"`
    : PrismaValue.empty;
  return PrismaValue.sql`EXISTS (SELECT 1 FROM sandbox_template_availability a
      JOIN sandbox_host src ON src.id = a."hostId" AND src."userId" = a."hostOwnerId"
      WHERE a."userId" = ${ownerId} AND a."hostOwnerId" = ${ownerId}
        AND src.id <> ${host}.id AND src."deletionRequestedAt" IS NULL
        AND a."localFingerprint" = ${plan.fingerprint} AND a.architecture = ${plan.architecture}
        AND a.status = 'AVAILABLE' AND a."sizeBytes" IS NOT NULL
        AND (a."imageFormat" IS NULL OR a."imageFormat" = 'unified')
        AND (src."daemonFeatures"->'image'->'serve') = 'true'::jsonb
        ${freshness})`;
}

/** Static fetch eligibility of host alias `host` (stage "template known"). */
export function fetchableStaticSql(
  plan: ImageFetchPlan | null,
  ownerId: string,
  host: Prisma.Sql = PrismaValue.raw("h"),
): Prisma.Sql {
  if (!plan) return PrismaValue.sql`false`;
  const foreignAllowed = plan.policy === "ANY_NODE";
  return PrismaValue.sql`((${host}."daemonFeatures"->'image'->'fetch') = 'true'::jsonb
    AND (${host}."userId" = ${ownerId} OR (${foreignAllowed}
      AND (${host}."daemonFeatures"->'image'->'acceptForeign') = 'true'::jsonb))
    AND ${sourceSql(plan, ownerId, host, null)})`;
}

/**
 * Current fetch admissibility (stage "template current"): the cache totals
 * are from this connection, the cap minus used minus other planned fetches
 * holds the image, the pool member cap holds foreign bytes, and (peer) a
 * source is connected and verified on its current epoch.
 */
export function fetchableCurrentSql(
  plan: ImageFetchPlan | null,
  ownerId: string,
  now: Date,
  host: Prisma.Sql = PrismaValue.raw("h"),
  poolOwner: Prisma.Sql | null = null,
  memberCapGiB: Prisma.Sql | null = null,
): Prisma.Sql {
  if (!plan) return PrismaValue.sql`false`;
  const memberCap =
    poolOwner && memberCapGiB
      ? PrismaValue.sql`AND (${host}."userId" = ${ownerId} OR ${host}."userId" = ${poolOwner}
          OR ${memberCapGiB} IS NULL
          OR COALESCE(${host}."imageCacheForeignBytes", 0)
            + ${pendingForeignSql(plan, ownerId, host)} + ${plan.sizeBytes}::bigint
            <= ${memberCapGiB}::bigint * 1073741824)`
      : PrismaValue.empty;
  return PrismaValue.sql`(${fetchableStaticSql(plan, ownerId, host)}
    AND ${host}."imageCacheEpoch" = ${host}."connectionEpoch"
    AND ${host}."imageCacheCapBytes" IS NOT NULL AND ${host}."imageCacheUsedBytes" IS NOT NULL
    AND ${host}."imageCacheCapBytes" - ${host}."imageCacheUsedBytes" - ${pendingOtherSql(plan, host)}
      >= ${plan.sizeBytes}::bigint
    ${memberCap}
    AND ${sourceSql(plan, ownerId, host, { now })})`;
}

/** Ranking tier: hosts with the image verified on their current epoch first. */
export function hasCurrentImageSql(
  ownerId: string,
  revisionId: string,
  host: Prisma.Sql = PrismaValue.raw("h"),
): Prisma.Sql {
  return PrismaValue.sql`CASE WHEN EXISTS (SELECT 1 FROM sandbox_template_availability a
      WHERE a."hostId" = ${host}.id AND a."userId" = ${ownerId} AND a."revisionId" = ${revisionId}
        AND a.status = 'AVAILABLE' AND a."verifiedConnectionEpoch" = ${host}."connectionEpoch")
    THEN 0 ELSE 1 END`;
}

/**
 * Direct (single host, H held) fetch decision when the host has no current
 * availability: the planned fetch bytes, or null when the image cannot be
 * fetched to this host right now.
 */
export async function directFetchDecision(
  tx: Prisma.TransactionClient,
  input: {
    ownerId: string;
    hostId: string;
    hostOwnerId: string;
    revision: PlanRevision;
    daemonFeatures: Prisma.JsonValue | null;
    now: Date;
    poolOwnerId?: string | null;
    memberCapGiB?: number | null;
  },
): Promise<ImageFetchPlan | null> {
  const features = hostImageFeatures(input.daemonFeatures);
  if (!features?.fetch) return null;
  const plan = await imageFetchPlan(tx, input.ownerId, input.revision);
  if (!plan) return null;
  const host = PrismaValue.raw("h");
  const poolOwner = input.poolOwnerId ? PrismaValue.sql`${input.poolOwnerId}` : null;
  const memberCap =
    input.poolOwnerId !== undefined && input.poolOwnerId !== null
      ? PrismaValue.sql`${input.memberCapGiB ?? null}::int`
      : null;
  const rows = await tx.$queryRaw<{ ok: boolean }[]>`
    SELECT ${fetchableCurrentSql(plan, input.ownerId, input.now, host, poolOwner, memberCap)} AS ok
    FROM sandbox_host h WHERE h.id = ${input.hostId} AND h."userId" = ${input.hostOwnerId}`;
  return rows[0]?.ok === true ? plan : null;
}

/**
 * Final suffix for a fetch-planned placement (instead of the availability
 * FOR SHARE): S3 locks the STORED artifact FOR SHARE after H, so GC either
 * waits and sees the new reference or wins and this placement reselects.
 * Peer re-checks that an owned source is still current.
 */
export async function lockImageFetchSuffix(
  tx: Prisma.TransactionClient,
  ownerId: string,
  plan: ImageFetchPlan,
  hostId: string,
  now: Date,
): Promise<boolean> {
  if (plan.mode === "upstream") return true;
  if (plan.mode === "s3") {
    const rows = await tx.$queryRaw<{ id: string }[]>`
      SELECT id FROM sandbox_image_artifact
      WHERE "userId" = ${ownerId} AND fingerprint = ${plan.fingerprint}
        AND state = 'STORED' AND "storeKind" = 'S3' FOR SHARE`;
    return rows.length === 1;
  }
  const host = PrismaValue.raw("h");
  const rows = await tx.$queryRaw<{ ok: boolean }[]>`
    SELECT ${peerSourceSql(plan, ownerId, host, { now })} AS ok
    FROM sandbox_host h WHERE h.id = ${hostId}`;
  return rows[0]?.ok === true;
}
