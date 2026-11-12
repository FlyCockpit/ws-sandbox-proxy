import type { Prisma, TemplateBuildState } from "@wssp/db";
import { Prisma as PrismaValue } from "@wssp/db/client";
import {
  type EffectivePlacement,
  effectiveImagePlacement,
  type ImageStoreMode,
  imageDistributionMode,
} from "../sandbox/image-store/config";
import { buildAuthorityLost } from "./build-authority";

/**
 * Placement inputs of a build create (plan template-builds §4). Read in the
 * placing transaction while the owner placement lock is held: both writers
 * (`setAccountImagePolicy`, `updateTemplateImageSettings`) take that lock, so
 * a concurrent toggle is ordered before or after the whole placement.
 */
export type BuildPlacement = {
  /** `AccountImagePolicy.allowForeignBuilds` of the build owner. */
  allowForeign: boolean;
  /** `effectiveImagePlacement` of the build's target template. */
  targetPlacement: EffectivePlacement;
  /** Deployment image distribution mode. */
  imageMode: ImageStoreMode;
};

/** Build states in which its VM may still be placed (§3.4, N18). */
const PLACEABLE_STATES: ReadonlySet<TemplateBuildState> = new Set(["QUEUED", "PLACING"]);

/** The create-side state check (§3.4, N18): a build VM may be placed only
 * while its build is QUEUED/PLACING with no cancel recorded. */
function buildPlaceable(build: {
  state: TemplateBuildState;
  cancelRequestedAt: Date | null;
}): boolean {
  return PLACEABLE_STATES.has(build.state) && build.cancelRequestedAt === null;
}

/**
 * The build's placement inputs, or null when the owner has no such build or
 * the build may no longer place its VM (cancelled, ended, or past placing).
 *
 * Plain reads, but every placement transaction (direct, pool and queue
 * materialization) calls this AFTER taking owner placement, which cancel also
 * takes before it writes CANCELLING (§3.4). So a create either commits before
 * the cancel (and the cleanup invariant then kills its VM, §3.10) or sees the
 * cancel here and is refused: a VM created after cancel is impossible (N18).
 */
export async function loadBuildPlacement(
  tx: Prisma.TransactionClient,
  ownerId: string,
  buildId: string,
): Promise<BuildPlacement | null> {
  const build = await tx.sandboxTemplateBuild.findFirst({
    where: { id: buildId, userId: ownerId },
    select: { templateId: true, state: true, cancelRequestedAt: true },
  });
  if (!build || !buildPlaceable(build)) return null;
  const policy = await tx.accountImagePolicy.findUnique({
    where: { userId: ownerId },
    select: { allowForeignBuilds: true },
  });
  return {
    allowForeign: policy?.allowForeignBuilds === true,
    targetPlacement: await effectiveImagePlacement(tx, ownerId, build.templateId),
    imageMode: imageDistributionMode(),
  };
}

/** `loadBuildPlacement` for a create that must place: a missing or no longer
 * placeable build means the build authority is gone (typed, never message
 * text; the orchestrator classifies it as terminal). */
export async function requireBuildPlacement(
  tx: Prisma.TransactionClient,
  ownerId: string,
  buildId: string,
): Promise<BuildPlacement> {
  const placement = await loadBuildPlacement(tx, ownerId, buildId);
  if (!placement) throw buildAuthorityLost();
  return placement;
}

/** The requester-side half of the foreign-builder rule (r1 M-4): the owner
 * opted in, the image store is S3 and the target template may live anywhere. */
export function foreignBuildsPermitted(build: BuildPlacement): boolean {
  return build.allowForeign && build.imageMode === "s3" && build.targetPlacement === "ANY_NODE";
}

/**
 * Host-side SQL over alias `h` (a `sandbox_host`) for a build owned by
 * `ownerId`. `offers`: the node builds for this requester; `admits`: the full
 * `builder` stage (§4), i.e. `offers` plus the capture policy for a foreign
 * node. An own node needs only `image.build`.
 */
export function builderSql(ownerId: string, build: BuildPlacement) {
  const own = PrismaValue.sql`h."userId" = ${ownerId}`;
  const capable = PrismaValue.sql`COALESCE((h."daemonFeatures"->'image'->'build') = 'true'::jsonb, false)`;
  const foreignBuilds = PrismaValue.sql`COALESCE((h."daemonFeatures"->'image'->'acceptForeignBuilds') = 'true'::jsonb, false)`;
  const foreignImages = PrismaValue.sql`COALESCE((h."daemonFeatures"->'image'->'acceptForeign') = 'true'::jsonb, false)`;
  const offers = PrismaValue.sql`(${capable} AND (${own} OR ${foreignBuilds}))`;
  const admits = PrismaValue.sql`(${capable} AND (${own}
      OR (${foreignBuildsPermitted(build)} AND ${foreignBuilds} AND ${foreignImages})))`;
  return { offers, admits };
}
