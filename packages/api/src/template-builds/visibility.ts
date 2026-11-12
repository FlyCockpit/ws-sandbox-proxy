/**
 * The build visibility rule and the public row projection.
 * A leaf module: acceptance and cancel use it without pulling in the read
 * services (and their import graph).
 */
import type { Prisma } from "@wssp/db";
import type { Principal } from "../sandbox/contracts";
import { buildIdOf, grantOf, recordedKeyIdOf, viewerOf } from "../sandbox/principal-kinds";
import { TEMPLATE_BUILD_SCOPE } from "./build-authority";

/** Matches no row (Prisma has no literal `false` filter). */
const NOTHING: Prisma.SandboxTemplateBuildWhereInput = { id: { in: [] } };

/**
 * The builds `principal` may see and act on (get, list, logs, cancel and,
 * narrowed further to the accepting principal, the context routes). Always
 * includes the owner filter; compose it with the requested id or filters.
 */
export function visibleBuildWhere(principal: Principal): Prisma.SandboxTemplateBuildWhereInput {
  // A build principal acts on its own VM through the action classes; it never
  // reads builds through these routes.
  if (buildIdOf(principal) !== null) return NOTHING;
  if (!grantOf(principal).has(TEMPLATE_BUILD_SCOPE)) return NOTHING;
  if (viewerOf(principal).resourceMode === "ALL_OWNED") return { userId: principal.ownerId };
  const keyId = recordedKeyIdOf(principal);
  if (keyId === null) return NOTHING;
  // Own builds only: never another key's, a session's or a system rebuild.
  return { userId: principal.ownerId, principalKind: "sdkKey", authorizingKeyId: keyId };
}

/** The public projection of a build row (a disclosure boundary). */
export const buildViewSelect = {
  id: true,
  templateId: true,
  tag: true,
  principalKind: true,
  state: true,
  phase: true,
  stepIndex: true,
  steps: true,
  recipeDigest: true,
  buildDigest: true,
  contextSha256: true,
  contextBytes: true,
  timeoutMinutes: true,
  reservedMinutes: true,
  chargedMinutes: true,
  revisionId: true,
  cacheHitRevisionId: true,
  errorCode: true,
  errorDetail: true,
  failureStepIndex: true,
  failureExitCode: true,
  cancelRequestedAt: true,
  cleanupState: true,
  createdAt: true,
  updatedAt: true,
  completedAt: true,
} satisfies Prisma.SandboxTemplateBuildSelect;
export type TemplateBuildSummary = Prisma.SandboxTemplateBuildGetPayload<{
  select: typeof buildViewSelect;
}>;
