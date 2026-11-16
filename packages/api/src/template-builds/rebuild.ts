import { randomUUID } from "node:crypto";
import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { parseTemplateSelector } from "@wssp/sandbox-contracts";
import { canonicalJson, sha256Hex } from "@wssp/template-recipe";
import { isPrismaUniqueViolation } from "../lib/prisma-errors";
import type { Principal } from "../sandbox/contracts";
import { lockOwnerPlacement } from "../sandbox/direct-placement";
import { buildIdOf } from "../sandbox/principal-kinds";
import { resolveTemplateRevision } from "../sandbox/template-resolution";
import { communityFirstCreateBuildLocked, communityRefreshOnMissLocked } from "./community/service";
import { templateBuildLeaseMs, templateBuildsConfig } from "./config";
import { ACTIVE_BUILD_STATES } from "./decide";
import { initialStepRecords, loadBuildExecPlan } from "./exec-plan";
import { buildQuotaRefusal, chargeMonthOf } from "./service";
import { notifyTemplateBuildsChanged } from "./wake";

/**
 * Rebuild on miss. A create that resolves a
 * tag to a revision produced by a successful, context-free build whose image
 * is gone everywhere (no AVAILABLE or PENDING host copy, not STORED) starts a
 * new build of the same recipe instead of failing:
 *
 * - The rebuild is a `principalKind = system` row (`authorizingKeyId` null,
 *   `triggeredByRevisionId` = the missing revision) run by the keyless build
 *   principal and charged to the template owner's concurrency and minutes.
 *   An exhausted quota refuses quietly: the create gets
 *   `image_unavailable{reason: "rebuild_quota"}` and no row is written.
 * - Concurrent misses join one rebuild: every trigger runs under owner
 *   placement and joins the newest active system build of that revision; the
 *   active dedupe index (`principalKey = 'sys'`) backs it.
 * - Recipes with COPY are never rebuilt (no stored context):
 *   `image_unavailable{hint: "rebuild_required"}`. A pinned BUILD revision
 *   whose image is gone fails `image_unavailable` (it never waits).
 *
 * Lock order (§3.4): every caller holds User (owner admission) and owner
 * placement before calling `rebuildOnMissLocked`; it takes no other lock and
 * never locks a build row (the insert is a new row).
 */

export type RebuildOnMiss =
  /** Not a rebuild case: the caller's own refusal or placement stands. */
  | { kind: "none" }
  /** A rebuild of this revision is running (started now or joined). */
  | { kind: "rebuilding"; buildId: string; started: boolean }
  /** The newest rebuild of this revision succeeded and the tag moved on:
   * re-resolve the selector. */
  | { kind: "rebuilt"; buildId: string }
  /** The revision cannot be rebuilt now (no row was written). */
  | {
      kind: "refused";
      reason: "rebuild_quota" | "rebuild_required" | "rebuild_failed" | "pinned";
    };

type MissingRevision = {
  id: string;
  templateId: string;
  sourceKind: string;
  incusFingerprint: string;
};

/** True when no host holds (or is importing) the revision and no store has it. */
async function revisionMissingEverywhere(
  tx: Prisma.TransactionClient,
  ownerId: string,
  revision: Pick<MissingRevision, "id" | "incusFingerprint">,
): Promise<boolean> {
  const copy = await tx.sandboxTemplateAvailability.findFirst({
    where: { userId: ownerId, revisionId: revision.id, status: { in: ["AVAILABLE", "PENDING"] } },
    select: { id: true },
  });
  if (copy) return false;
  const stored = await tx.sandboxImageArtifact.findFirst({
    where: { userId: ownerId, fingerprint: revision.incusFingerprint, state: "STORED" },
    select: { id: true },
  });
  return !stored;
}

/** The tag a selector moves, or null for a pinned revision. */
function selectorTag(selector: string): string | null {
  try {
    const parsed = parseTemplateSelector(selector);
    if (parsed.kind === "revision") return null;
    return parsed.kind === "tag" ? parsed.tag : "latest";
  } catch {
    return null;
  }
}

const sourceSelect = {
  id: true,
  userId: true,
  templateId: true,
  state: true,
  recipe: true,
  recipeDigest: true,
  buildDigest: true,
  sourceFormat: true,
  dockerfileText: true,
  baseRevisionId: true,
  baseFingerprint: true,
  buildArgs: true,
  contextSha256: true,
  poolId: true,
  requestedHostId: true,
  targetKey: true,
  cpuCount: true,
  memoryMiB: true,
  diskGiB: true,
  defaultDiskGiB: true,
  egressRequest: true,
  egressPresets: true,
  timeoutMinutes: true,
  waitForCapacityMs: true,
} satisfies Prisma.SandboxTemplateBuildSelect;

/**
 * Decide, and when needed start, the rebuild of `revision` for a create that
 * resolved it through `selector`. The caller holds User and owner placement.
 * `retryFailed`: whether a newest FAILED/CANCELLED rebuild may be retried
 * (a fresh create may; a waiting create re-evaluated by the queue may not).
 */
export async function rebuildOnMissLocked(
  tx: Prisma.TransactionClient,
  principal: Principal,
  selector: string,
  revision: MissingRevision,
  options: { retryFailed: boolean; now?: Date },
): Promise<RebuildOnMiss> {
  const ownerId = principal.ownerId;
  // A build VM's own create (its base) never triggers another build.
  if (buildIdOf(principal) !== null) return { kind: "none" };
  if (revision.sourceKind !== "BUILD") return { kind: "none" };
  if (!(await revisionMissingEverywhere(tx, ownerId, revision))) return { kind: "none" };
  // A community template refreshes from its upstream pin instead (D-H): the
  // generic path would rebuild without the verify step.
  const community = await tx.sandboxTemplate.findFirst({
    where: { id: revision.templateId, userId: ownerId },
    select: { communitySource: true },
  });
  if (community?.communitySource) {
    if (selectorTag(selector) === null) return { kind: "refused", reason: "pinned" };
    const outcome = await communityRefreshOnMissLocked(
      tx,
      ownerId,
      revision.templateId,
      options.now ?? new Date(),
    );
    if (outcome.kind === "started")
      return { kind: "rebuilding", buildId: outcome.buildId, started: true };
    if (outcome.kind === "active")
      return { kind: "rebuilding", buildId: outcome.buildId, started: false };
    return outcome.reason === "quota"
      ? { kind: "refused", reason: "rebuild_quota" }
      : { kind: "none" };
  }
  // A pinned revision is never rebuilt (a rebuild is a new revision): it
  // fails `image_unavailable` instead of waiting for an image that cannot come.
  const tag = selectorTag(selector);
  if (tag === null) return { kind: "refused", reason: "pinned" };
  const newest = await tx.sandboxTemplateBuild.findFirst({
    where: { userId: ownerId, triggeredByRevisionId: revision.id },
    orderBy: { createdAt: "desc" },
    select: { id: true, state: true },
  });
  if (newest && ACTIVE_BUILD_STATES.includes(newest.state))
    return { kind: "rebuilding", buildId: newest.id, started: false };
  const current = await tx.sandboxTemplateTag.findFirst({
    where: { userId: ownerId, templateId: revision.templateId, tag },
    select: { revisionId: true },
  });
  if (current?.revisionId !== revision.id)
    return newest?.state === "SUCCEEDED"
      ? { kind: "rebuilt", buildId: newest.id }
      : { kind: "none" };
  if (newest && newest.state !== "SUCCEEDED" && !options.retryFailed)
    return { kind: "refused", reason: "rebuild_failed" };
  const row = await tx.sandboxTemplateRevision.findFirst({
    where: { id: revision.id, userId: ownerId },
    select: { buildId: true },
  });
  if (!row?.buildId) return { kind: "none" };
  const source = await tx.sandboxTemplateBuild.findFirst({
    where: { id: row.buildId, userId: ownerId, templateId: revision.templateId },
    select: sourceSelect,
  });
  if (source?.state !== "SUCCEEDED") return { kind: "none" };
  // Contexts are never stored (§3.9): a COPY recipe needs a new upload.
  if (source.contextSha256 !== null) return { kind: "refused", reason: "rebuild_required" };
  const base = await tx.sandboxTemplateRevision.findFirst({
    where: {
      id: source.baseRevisionId,
      userId: ownerId,
      incusFingerprint: source.baseFingerprint,
      retiredAt: null,
      Template: { archivedAt: null },
    },
    select: { id: true },
  });
  if (!base) return { kind: "none" };
  const exec = await loadBuildExecPlan(tx, source);
  if (exec.steps.some((step) => step.kind === "copy"))
    return { kind: "refused", reason: "rebuild_required" };
  const config = templateBuildsConfig();
  if (!config.enabled) return { kind: "none" };
  const timeoutMinutes = Math.min(source.timeoutMinutes, config.maxMinutes);
  if (
    timeoutMinutes < 1 ||
    templateBuildLeaseMs(timeoutMinutes, config.captureWindowMinutes) > config.leaseCeilingMs
  )
    return { kind: "none" };
  // An identical active system build (the dedupe index's key) is joined too.
  const twin = await tx.sandboxTemplateBuild.findFirst({
    where: {
      userId: ownerId,
      templateId: revision.templateId,
      tag,
      buildDigest: source.buildDigest,
      targetKey: source.targetKey,
      principalKey: "sys",
      noCache: false,
      state: { in: [...ACTIVE_BUILD_STATES] },
    },
    select: { id: true },
  });
  if (twin) return { kind: "rebuilding", buildId: twin.id, started: false };
  const now = options.now ?? new Date();
  // Charged to the template owner (the creator's owner: templates are
  // owner-scoped), whoever's create noticed the miss.
  if (await buildQuotaRefusal(tx, ownerId, timeoutMinutes, now, config))
    return { kind: "refused", reason: "rebuild_quota" };
  const created = await tx.sandboxTemplateBuild.create({
    data: {
      userId: ownerId,
      templateId: revision.templateId,
      tag,
      principalKind: "system",
      authorizingKeyId: null,
      principalKey: "sys",
      triggeredByRevisionId: revision.id,
      idempotencyKey: `tb:rebuild:${revision.id}:${randomUUID()}`,
      requestBodyHash: await sha256Hex(
        canonicalJson({ rebuildOf: revision.id, sourceBuildId: source.id, tag }),
      ),
      recipe: source.recipe as Prisma.InputJsonValue,
      recipeDigest: source.recipeDigest,
      buildDigest: source.buildDigest,
      sourceFormat: source.sourceFormat,
      dockerfileText: source.dockerfileText,
      baseRevisionId: source.baseRevisionId,
      baseFingerprint: source.baseFingerprint,
      buildArgs: source.buildArgs as Prisma.InputJsonValue,
      contextSha256: null,
      contextBytes: null,
      poolId: source.poolId,
      requestedHostId: source.requestedHostId,
      targetKey: source.targetKey,
      cpuCount: source.cpuCount,
      memoryMiB: source.memoryMiB,
      diskGiB: source.diskGiB,
      defaultDiskGiB: source.defaultDiskGiB,
      egressRequest: (source.egressRequest ?? undefined) as Prisma.InputJsonValue | undefined,
      egressPresets: source.egressPresets,
      timeoutMinutes,
      waitForCapacityMs: source.waitForCapacityMs,
      reservedMinutes: timeoutMinutes,
      chargeMonth: chargeMonthOf(now),
      noCache: false,
      state: "QUEUED",
      phase: "queued",
      steps: initialStepRecords(exec.steps) as unknown as Prisma.InputJsonValue,
    },
    select: { id: true },
  });
  return { kind: "rebuilding", buildId: created.id, started: true };
}

/** `sandbox.template_image_unavailable` with the rebuild reason or hint. */
export function rebuildRefusal(outcome: RebuildOnMiss) {
  const extra =
    outcome.kind === "rebuilding"
      ? { reason: "rebuilding" }
      : outcome.kind === "refused" && outcome.reason === "rebuild_quota"
        ? { reason: "rebuild_quota" }
        : outcome.kind === "refused" && outcome.reason === "rebuild_required"
          ? { hint: "rebuild_required" }
          : {};
  return new ORPCError("CONFLICT", {
    message: "No eligible host has or can fetch this template image.",
    data: { code: "sandbox.template_image_unavailable", ...extra },
  });
}

/** Image refusals after which a create without a wait checks for a rebuild. */
const TEMPLATE_NOT_FOUND = "sandbox.template_not_found";
const IMAGE_REFUSALS = new Set<string>([
  "sandbox.template_unavailable",
  "sandbox.template_image_missing",
  "sandbox.template_image_rejected",
  "sandbox.template_image_unavailable",
]);

/**
 * A create that does not wait was refused for its image: in a transaction of
 * its own (the create's rolled back), User → owner placement, re-resolve the
 * selector and start or join the rebuild. Returns the error to throw: the
 * original refusal when this is not a rebuild case.
 */
export async function rebuildAfterRefusal(
  principal: Principal,
  selector: string,
  refusal: unknown,
): Promise<unknown> {
  if (!(refusal instanceof ORPCError)) return refusal;
  const code = (refusal.data as { code?: unknown } | undefined)?.code;
  if (typeof code !== "string") return refusal;
  if (buildIdOf(principal) !== null) return refusal;
  if (code === TEMPLATE_NOT_FOUND) {
    // The community first-create window, after the visibility re-proof.
    try {
      const buildId = await prisma.$transaction(async (tx) => {
        await lockOwnerForAdmission(tx, principal.ownerId);
        return communityFirstCreateBuildLocked(tx, principal, selector);
      });
      return buildId ? rebuildRefusal({ kind: "rebuilding", buildId, started: false }) : refusal;
    } catch {
      return refusal;
    }
  }
  if (!IMAGE_REFUSALS.has(code)) return refusal;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const outcome = await prisma.$transaction(async (tx) => {
        await lockOwnerForAdmission(tx, principal.ownerId);
        await lockOwnerPlacement(tx, principal.ownerId);
        const revision = await resolveTemplateRevision(tx, principal, selector);
        return rebuildOnMissLocked(tx, principal, selector, revision, { retryFailed: true });
      });
      if (outcome.kind === "rebuilding" && outcome.started) notifyTemplateBuildsChanged();
      return outcome.kind === "none" || outcome.kind === "rebuilt"
        ? refusal
        : rebuildRefusal(outcome);
    } catch (error) {
      if (attempt === 0 && isPrismaUniqueViolation(error)) continue;
      // The trigger is best effort: the create's own refusal stands.
      console.warn(
        "[template-builds] Rebuild on miss failed:",
        error instanceof Error ? error.name : "error",
      );
      return refusal;
    }
  }
  return refusal;
}
