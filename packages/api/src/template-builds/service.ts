import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { Prisma as PrismaValue } from "@wssp/db/client";
import {
  BUILD_DISK_HEADROOM_GIB,
  CAPACITY_WAIT_MAX_MS,
  type CapacityWaitRequest,
  resolveVmSize,
  type TemplateBuildCreateBody,
  VM_SIZE_LIMITS,
  type VmSizeOverrides,
} from "@wssp/sandbox-contracts";
import {
  buildDigest,
  canonicalJson,
  compileDockerfile,
  type ParsedRecipe,
  parseRecipe,
  RecipeError,
  recipeFromSelector,
  sha256Hex,
  TEMPLATE_SLUG_PATTERN,
  TEMPLATE_TAG_PATTERN,
} from "@wssp/template-recipe";
import { authorizeServiceIntent, serviceResourceFilter } from "../lib/sdk-key-access";
import type { Principal } from "../sandbox/contracts";
import { lockOwnerPlacement } from "../sandbox/direct-placement";
import { diskBelowImage, hostNotFound, templateNotFound } from "../sandbox/errors";
import { buildIdOf, grantOf, isBrowserSession, recordedKeyIdOf } from "../sandbox/principal-kinds";
import { loadRevisionDefaults } from "../sandbox/revision-config";
import { requirePoolUse } from "../sandbox/sharing-authority";
import { launchableRevisionWhere, resolveTemplateRevision } from "../sandbox/template-resolution";
import { assertDiskFitsImage } from "../sandbox/vm-size-input";
import { refuseCommunityWrite } from "./community/managed";
import {
  accountTemplateBuildQuotas,
  TEMPLATE_BUILD_CONTEXT_SEALED_MAX_MS,
  templateBuildLeaseMs,
  templateBuildsConfig,
} from "./config";
import { ACTIVE_BUILD_STATES } from "./decide";
import { type BuildStepRecord, buildExecPlan, initialStepRecords } from "./exec-plan";
import { buildViewSelect, type TemplateBuildSummary, visibleBuildWhere } from "./visibility";
import { notifyTemplateBuildProgress, notifyTemplateBuildsChanged } from "./wake";

/**
 * Template-build acceptance and cancel. Acceptance commits
 * only the build row (the `apps/server` route opens the staged context
 * afterwards, §3.6 "Where acceptance runs"); cancel only records the intent:
 * the orchestrator settles it and the cleanup invariant kills the VM.
 *
 * Both run under owner admission → SDK key (`FOR SHARE`, revalidated, its
 * refreshed grants applied to the principal) → owner placement → (template)
 * → build row (§3.4), for any accepting principal (session or SDK key with
 * `templates:build`: tag rule, allowlists through the grant-filtered
 * resolvers, the real key stored on the row). Cancel acts only on a build
 * the caller can see (`visibleBuildWhere`, r3 N20).
 */

export type CreateTemplateBuildInput = {
  idempotencyKey: string;
  /** Target template: an existing id, or a slug (created when missing). */
  template: { id: string } | { slug: string };
  /** Sessions may name a tag; SDK keys move `latest` only (as captures, I5). */
  tag?: string;
  /** Exactly one of a canonical recipe (JSON) or a Dockerfile subset. */
  recipe?: unknown;
  dockerfile?: string;
  buildArgs?: Record<string, string>;
  poolId?: string;
  sandboxHostId?: string;
  /** Override the recipe's resources (themselves overriding the base). */
  resources?: VmSizeOverrides;
  /** The published revision's default disk (default: the base's, at least the build disk). */
  defaultDiskGiB?: number;
  timeoutMinutes?: number;
  waitForCapacityMs?: CapacityWaitRequest;
  /** Required exactly when the recipe has a COPY step. */
  contextSha256?: string;
  contextBytes?: number;
  noCache?: boolean;
};

/** The create body of either plane (top-level VM size fields) as service input. */
export function templateBuildInputFromBody(
  body: Omit<TemplateBuildCreateBody, "tag"> & { tag?: string },
  idempotencyKey: string,
): CreateTemplateBuildInput {
  const { cpuCount, memoryMiB, diskGiB, ...rest } = body;
  const resources: VmSizeOverrides = {
    ...(cpuCount === undefined ? {} : { cpuCount }),
    ...(memoryMiB === undefined ? {} : { memoryMiB }),
    ...(diskGiB === undefined ? {} : { diskGiB }),
  };
  return {
    ...rest,
    idempotencyKey,
    ...(Object.keys(resources).length ? { resources } : {}),
  };
}

/** `template.build_*` refusals (B7 adds them to the public catalog). */
export function buildError(
  status: "BAD_REQUEST" | "CONFLICT" | "NOT_FOUND" | "SERVICE_UNAVAILABLE",
  code: string,
  extra: Record<string, unknown> = {},
) {
  return new ORPCError(status, { data: { ...extra, code } });
}

function recipeInvalid(code: string, error?: RecipeError) {
  return buildError("BAD_REQUEST", "template.build_recipe_invalid", {
    recipeCode: code,
    ...(error?.line !== undefined ? { line: error.line } : {}),
    ...(error?.column !== undefined ? { column: error.column } : {}),
    ...(error?.stepIndex !== undefined ? { stepIndex: error.stepIndex } : {}),
  });
}

function parseInput(input: CreateTemplateBuildInput): {
  parsed: ParsedRecipe;
  sourceFormat: "RECIPE" | "DOCKERFILE";
} {
  if ((input.recipe === undefined) === (input.dockerfile === undefined))
    throw recipeInvalid("recipe_invalid");
  try {
    if (input.dockerfile !== undefined)
      return {
        parsed: compileDockerfile(input.dockerfile, { buildArgs: input.buildArgs }),
        sourceFormat: "DOCKERFILE",
      };
    return {
      parsed: parseRecipe(input.recipe, { buildArgs: input.buildArgs }),
      sourceFormat: "RECIPE",
    };
  } catch (error) {
    if (error instanceof RecipeError) throw recipeInvalid(error.code, error);
    throw error;
  }
}

/** The accepting principal as stored on the row: never null-means-session
 * (CHECK `template_build_principal`). Build principals never accept. */
function acceptingPrincipal(principal: Principal) {
  if (buildIdOf(principal) !== null) throw new ORPCError("FORBIDDEN");
  if (isBrowserSession(principal))
    return { principalKind: "session" as const, authorizingKeyId: null, principalKey: "s" };
  const keyId = recordedKeyIdOf(principal);
  if (keyId === null) throw new ORPCError("FORBIDDEN");
  return { principalKind: "sdkKey" as const, authorizingKeyId: keyId, principalKey: `k:${keyId}` };
}

/** First day of the UTC month (`chargeMonth`). */
export function chargeMonthOf(now: Date): Date {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
}

/** Clamp a create's capacity wait: "unlimited" is the longest finite wait;
 * a COPY build waits at most the sealed-context ceiling (§3.7, I25). */
export function frozenCapacityWait(
  request: CapacityWaitRequest | undefined,
  hasCopy: boolean,
): number | null {
  if (request === undefined) return null;
  const ms = request === "unlimited" ? CAPACITY_WAIT_MAX_MS : request;
  return hasCopy ? Math.min(ms, TEMPLATE_BUILD_CONTEXT_SEALED_MAX_MS) : ms;
}

async function resolveTargetTemplate(
  tx: Prisma.TransactionClient,
  principal: Principal,
  template: CreateTemplateBuildInput["template"],
): Promise<string> {
  if ("id" in template) {
    const row = await tx.sandboxTemplate.findFirst({
      where: { AND: [serviceResourceFilter(principal, "template"), { id: template.id }] },
      select: { id: true },
    });
    if (!row) throw templateNotFound();
    return row.id;
  }
  if (!TEMPLATE_SLUG_PATTERN.test(template.slug) || template.slug.length > 63)
    throw recipeInvalid("template_slug_invalid");
  const existing = await tx.sandboxTemplate.findFirst({
    where: { userId: principal.ownerId, slug: template.slug },
    select: { id: true },
  });
  if (existing) {
    const visible = await tx.sandboxTemplate.findFirst({
      where: { AND: [serviceResourceFilter(principal, "template"), { id: existing.id }] },
      select: { id: true },
    });
    if (!visible) throw templateNotFound();
    return existing.id;
  }
  // Creating a template is a template write: an SDK key needs
  // `templates:write` for it (I6). Without it the slug simply is not found.
  if (!grantOf(principal).has("templates:write")) throw templateNotFound();
  // Owner placement is held: two acceptances of one new slug serialize here.
  const created = await tx.sandboxTemplate.create({
    data: { userId: principal.ownerId, slug: template.slug, label: template.slug },
    select: { id: true },
  });
  return created.id;
}

/** The whole-recipe cache hit (§6.1): newest SUCCEEDED build of this owner,
 * template and digest whose revision is live, available and resolvable by
 * the requester (its revision allowlist). Owner-wide by design. */
async function findCacheHit(
  tx: Prisma.TransactionClient,
  principal: Principal,
  templateId: string,
  digest: string,
): Promise<string | null> {
  const prior = await tx.sandboxTemplateBuild.findMany({
    where: {
      userId: principal.ownerId,
      templateId,
      buildDigest: digest,
      state: "SUCCEEDED",
      OR: [{ revisionId: { not: null } }, { cacheHitRevisionId: { not: null } }],
    },
    orderBy: { createdAt: "desc" },
    select: { revisionId: true, cacheHitRevisionId: true },
    take: 8,
  });
  for (const build of prior) {
    const revisionId = build.revisionId ?? build.cacheHitRevisionId;
    if (!revisionId) continue;
    const revision = await tx.sandboxTemplateRevision.findFirst({
      where: {
        AND: [
          serviceResourceFilter(principal, "revision"),
          launchableRevisionWhere(),
          { id: revisionId, templateId, retiredAt: null },
        ],
      },
      select: { id: true, incusFingerprint: true },
    });
    if (!revision) continue;
    const stored = await tx.sandboxImageArtifact.findFirst({
      where: { userId: principal.ownerId, fingerprint: revision.incusFingerprint, state: "STORED" },
      select: { id: true },
    });
    const available = await tx.sandboxTemplateAvailability.findFirst({
      where: { userId: principal.ownerId, revisionId: revision.id, status: "AVAILABLE" },
      select: { id: true },
    });
    if (stored || available) return revision.id;
  }
  return null;
}

/** The owner's build minutes in `now`'s UTC month: settled charge, else the reservation. */
export async function buildMinutesUsed(
  tx: Pick<Prisma.TransactionClient, "$queryRaw">,
  ownerId: string,
  now: Date,
): Promise<number> {
  const [used] = await tx.$queryRaw<{ minutes: bigint }[]>`
    SELECT coalesce(sum(CASE WHEN "minutesSettled" THEN "chargedMinutes" ELSE "reservedMinutes" END), 0)::bigint AS minutes
    FROM sandbox_template_build
    WHERE "userId" = ${ownerId} AND "chargeMonth" = ${chargeMonthOf(now)}`;
  return Number(used?.minutes ?? 0n);
}

/**
 * The owner's build quotas (§7): concurrent active builds and the month's
 * minutes (settled charge, else the reservation). The caller holds owner
 * placement, which serializes every reservation of this owner. Returns the
 * typed refusal, or null when `timeoutMinutes` more fit.
 */
export async function buildQuotaRefusal(
  tx: Prisma.TransactionClient,
  ownerId: string,
  timeoutMinutes: number,
  now: Date,
  config = templateBuildsConfig(),
): Promise<ORPCError<string, unknown> | null> {
  const quotas = await accountTemplateBuildQuotas(tx, ownerId, config);
  if (quotas.maxConcurrent !== null) {
    const running = await tx.sandboxTemplateBuild.count({
      where: { userId: ownerId, state: { in: [...ACTIVE_BUILD_STATES] } },
    });
    if (running >= quotas.maxConcurrent)
      return buildError("CONFLICT", "template.build_concurrency", {
        maxConcurrent: quotas.maxConcurrent,
      });
  }
  if (quotas.minutesPerMonth !== null) {
    const used = await buildMinutesUsed(tx, ownerId, now);
    if (used + timeoutMinutes > quotas.minutesPerMonth)
      return buildError("CONFLICT", "template.build_minutes_exhausted", {
        minutesPerMonth: quotas.minutesPerMonth,
      });
  }
  return null;
}

/**
 * The build-row insert of every accepting path (the user path above and the
 * community create, retry and refresh paths), extracted unchanged: the
 * owner's quotas, then the row with its reservation and step records. The
 * caller holds owner admission and owner placement. `origin` is never set by
 * the user path (the row default USER); only `community/service.ts` writes
 * COMMUNITY_PREP (enumeration test in `community/service.test.ts`).
 */
export async function insertBuildLocked(
  tx: Prisma.TransactionClient,
  data: Omit<
    Prisma.SandboxTemplateBuildUncheckedCreateInput,
    "state" | "phase" | "reservedMinutes" | "steps"
  > & { timeoutMinutes: number },
  options: {
    hasContext: boolean;
    steps: BuildStepRecord[];
    now: Date;
    config?: ReturnType<typeof templateBuildsConfig>;
  },
): Promise<TemplateBuildSummary> {
  const refusal = await buildQuotaRefusal(
    tx,
    data.userId,
    data.timeoutMinutes,
    options.now,
    options.config,
  );
  if (refusal) throw refusal;
  return tx.sandboxTemplateBuild.create({
    data: {
      ...data,
      state: options.hasContext ? "AWAITING_CONTEXT" : "QUEUED",
      phase: options.hasContext ? "awaiting_context" : "queued",
      reservedMinutes: data.timeoutMinutes,
      steps: options.steps as unknown as Prisma.InputJsonValue,
    },
    select: buildViewSelect,
  });
}

export type AcceptedTemplateBuild = {
  build: TemplateBuildSummary;
  /** An identical active build was joined (never receives the upload handle). */
  joined: boolean;
  cacheHit: boolean;
  /** The caller should open the staged context (COPY build it accepted). */
  needsContext: boolean;
};

/** Acceptance (§3.6) for any accepting principal; see the module comment. */
export async function acceptTemplateBuild(
  principal: Principal,
  input: CreateTemplateBuildInput,
  now: Date = new Date(),
): Promise<AcceptedTemplateBuild> {
  const config = templateBuildsConfig();
  if (!config.enabled)
    throw buildError("SERVICE_UNAVAILABLE", "template.build_disabled", { reason: config.reason });
  const accepting = acceptingPrincipal(principal);
  const tag = input.tag ?? "latest";
  if (!TEMPLATE_TAG_PATTERN.test(tag)) throw recipeInvalid("tag_invalid");
  if (!isBrowserSession(principal) && tag !== "latest") throw recipeInvalid("tag_not_latest");
  const timeoutMinutes = input.timeoutMinutes ?? Math.min(30, config.maxMinutes);
  if (!Number.isInteger(timeoutMinutes) || timeoutMinutes < 1)
    throw recipeInvalid("timeout_invalid");
  if (templateBuildLeaseMs(timeoutMinutes, config.captureWindowMinutes) > config.leaseCeilingMs)
    throw recipeInvalid("timeout_exceeds_lease_ceiling");
  if (timeoutMinutes > config.maxMinutes) throw recipeInvalid("timeout_exceeds_max");
  if ((input.poolId === undefined) === (input.sandboxHostId === undefined))
    throw recipeInvalid("target_invalid");
  if (input.waitForCapacityMs !== undefined && input.poolId === undefined)
    throw recipeInvalid("wait_needs_pool");
  const { parsed, sourceFormat } = parseInput(input);
  // Open requests follow the egress plan (§6.3): the build VM's effective
  // policy is resolved at materialization like any sandbox's, downgraded to
  // the fallback grants on a non-consenting foreign builder.
  const hasCopy = parsed.plan.hasCopy;
  if (hasCopy) {
    if (
      typeof input.contextSha256 !== "string" ||
      !/^[0-9a-f]{64}$/.test(input.contextSha256) ||
      !Number.isSafeInteger(input.contextBytes) ||
      (input.contextBytes ?? 0) <= 0
    )
      throw buildError("BAD_REQUEST", "template.build_context_required");
    if ((input.contextBytes ?? 0) > config.contextMaxBytes)
      throw buildError("BAD_REQUEST", "template.build_context_too_large", {
        maxBytes: config.contextMaxBytes,
      });
  } else if (input.contextSha256 !== undefined || input.contextBytes !== undefined)
    throw recipeInvalid("context_without_copy");
  const waitForCapacityMs = frozenCapacityWait(input.waitForCapacityMs, hasCopy);
  const recipeDigest = await sha256Hex(parsed.canonical);
  const requestBodyHash = await sha256Hex(
    canonicalJson({
      template: input.template,
      tag,
      recipe: parsed.canonical,
      buildArgs: input.buildArgs ?? {},
      poolId: input.poolId ?? null,
      sandboxHostId: input.sandboxHostId ?? null,
      resources: input.resources ?? {},
      defaultDiskGiB: input.defaultDiskGiB ?? null,
      timeoutMinutes,
      waitForCapacityMs,
      contextSha256: input.contextSha256 ?? null,
      contextBytes: input.contextBytes ?? null,
      noCache: input.noCache === true,
    }),
  );

  const outcome = await prisma.$transaction(async (tx): Promise<AcceptedTemplateBuild> => {
    await lockOwnerForAdmission(tx, principal.ownerId);
    // Mutation authority serializes with revocation: the key is locked and
    // revalidated inside this transaction and stays locked through commit,
    // so a revocation either commits first (refused here) or waits for this
    // build. Entry authorization alone cannot roll back a committed tag move.
    await authorizeServiceIntent(principal, "templates.build", tx);
    await lockOwnerPlacement(tx, principal.ownerId);
    const prior = await tx.sandboxTemplateBuild.findUnique({
      where: {
        userId_idempotencyKey: { userId: principal.ownerId, idempotencyKey: input.idempotencyKey },
      },
      select: { ...buildViewSelect, requestBodyHash: true, principalKey: true },
    });
    if (prior) {
      if (
        prior.requestBodyHash !== requestBodyHash ||
        prior.principalKey !== accepting.principalKey
      )
        throw new ORPCError("CONFLICT", { data: { code: "sandbox.idempotency_conflict" } });
      const { requestBodyHash: _hash, principalKey: _key, ...build } = prior;
      // The accepting request's replay gets the upload handle again (§3.6).
      return {
        build,
        joined: false,
        cacheHit: build.cacheHitRevisionId !== null,
        needsContext: build.state === "AWAITING_CONTEXT",
      };
    }
    // The base, under the requester's revision allowlist.
    const base = await resolveTemplateRevision(
      tx,
      principal,
      recipeFromSelector(parsed.recipe.from),
    );
    const baseEnvs = Object.fromEntries(await loadRevisionDefaults(tx, base.id, principal.ownerId));
    let exec: ReturnType<typeof buildExecPlan>;
    try {
      exec = buildExecPlan({
        recipe: parsed.recipe,
        buildArgs: input.buildArgs ?? {},
        baseEnvs,
        guest: { uid: base.guestUid, gid: base.guestGid },
      });
    } catch (error) {
      if (error instanceof RecipeError) throw recipeInvalid(error.code, error);
      throw error;
    }
    const templateId = await resolveTargetTemplate(tx, principal, input.template);
    const [template] = await tx.$queryRaw<{ archivedAt: Date | null }[]>`
      SELECT "archivedAt" FROM sandbox_logical_template
      WHERE id = ${templateId} AND "userId" = ${principal.ownerId} FOR UPDATE`;
    if (!template || template.archivedAt) throw templateNotFound();
    // A community template is built only by its own community paths (D-G).
    await refuseCommunityWrite(tx, principal.ownerId, templateId);
    if (input.sandboxHostId !== undefined) {
      // A direct target is always an own host (as for any create).
      const host = await tx.sandboxHost.findFirst({
        where: {
          AND: [
            serviceResourceFilter(principal, "host"),
            { id: input.sandboxHostId, userId: principal.ownerId },
          ],
        },
        select: { id: true },
      });
      if (!host) throw hostNotFound();
    } else await requirePoolUse(tx, principal, input.poolId as string);
    let size: { cpuCount: number; memoryMiB: number; diskGiB: number };
    try {
      size = resolveVmSize(
        {
          cpuCount: base.cpuCount,
          memoryMiB: base.memoryMiB,
          // Unsized builds stay small: the build disk is the published
          // revision's floor, and every descendant's.
          diskGiB: Math.min(base.minDiskGiB + BUILD_DISK_HEADROOM_GIB, VM_SIZE_LIMITS.diskGiBMax),
        },
        { ...(parsed.recipe.resources ?? {}), ...(input.resources ?? {}) },
      );
    } catch {
      throw recipeInvalid("recipe_resources_invalid");
    }
    // The build VM's root holds the base image: it needs at least the base's
    // floor (the same refusal as a sandbox create).
    assertDiskFitsImage(base, size.diskGiB);
    const defaultDiskGiB = input.defaultDiskGiB ?? Math.max(base.defaultDiskGiB, size.diskGiB);
    if (defaultDiskGiB < size.diskGiB) throw diskBelowImage();
    const digest = await buildDigest({
      recipeDigest,
      baseRevisionId: base.id,
      baseFingerprint: base.incusFingerprint,
      args: exec.plan.args,
      contextSha256: hasCopy ? (input.contextSha256 ?? null) : null,
      egressRequest: parsed.egress?.request ?? null,
      // The resolved size, not the raw overrides: the same effective VM
      // reached through recipe or request values is the same result.
      resources: { ...size, defaultDiskGiB },
    });
    const targetKey = input.poolId ?? (input.sandboxHostId as string);
    const common = {
      userId: principal.ownerId,
      templateId,
      tag,
      ...accepting,
      idempotencyKey: input.idempotencyKey,
      requestBodyHash,
      recipe: parsed.recipe as unknown as Prisma.InputJsonValue,
      recipeDigest,
      buildDigest: digest,
      sourceFormat,
      dockerfileText: sourceFormat === "DOCKERFILE" ? (input.dockerfile ?? null) : null,
      baseRevisionId: base.id,
      baseFingerprint: base.incusFingerprint,
      buildArgs: (input.buildArgs ?? {}) as Prisma.InputJsonValue,
      contextSha256: hasCopy ? (input.contextSha256 ?? null) : null,
      contextBytes: hasCopy ? BigInt(input.contextBytes ?? 0) : null,
      poolId: input.poolId ?? null,
      requestedHostId: input.sandboxHostId ?? null,
      targetKey,
      ...size,
      defaultDiskGiB,
      egressRequest: parsed.egress
        ? (parsed.egress.request as unknown as Prisma.InputJsonValue)
        : undefined,
      egressPresets: parsed.egress?.presets ?? [],
      timeoutMinutes,
      waitForCapacityMs,
      chargeMonth: chargeMonthOf(now),
      noCache: input.noCache === true,
    };
    if (input.noCache !== true) {
      const hit = await findCacheHit(tx, principal, templateId, digest);
      if (hit) {
        // No VM, no minutes; the tag moves in this transaction (§3.2).
        await tx.sandboxTemplateTag.upsert({
          where: { templateId_tag: { templateId, tag } },
          create: { userId: principal.ownerId, templateId, revisionId: hit, tag },
          update: { revisionId: hit },
        });
        const build = await tx.sandboxTemplateBuild.create({
          data: {
            ...common,
            state: "SUCCEEDED",
            cacheHitRevisionId: hit,
            reservedMinutes: 0,
            chargedMinutes: 0,
            minutesSettled: true,
            steps: [],
            completedAt: now,
            cleanupState: "DONE",
            cleanupDoneAt: now,
          },
          select: buildViewSelect,
        });
        return { build, joined: false, cacheHit: true, needsContext: false };
      }
      // Join an identical active build of the same target and principal.
      const active = await tx.sandboxTemplateBuild.findFirst({
        where: {
          userId: principal.ownerId,
          templateId,
          tag,
          buildDigest: digest,
          targetKey,
          principalKey: accepting.principalKey,
          state: {
            in: ["AWAITING_CONTEXT", "QUEUED", "PLACING", "RUNNING", "STOPPING", "CAPTURING"],
          },
          noCache: false,
        },
        select: buildViewSelect,
      });
      if (active) return { build: active, joined: true, cacheHit: false, needsContext: false };
    }
    const build = await insertBuildLocked(tx, common, {
      hasContext: hasCopy,
      steps: initialStepRecords(exec.steps),
      now,
      config,
    });
    return { build, joined: false, cacheHit: false, needsContext: hasCopy };
  });
  if (outcome.build.state === "QUEUED") notifyTemplateBuildsChanged();
  return outcome;
}

/** Cancel (§3.8): User → owner placement → build row; records the intent
 * only. Idempotent for CANCELLING/CANCELLED; refused after SUCCEEDED/FAILED. */
export async function requestTemplateBuildCancel(
  principal: Principal,
  buildId: string,
  now: Date = new Date(),
): Promise<TemplateBuildSummary> {
  const build = await prisma.$transaction(async (tx) => {
    await lockOwnerForAdmission(tx, principal.ownerId);
    // As in acceptance: the key is revalidated and held through commit.
    await authorizeServiceIntent(principal, "templates.build", tx);
    await lockOwnerPlacement(tx, principal.ownerId);
    // Visibility first (an ALLOWLIST key cancels only its own builds); a
    // build it cannot see is NOT_FOUND, like a build that does not exist.
    const visible = await tx.sandboxTemplateBuild.findFirst({
      where: { AND: [visibleBuildWhere(principal), { id: buildId }] },
      select: { id: true },
    });
    if (!visible) throw new ORPCError("NOT_FOUND", { message: "Template build not found." });
    const [locked] = await tx.$queryRaw<{ id: string }[]>`
      SELECT id FROM sandbox_template_build
      WHERE id = ${buildId} AND "userId" = ${principal.ownerId} FOR UPDATE`;
    if (!locked) throw new ORPCError("NOT_FOUND", { message: "Template build not found." });
    const row = await tx.sandboxTemplateBuild.findUniqueOrThrow({
      where: { id: buildId },
      select: buildViewSelect,
    });
    if (row.state === "CANCELLING" || row.state === "CANCELLED") return row;
    if (row.state === "SUCCEEDED" || row.state === "FAILED")
      throw buildError("CONFLICT", "template.build_not_cancellable", { state: row.state });
    // A claim in flight is dropped: its result is discarded by tx B, and a
    // create it issued either committed before this (cleaned by §3.10) or is
    // refused by the create-side state check after owner placement (N18).
    // A capture it issued is not lost with the claim: the orchestrator finds
    // it by its immutable (buildId, attempt).
    //
    // Cancel vs. an in-flight capture (E2-A-01 ruling): a host result
    // recorded before this cancel commits wins; one recorded after loses.
    // This UPDATE row-locks every capture of the build that is still PENDING
    // and the relay's result recording (`recordCaptureResult`) updates the
    // same row only while PENDING, so the two serialize on that row and the
    // winner is persisted: a result already recorded leaves the capture
    // CAPTURED/STORING (unmarked, it publishes); otherwise the mark makes the
    // finalizer fail it and release its image. The capture create re-checks
    // the build under its share lock, so none can start after this commits.
    await tx.sandboxTemplateCapture.updateMany({
      where: { buildId, userId: principal.ownerId, state: "PENDING", buildCancelledAt: null },
      data: { buildCancelledAt: now },
    });
    return tx.sandboxTemplateBuild.update({
      where: { id: buildId },
      data: {
        state: "CANCELLING",
        cancelRequestedAt: now,
        pendingAction: PrismaValue.DbNull,
        nextAttemptAt: now,
      },
      select: buildViewSelect,
    });
  });
  notifyTemplateBuildsChanged();
  notifyTemplateBuildProgress(buildId);
  return build;
}
