/**
 * Template-build reads: get, list and step logs, plus the one
 * visibility rule every build route uses (r3 N20, `visibleBuildWhere`).
 *
 * A session and an `ALL_OWNED` key see every build of the owner; an
 * `ALLOWLIST` key sees only the builds it accepted itself (the sandbox
 * `creationKey` rule). Anything else is NOT_FOUND, indistinguishable from a
 * build that does not exist (pg 8b, pg 26). The rule is built on
 * `grantOf`/`viewerOf`/`recordedKeyIdOf`, never on a kind comparison.
 */
import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import {
  PAGE_SIZE_DEFAULT,
  type SandboxEgressModeReason,
  TEMPLATE_BUILD_ERROR_CODES,
  TEMPLATE_BUILD_STATES,
  type TemplateBuildDto,
  type TemplateBuildErrorCode,
  type TemplateBuildStateDto,
  type TemplateBuildStepDto,
} from "@wssp/sandbox-contracts";
import { z } from "zod";
import { cursorPage, cursorTokenSchema, pageTake, withCursor } from "../lib/pagination";
import { serviceProcedure } from "../lib/sdk-key-access";
import { consumeSandboxWriteBudget } from "../sandbox/budgets";
import type { Principal } from "../sandbox/contracts";
import { imageDistributionMode } from "../sandbox/image-store/config";
import { budgetSubjectOf } from "../sandbox/principal-kinds";
import { egressModeReasonDto } from "../sandbox/public-dto";
import { getCommandOutput } from "../sandbox/services/sandboxes";
import { templateBuildCapabilities } from "./config";
import { ACTIVE_BUILD_STATES } from "./decide";
import { parseStepRecords } from "./exec-plan";
import { stepHints } from "./hints";
import { loadBuildPrincipal } from "./principal";
import {
  acceptTemplateBuild,
  buildMinutesUsed,
  type CreateTemplateBuildInput,
  requestTemplateBuildCancel,
  templateBuildInputFromBody,
} from "./service";
import { buildViewSelect, type TemplateBuildSummary, visibleBuildWhere } from "./visibility";

export { templateBuildWatchKey } from "./wake";

export {
  buildViewSelect,
  type TemplateBuildSummary,
  templateBuildInputFromBody,
  visibleBuildWhere,
};

const ERROR_CODES: ReadonlySet<string> = new Set(TEMPLATE_BUILD_ERROR_CODES);

function stepDto(step: ReturnType<typeof parseStepRecords>[number]): TemplateBuildStepDto {
  return {
    n: step.n,
    stepIndex: step.stepIndex,
    kind: step.kind,
    state: step.state,
    operationId: step.operationId ?? null,
    exitCode: step.exitCode ?? null,
  };
}

/**
 * The build VMs' effective-egress downgrade reasons (§6.3, I24): read from
 * each build VM's sandbox row (`Sandbox.buildId`), never stored on the build.
 */
export async function buildEgressModeReasons(
  ownerId: string,
  buildIds: readonly string[],
): Promise<Map<string, SandboxEgressModeReason>> {
  if (buildIds.length === 0) return new Map();
  const rows = await prisma.sandbox.findMany({
    where: { userId: ownerId, buildId: { in: [...buildIds] }, egressModeReason: { not: null } },
    select: { buildId: true, egressModeReason: true },
    take: buildIds.length,
  });
  const out = new Map<string, SandboxEgressModeReason>();
  for (const row of rows) {
    const reason = egressModeReasonDto(row.egressModeReason);
    if (row.buildId && reason) out.set(row.buildId, reason);
  }
  return out;
}

export function toTemplateBuildDto(
  row: TemplateBuildSummary,
  egressModeReason: SandboxEgressModeReason | null = null,
): TemplateBuildDto {
  return {
    id: row.id,
    templateId: row.templateId,
    tag: row.tag,
    acceptedBy: row.principalKind,
    state: row.state,
    phase: row.phase,
    stepIndex: row.stepIndex,
    steps: parseStepRecords(row.steps).map(stepDto),
    recipeDigest: row.recipeDigest,
    buildDigest: row.buildDigest,
    contextSha256: row.contextSha256,
    contextBytes: row.contextBytes === null ? null : Number(row.contextBytes),
    timeoutMinutes: row.timeoutMinutes,
    reservedMinutes: row.reservedMinutes,
    chargedMinutes: row.chargedMinutes,
    revisionId: row.revisionId,
    cacheHitRevisionId: row.cacheHitRevisionId,
    // The catalog is CHECK-bound in the database; anything else is internal.
    errorCode:
      row.errorCode === null
        ? null
        : ERROR_CODES.has(row.errorCode)
          ? (row.errorCode as TemplateBuildErrorCode)
          : "build_internal",
    errorDetail: row.errorDetail,
    failureStepIndex: row.failureStepIndex,
    failureExitCode: row.failureExitCode,
    cancelRequestedAt: row.cancelRequestedAt?.toISOString() ?? null,
    cleanupState: row.cleanupState,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
    completedAt: row.completedAt?.toISOString() ?? null,
    egressModeReason,
  };
}

/**
 * Browser plane only (the `/v1` DTO is unchanged): each build with its
 * template's display name (label, else slug), its slug, and the result
 * revision's number, so pages show `slug:tag` and `slug vN` and never raw
 * ids. Builds are owner-scoped, and so are both lookups.
 */
export async function withTemplateNames<
  T extends { templateId: string; revisionId?: string | null; cacheHitRevisionId?: string | null },
>(
  ownerId: string,
  builds: readonly T[],
): Promise<
  (T & {
    templateName: string | null;
    templateSlug: string | null;
    revisionNumber: number | null;
  })[]
> {
  const ids = [...new Set(builds.map((build) => build.templateId))];
  // The result revision: the captured one, else the one an identical build reused.
  const resultOf = (build: T) => build.revisionId ?? build.cacheHitRevisionId ?? null;
  const revisionIds = [
    ...new Set(builds.flatMap((build) => (resultOf(build) ? [resultOf(build) as string] : []))),
  ];
  const [rows, revisions] = await Promise.all([
    ids.length
      ? prisma.sandboxTemplate.findMany({
          where: { userId: ownerId, id: { in: ids } },
          select: { id: true, slug: true, label: true } satisfies Prisma.SandboxTemplateSelect,
          take: ids.length,
        })
      : [],
    revisionIds.length
      ? prisma.sandboxTemplateRevision.findMany({
          where: { id: { in: revisionIds }, Template: { userId: ownerId } },
          select: { id: true, revision: true } satisfies Prisma.SandboxTemplateRevisionSelect,
          take: revisionIds.length,
        })
      : [],
  ]);
  const templates = new Map(rows.map((row) => [row.id, row]));
  const numbers = new Map(revisions.map((row) => [row.id, row.revision]));
  return builds.map((build) => {
    const template = templates.get(build.templateId);
    return {
      ...build,
      templateName: template ? template.label || template.slug : null,
      templateSlug: template?.slug ?? null,
      revisionNumber: numbers.get(resultOf(build) ?? "") ?? null,
    };
  });
}

export function templateBuildNotFound() {
  return new ORPCError("NOT_FOUND", { message: "Template build not found." });
}

const buildIdSchema = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/);
export const templateBuildIdInput = z.object({ id: buildIdSchema });
export const listTemplateBuildsInput = z.object({
  cursor: cursorTokenSchema.optional(),
  limit: z.number().int().min(1).max(100).default(PAGE_SIZE_DEFAULT),
  templateId: buildIdSchema.optional(),
  state: z.enum(TEMPLATE_BUILD_STATES).optional(),
});
export const templateBuildLogsInput = templateBuildIdInput.extend({
  step: z.number().int().min(0).max(255),
  cursor: z
    .string()
    .regex(/^[A-Za-z0-9_-]{1,128}$/)
    .optional(),
  maxBytes: z.number().int().min(1).max(65536).optional(),
});

function parse<T extends z.ZodType>(schema: T, input: unknown): z.output<T> {
  const parsed = schema.safeParse(input);
  if (!parsed.success) throw new ORPCError("BAD_REQUEST");
  return parsed.data;
}

const TERMINAL: ReadonlySet<TemplateBuildStateDto> = new Set(["SUCCEEDED", "FAILED", "CANCELLED"]);
export function isTemplateBuildTerminal(build: { state: TemplateBuildStateDto }): boolean {
  return TERMINAL.has(build.state);
}

export const getTemplateBuild = serviceProcedure(
  { action: "templates.build" },
  async (principal: Principal, input: z.input<typeof templateBuildIdInput>) => {
    const { id } = parse(templateBuildIdInput, input);
    const row = await prisma.sandboxTemplateBuild.findFirst({
      where: { AND: [visibleBuildWhere(principal), { id }] },
      select: buildViewSelect,
    });
    if (!row) throw templateBuildNotFound();
    const reasons = await buildEgressModeReasons(principal.ownerId, [row.id]);
    return toTemplateBuildDto(row, reasons.get(row.id) ?? null);
  },
);

export const listTemplateBuilds = serviceProcedure(
  { action: "templates.build" },
  async (principal: Principal, input: z.input<typeof listTemplateBuildsInput>) => {
    const page = parse(listTemplateBuildsInput, input);
    const where: Prisma.SandboxTemplateBuildWhereInput = {
      AND: [
        visibleBuildWhere(principal),
        ...(page.templateId ? [{ templateId: page.templateId }] : []),
        ...(page.state ? [{ state: page.state }] : []),
      ],
    };
    const rows = await prisma.sandboxTemplateBuild.findMany({
      where: withCursor(where, "createdAt", page.cursor, "desc"),
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: pageTake(page.limit),
      select: buildViewSelect,
    });
    const result = cursorPage(rows, page.limit, "createdAt");
    const reasons = await buildEgressModeReasons(
      principal.ownerId,
      result.items.map((row) => row.id),
    );
    return {
      items: result.items.map((row) => toTemplateBuildDto(row, reasons.get(row.id) ?? null)),
      nextCursor: result.nextCursor,
    };
  },
);

/**
 * One page of one executed step's output. The requester only needs
 * `templates:build` and visibility of the build: the output is read with the
 * build principal's read class, never with the requester's
 * `operations:read`/`commands:read`.
 */
export const getTemplateBuildLogs = serviceProcedure(
  { action: "templates.build" },
  async (principal: Principal, input: z.input<typeof templateBuildLogsInput>) => {
    const query = parse(templateBuildLogsInput, input);
    const row = await prisma.sandboxTemplateBuild.findFirst({
      where: { AND: [visibleBuildWhere(principal), { id: query.id }] },
      select: { id: true, steps: true, egressHints: true, foreignHost: true },
    });
    if (!row) throw templateBuildNotFound();
    const step = parseStepRecords(row.steps).find((record) => record.n === query.step);
    if (!step) throw new ORPCError("BAD_REQUEST", { message: "No such build step." });
    // B12: blocked-name hints interleave as synthetic lines of this step.
    const hints = stepHints(row, step.n);
    if (!step.operationId) return { buildId: row.id, step: stepDto(step), output: null, hints };
    const build = await loadBuildPrincipal(prisma, row.id, principal.ownerId);
    if (!build) throw templateBuildNotFound();
    const output = await getCommandOutput(build, {
      operationId: step.operationId,
      cursor: query.cursor,
      maxBytes: query.maxBytes,
    });
    return { buildId: row.id, step: stepDto(step), output, hints };
  },
);

/** Acceptance and cancel request rate (§7): the owner's "build" budget. */
async function consumeBuildBudget(principal: Principal) {
  const subject = budgetSubjectOf(principal);
  if (subject) await consumeSandboxWriteBudget(subject.ownerId, "build");
}

/** Entry points for both planes: a session (all scopes) or an SDK key with
 * `templates:build` (and `templates:write` to create the template by slug). */
export const createTemplateBuild = serviceProcedure(
  { action: "templates.build" },
  async (principal: Principal, input: CreateTemplateBuildInput) => {
    await consumeBuildBudget(principal);
    return acceptTemplateBuild(principal, input);
  },
);

export const cancelTemplateBuild = serviceProcedure(
  { action: "templates.build" },
  async (principal: Principal, input: { id: string }) => {
    await consumeBuildBudget(principal);
    return requestTemplateBuildCancel(principal, input.id);
  },
);

/**
 * Owner-only (browser session): the failed step's output tail, kept beyond
 * the 24 h output retention. Not part of the build DTO
 * or any `/v1` route; a key cannot read it.
 */
export const getTemplateBuildFailureTail = serviceProcedure(
  { sessionOnly: true },
  async (principal: Principal, input: z.input<typeof templateBuildIdInput>) => {
    const { id } = parse(templateBuildIdInput, input);
    const row = await prisma.sandboxTemplateBuild.findFirst({
      where: { AND: [visibleBuildWhere(principal), { id, userId: principal.ownerId }] },
      select: { failureTail: true } satisfies Prisma.SandboxTemplateBuildSelect,
    });
    if (!row) throw templateBuildNotFound();
    return {
      tail: row.failureTail ? new TextDecoder("utf-8").decode(row.failureTail) : null,
    };
  },
);

/**
 * Browser session: whether builds are available (and why not), the account's
 * build quotas and current usage, and the owner's foreign-builds consent.
 */
export const getTemplateBuildUsage = serviceProcedure(
  { sessionOnly: true },
  async (principal: Principal, _input: undefined) => {
    const ownerId = principal.ownerId;
    const limits = await templateBuildCapabilities(prisma, ownerId);
    const activeBuilds = await prisma.sandboxTemplateBuild.count({
      where: { userId: ownerId, state: { in: [...ACTIVE_BUILD_STATES] } },
    });
    const minutesUsedThisMonth = await buildMinutesUsed(prisma, ownerId, new Date());
    const policy = await prisma.accountImagePolicy.findUnique({
      where: { userId: ownerId },
      select: { allowForeignBuilds: true },
    });
    return {
      ...limits,
      imageMode: imageDistributionMode(),
      allowForeignBuilds: policy?.allowForeignBuilds ?? false,
      usage: { activeBuilds, minutesUsedThisMonth },
    };
  },
);
