import { randomUUID } from "node:crypto";
import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { canonicalJson, parseRecipe, sha256Hex } from "@wssp/template-recipe";
import { authorizeServiceIntent, serviceResourceFilter } from "../../lib/sdk-key-access";
import type { Principal } from "../../sandbox/contracts";
import { lockOwnerPlacement } from "../../sandbox/direct-placement";
import { hostNotFound, templateNotFound } from "../../sandbox/errors";
import { imageDistributionMode } from "../../sandbox/image-store/config";
import {
  buildIdOf,
  grantOf,
  isBrowserSession,
  recordedKeyIdOf,
  viewerOf,
} from "../../sandbox/principal-kinds";
import { writeRevisionDefaults } from "../../sandbox/revision-config";
import { requirePoolUse } from "../../sandbox/sharing-authority";
import { TEMPLATE_BUILD_LEASE_SLACK_MINUTES, templateBuildsConfig } from "../config";
import { ACTIVE_BUILD_STATES } from "../decide";
import { buildExecPlan, initialStepRecords } from "../exec-plan";
import { buildError, chargeMonthOf, insertBuildLocked } from "../service";
import { buildViewSelect, type TemplateBuildSummary } from "../visibility";
import { notifyTemplateBuildsChanged } from "../wake";
import {
  COMMUNITY_IMAGES,
  COMMUNITY_REFRESH_MIN_AGE_MS,
  type CommunityImageEntry,
  communityImage,
  UBUNTU_CLOUD_PREP_V1,
  UBUNTU_CLOUD_PREP_V1_DIGEST,
  UPSTREAM_GUEST,
  VERIFY_WINDOW_MINUTES,
} from "./catalog";
import {
  type CommunityIndexClient,
  CommunityIndexError,
  communityIndexClient,
  type UpstreamPin,
} from "./index-client";
import { communityManaged } from "./managed";
import { communityPrepBuildDigest } from "./wssp-recipe";

/**
 * Community base templates (community-base S8, S10). The ONLY writer of
 * UPSTREAM revisions (the dedicated insert, never the registration helper:
 * no tag, no availability) and of COMMUNITY_PREP builds. Every path checks,
 * in order: builds enabled and image distribution on (D-M), the key's scope
 * (D-K), the timeout fit, the owner's build quota (inside the transaction),
 * then reads the index BEFORE its transaction (no network IO under locks).
 *
 * Lock order: owner admission → (key, revalidated) → owner placement →
 * template → build insert, the build acceptance order (§3.4).
 */

export type CommunityTarget = { poolId: string } | { sandboxHostId: string };

export type CommunityImageChoice = {
  id: string;
  label: string;
  architecture: string;
  /** The prep build's size: `diskGiB` becomes the base's `minDiskGiB`. */
  resources: { cpuCount: number; memoryMiB: number; diskGiB: number; defaultDiskGiB: number };
};

/** The tested picker entries, and why creation is disabled (if it is). */
export function listCommunityImages(): {
  images: CommunityImageChoice[];
  disabledReason: string | null;
} {
  return {
    images: COMMUNITY_IMAGES.filter((entry) => entry.tested).map((entry) => ({
      id: entry.id,
      label: entry.label,
      architecture: entry.architecture,
      resources: { ...entry.resources },
    })),
    disabledReason: communityDisabledReason(),
  };
}

/** The community build's whole reservation: the recipe plus the verify window. */
export function communityTimeoutMinutes(entry: CommunityImageEntry): number {
  return entry.recipeTimeoutMinutes + VERIFY_WINDOW_MINUTES;
}

function communityDisabledReason(): string | null {
  const config = templateBuildsConfig();
  if (!config.enabled) return config.reason ?? "off";
  if (imageDistributionMode() === "off") return "image_distribution_off";
  return null;
}

/** D-M, D-K and the timeout fit, before any lock or network IO. */
function preflight(principal: Principal, entry: CommunityImageEntry) {
  const config = templateBuildsConfig();
  if (!config.enabled)
    throw buildError("SERVICE_UNAVAILABLE", "template.build_disabled", { reason: config.reason });
  if (imageDistributionMode() === "off")
    throw buildError("SERVICE_UNAVAILABLE", "template.build_disabled", {
      reason: "image_distribution_off",
    });
  if (buildIdOf(principal) !== null) throw new ORPCError("FORBIDDEN");
  // D-K: an ALLOWLIST key could never see the new template or its revisions;
  // it is refused up front, typed, before anything is written.
  if (!isBrowserSession(principal) && viewerOf(principal).resourceMode === "ALLOWLIST")
    throw new ORPCError("FORBIDDEN", {
      message: "Community templates need a key that can see every template and revision.",
      data: { code: "template.community_key_scope" },
    });
  if (!isBrowserSession(principal) && !grantOf(principal).has("templates:write"))
    throw new ORPCError("FORBIDDEN");
  const timeoutMinutes = communityTimeoutMinutes(entry);
  // A misfit is refused, never truncated (S8).
  if (
    timeoutMinutes > config.maxMinutes ||
    (timeoutMinutes + config.captureWindowMinutes + TEMPLATE_BUILD_LEASE_SLACK_MINUTES) * 60_000 >
      config.leaseCeilingMs
  )
    throw buildError("SERVICE_UNAVAILABLE", "template.build_disabled", {
      reason: "community_timeout_exceeds_max",
    });
  return { config, timeoutMinutes };
}

/** The index read, before any transaction (typed 409 on failure). */
async function readPin(entry: CommunityImageEntry, client: CommunityIndexClient) {
  try {
    return await client.newest(entry);
  } catch (error) {
    const reason = error instanceof CommunityIndexError ? error.reason : "index_unreachable";
    throw new ORPCError("CONFLICT", {
      message: "No tested community image is available right now.",
      data: { code: "template.community_unavailable", reason },
    });
  }
}

async function requireTarget(
  tx: Prisma.TransactionClient,
  principal: Principal,
  target: CommunityTarget,
) {
  if ("sandboxHostId" in target) {
    const host = await tx.sandboxHost.findFirst({
      where: {
        AND: [
          serviceResourceFilter(principal, "host"),
          { id: target.sandboxHostId, userId: principal.ownerId },
        ],
      },
      select: { id: true },
    });
    if (!host) throw hostNotFound();
    return { poolId: null, requestedHostId: host.id, targetKey: host.id };
  }
  await requirePoolUse(tx, principal, target.poolId);
  return { poolId: target.poolId, requestedHostId: null, targetKey: target.poolId };
}

/**
 * The dedicated UPSTREAM insert (D-A, M1): a hidden revision of the
 * template with the target identity declared, its pinned upstream facts, and
 * NO tag and NO availability. Idempotent per (template, fingerprint) (I10): a
 * known pin is reused, revived when it had retired idle.
 */
async function upsertUpstreamRevision(
  tx: Prisma.TransactionClient,
  ownerId: string,
  templateId: string,
  entry: CommunityImageEntry,
  pin: UpstreamPin,
): Promise<{ id: string; fingerprint: string }> {
  const known = await tx.sandboxUpstreamImage.findFirst({
    where: { templateId, userId: ownerId, fingerprint: pin.fingerprint },
    select: { revisionId: true },
  });
  if (known) {
    await tx.sandboxTemplateRevision.updateMany({
      where: { id: known.revisionId, userId: ownerId, sourceKind: "UPSTREAM" },
      data: { retiredAt: null, retiredReason: null },
    });
    return { id: known.revisionId, fingerprint: pin.fingerprint };
  }
  await tx.$queryRaw`SELECT id FROM sandbox_template_tag WHERE "templateId" = ${templateId} AND "userId" = ${ownerId} ORDER BY id FOR UPDATE`;
  const last = await tx.sandboxTemplateRevision.findFirst({
    where: { templateId, userId: ownerId },
    orderBy: { revision: "desc" },
    select: { revision: true },
  });
  const manifest = {
    incusFingerprint: pin.fingerprint,
    architecture: pin.architecture,
    ...UPSTREAM_GUEST,
    guestVersion: pin.version,
  };
  const revision = await tx.sandboxTemplateRevision.create({
    data: {
      userId: ownerId,
      templateId,
      revision: (last?.revision ?? 0) + 1,
      ...manifest,
      // Hidden build base: its floor and default are the prep build's disk.
      cpuCount: entry.resources.cpuCount,
      memoryMiB: entry.resources.memoryMiB,
      minDiskGiB: entry.resources.diskGiB,
      defaultDiskGiB: entry.resources.diskGiB,
      manifestDigest: await sha256Hex(canonicalJson(manifest)),
      sourceKind: "UPSTREAM",
    },
    select: { id: true },
  });
  // Every revision has its private defaults row (empty here): the build
  // and the placement read it like any base's.
  await writeRevisionDefaults(tx, ownerId, revision.id, {});
  await tx.sandboxUpstreamImage.create({
    data: {
      userId: ownerId,
      templateId,
      revisionId: revision.id,
      source: entry.id,
      product: pin.product,
      version: pin.version,
      fingerprint: pin.fingerprint,
      architecture: pin.architecture,
      metaPath: pin.metaPath,
      metaSha256: pin.metaSha256,
      metaSize: BigInt(pin.metaSize),
      diskPath: pin.diskPath,
      diskSha256: pin.diskSha256,
      diskSize: BigInt(pin.diskSize),
    },
  });
  return { id: revision.id, fingerprint: pin.fingerprint };
}

type Accepting =
  | { principalKind: "session"; authorizingKeyId: null; principalKey: "s" }
  | { principalKind: "sdkKey"; authorizingKeyId: string; principalKey: string }
  | {
      principalKind: "system";
      authorizingKeyId: null;
      principalKey: "sys";
      triggeredByRevisionId: string;
    };

function acceptingOf(principal: Principal): Accepting {
  if (isBrowserSession(principal))
    return { principalKind: "session", authorizingKeyId: null, principalKey: "s" };
  const keyId = recordedKeyIdOf(principal);
  if (keyId === null) throw new ORPCError("FORBIDDEN");
  return { principalKind: "sdkKey", authorizingKeyId: keyId, principalKey: `k:${keyId}` };
}

/**
 * The canonical identity of a community request (Codex P3): what a replay
 * under the same idempotency key must repeat exactly, else it is an
 * idempotency conflict, never the earlier acceptance.
 */
function communityRequestHash(
  request:
    | { kind: "create"; source: string; target: CommunityTarget; label: string | null }
    | { kind: "retry"; templateId: string; target: CommunityTarget | null },
): Promise<string> {
  return sha256Hex(canonicalJson(request));
}

/** The replay of `prior` is ours only for the same request and principal. */
function requireSameRequest(
  prior: { origin: string; requestBodyHash: string; principalKey: string },
  requestBodyHash: string,
  accepting: Accepting,
) {
  if (
    prior.origin !== "COMMUNITY_PREP" ||
    prior.requestBodyHash !== requestBodyHash ||
    prior.principalKey !== accepting.principalKey
  )
    throw new ORPCError("CONFLICT", { data: { code: "sandbox.idempotency_conflict" } });
}

/**
 * Insert one COMMUNITY_PREP build (the only writer of that origin, guest-sudo
 * U3). Server-composed: the constant recipe on the template's own UPSTREAM
 * base, verify required, never cached or joined, no capacity wait, the
 * catalog size, the build VM pinned to `guestSudo = false` by the
 * orchestrator's create (D-O).
 */
async function insertCommunityBuild(
  tx: Prisma.TransactionClient,
  input: {
    ownerId: string;
    templateId: string;
    entry: CommunityImageEntry;
    base: { id: string; fingerprint: string };
    target: { poolId: string | null; requestedHostId: string | null; targetKey: string };
    accepting: Accepting;
    idempotencyKey: string;
    /** The canonical request identity a replay of the key must match. */
    requestBodyHash: string;
    timeoutMinutes: number;
    now: Date;
    config: ReturnType<typeof templateBuildsConfig>;
  },
): Promise<TemplateBuildSummary> {
  const parsed = parseRecipe(UBUNTU_CLOUD_PREP_V1, {});
  const exec = buildExecPlan({
    recipe: UBUNTU_CLOUD_PREP_V1,
    buildArgs: {},
    baseEnvs: {},
    guest: { uid: UPSTREAM_GUEST.guestUid, gid: UPSTREAM_GUEST.guestGid },
  });
  return insertBuildLocked(
    tx,
    {
      userId: input.ownerId,
      templateId: input.templateId,
      tag: "latest",
      ...input.accepting,
      idempotencyKey: input.idempotencyKey,
      requestBodyHash: input.requestBodyHash,
      recipe: UBUNTU_CLOUD_PREP_V1 as unknown as Prisma.InputJsonValue,
      recipeDigest: UBUNTU_CLOUD_PREP_V1_DIGEST,
      buildDigest: await communityPrepBuildDigest({
        baseRevisionId: input.base.id,
        baseFingerprint: input.base.fingerprint,
        resources: input.entry.resources,
      }),
      sourceFormat: "RECIPE",
      dockerfileText: null,
      baseRevisionId: input.base.id,
      baseFingerprint: input.base.fingerprint,
      buildArgs: {},
      contextSha256: null,
      contextBytes: null,
      ...input.target,
      ...input.entry.resources,
      egressRequest: parsed.egress
        ? (parsed.egress.request as unknown as Prisma.InputJsonValue)
        : undefined,
      egressPresets: parsed.egress?.presets ?? [],
      timeoutMinutes: input.timeoutMinutes,
      waitForCapacityMs: null,
      chargeMonth: chargeMonthOf(input.now),
      noCache: true,
      origin: "COMMUNITY_PREP",
      verifyRequired: true,
    },
    {
      hasContext: false,
      steps: initialStepRecords(exec.steps),
      now: input.now,
      config: input.config,
    },
  );
}

export type CommunityTemplateResult = {
  template: { id: string; slug: string; label: string };
  build: TemplateBuildSummary | null;
  /** The template already existed for this catalog entry (same-source join). */
  existing: boolean;
};

const templateFields = { id: true, slug: true, label: true } as const;

async function activeCommunityBuild(
  tx: Prisma.TransactionClient,
  ownerId: string,
  templateId: string,
) {
  return tx.sandboxTemplateBuild.findFirst({
    where: { userId: ownerId, templateId, state: { in: [...ACTIVE_BUILD_STATES] } },
    orderBy: { createdAt: "desc" },
    select: buildViewSelect,
  });
}

/** A free slug for the new template: the catalog slug, else `-2`…`-9`. */
async function freeSlug(tx: Prisma.TransactionClient, ownerId: string, base: string) {
  for (let n = 1; n < 10; n++) {
    const slug = n === 1 ? base : `${base}-${n}`;
    const taken = await tx.sandboxTemplate.findFirst({
      where: { userId: ownerId, slug },
      select: { id: true },
    });
    if (!taken) return slug;
  }
  throw new ORPCError("CONFLICT", { data: { code: "sandbox.template_exists" } });
}

/**
 * Create the owner's community template for `source` and its first prep
 * build (S8). Idempotent: the same key replays its build; another create of
 * the same source returns the existing template (and its active build).
 */
export async function createCommunityTemplate(
  principal: Principal,
  input: { source: string; idempotencyKey: string; target: CommunityTarget; label?: string },
  now: Date = new Date(),
  index: CommunityIndexClient = communityIndexClient(),
): Promise<CommunityTemplateResult> {
  const entry = communityImage(input.source);
  if (!entry?.tested)
    throw buildError("BAD_REQUEST", "template.build_recipe_invalid", {
      recipeCode: "community_source_invalid",
    });
  const { config, timeoutMinutes } = preflight(principal, entry);
  const accepting = acceptingOf(principal);
  const requestBodyHash = await communityRequestHash({
    kind: "create",
    source: entry.id,
    target: input.target,
    label: input.label?.trim() || null,
  });
  const pin = await readPin(entry, index);
  const result = await prisma.$transaction(async (tx): Promise<CommunityTemplateResult> => {
    await lockOwnerForAdmission(tx, principal.ownerId);
    // The key is revalidated and held through commit (as in acceptance).
    await authorizeServiceIntent(principal, "templates.build", tx);
    await lockOwnerPlacement(tx, principal.ownerId);
    const prior = await tx.sandboxTemplateBuild.findUnique({
      where: {
        userId_idempotencyKey: { userId: principal.ownerId, idempotencyKey: input.idempotencyKey },
      },
      select: {
        ...buildViewSelect,
        origin: true,
        requestBodyHash: true,
        principalKey: true,
        Template: { select: templateFields },
      },
    });
    if (prior) {
      requireSameRequest(prior, requestBodyHash, accepting);
      const { Template, origin: _o, requestBodyHash: _h, principalKey: _k, ...build } = prior;
      return { template: Template, build, existing: true };
    }
    const target = await requireTarget(tx, principal, input.target);
    const same = await tx.sandboxTemplate.findFirst({
      where: { userId: principal.ownerId, communitySource: entry.id },
      select: { ...templateFields, archivedAt: true },
    });
    if (same && same.archivedAt === null) {
      // The same-source template: join it, never a second one.
      const { archivedAt: _archived, ...template } = same;
      return {
        template,
        build: await activeCommunityBuild(tx, principal.ownerId, same.id),
        existing: true,
      };
    }
    // An archived community template keeps its rows but stops being the
    // owner's community template for this source (one per owner, I10).
    if (same)
      await tx.sandboxTemplate.update({ where: { id: same.id }, data: { communitySource: null } });
    const template = await tx.sandboxTemplate.create({
      data: {
        userId: principal.ownerId,
        slug: await freeSlug(tx, principal.ownerId, entry.slug),
        label: input.label?.trim() || entry.label,
        communitySource: entry.id,
      },
      select: templateFields,
    });
    await tx.$queryRaw`SELECT id FROM sandbox_logical_template WHERE id = ${template.id} FOR UPDATE`;
    const base = await upsertUpstreamRevision(tx, principal.ownerId, template.id, entry, pin);
    const build = await insertCommunityBuild(tx, {
      ownerId: principal.ownerId,
      templateId: template.id,
      entry,
      base,
      target,
      accepting,
      idempotencyKey: input.idempotencyKey,
      requestBodyHash,
      timeoutMinutes,
      now,
      config,
    });
    return { template, build, existing: false };
  });
  if (result.build?.state === "QUEUED") notifyTemplateBuildsChanged();
  return result;
}

/** The visible, live community template, locked, with its catalog entry. */
async function lockCommunityTemplate(
  tx: Prisma.TransactionClient,
  principal: Principal,
  templateId: string,
) {
  const visible = await tx.sandboxTemplate.findFirst({
    where: { AND: [serviceResourceFilter(principal, "template"), { id: templateId }] },
    select: { id: true },
  });
  if (!visible) throw templateNotFound();
  const [row] = await tx.$queryRaw<
    {
      id: string;
      slug: string;
      label: string;
      archivedAt: Date | null;
      communitySource: string | null;
    }[]
  >`SELECT id, slug, label, "archivedAt", "communitySource" FROM sandbox_logical_template
    WHERE id = ${templateId} AND "userId" = ${principal.ownerId} FOR UPDATE`;
  if (!row || row.archivedAt) throw templateNotFound();
  const entry = row.communitySource ? communityImage(row.communitySource) : null;
  if (!entry) throw communityManaged();
  return { template: { id: row.id, slug: row.slug, label: row.label }, entry };
}

/** The last community build's target (retry and refresh reuse it). */
async function lastTarget(tx: Prisma.TransactionClient, ownerId: string, templateId: string) {
  const last = await tx.sandboxTemplateBuild.findFirst({
    where: { userId: ownerId, templateId, origin: "COMMUNITY_PREP" },
    orderBy: { createdAt: "desc" },
    select: { poolId: true, requestedHostId: true, targetKey: true },
  });
  return last;
}

/**
 * "Try again" (D-F): a new prep build under the caller's principal, on the
 * newest upstream pin, after a failed or cancelled one. Refused while a
 * build is active (that build is returned instead).
 */
export async function retryCommunityTemplate(
  principal: Principal,
  input: { templateId: string; idempotencyKey: string; target?: CommunityTarget },
  now: Date = new Date(),
  index: CommunityIndexClient = communityIndexClient(),
): Promise<CommunityTemplateResult> {
  const probe = await prisma.sandboxTemplate.findFirst({
    where: { AND: [serviceResourceFilter(principal, "template"), { id: input.templateId }] },
    select: { communitySource: true },
  });
  const entry = probe?.communitySource ? communityImage(probe.communitySource) : null;
  if (!probe) throw templateNotFound();
  if (!entry) throw communityManaged();
  const { config, timeoutMinutes } = preflight(principal, entry);
  const accepting = acceptingOf(principal);
  const requestBodyHash = await communityRequestHash({
    kind: "retry",
    templateId: input.templateId,
    target: input.target ?? null,
  });
  const pin = await readPin(entry, index);
  const result = await prisma.$transaction(async (tx): Promise<CommunityTemplateResult> => {
    await lockOwnerForAdmission(tx, principal.ownerId);
    await authorizeServiceIntent(principal, "templates.build", tx);
    await lockOwnerPlacement(tx, principal.ownerId);
    const prior = await tx.sandboxTemplateBuild.findUnique({
      where: {
        userId_idempotencyKey: { userId: principal.ownerId, idempotencyKey: input.idempotencyKey },
      },
      select: {
        ...buildViewSelect,
        origin: true,
        requestBodyHash: true,
        principalKey: true,
        Template: { select: templateFields },
      },
    });
    if (prior) {
      requireSameRequest(prior, requestBodyHash, accepting);
      const { Template, origin: _o, requestBodyHash: _h, principalKey: _k, ...build } = prior;
      return { template: Template, build, existing: true };
    }
    const { template } = await lockCommunityTemplate(tx, principal, input.templateId);
    const active = await activeCommunityBuild(tx, principal.ownerId, template.id);
    if (active) return { template, build: active, existing: true };
    const target = input.target
      ? await requireTarget(tx, principal, input.target)
      : await lastTarget(tx, principal.ownerId, template.id);
    if (!target) throw hostNotFound();
    const base = await upsertUpstreamRevision(tx, principal.ownerId, template.id, entry, pin);
    const build = await insertCommunityBuild(tx, {
      ownerId: principal.ownerId,
      templateId: template.id,
      entry,
      base,
      target,
      accepting,
      idempotencyKey: input.idempotencyKey,
      requestBodyHash,
      timeoutMinutes,
      now,
      config,
    });
    return { template, build, existing: false };
  });
  if (result.build?.state === "QUEUED") notifyTemplateBuildsChanged();
  return result;
}

export type RefreshOutcome =
  | { kind: "started"; buildId: string }
  | { kind: "active"; buildId: string }
  | {
      kind: "skipped";
      reason:
        | "no_latest"
        | "archived"
        | "owner_inactive"
        | "refresh_off"
        | "builds_disabled"
        | "timeout_misfit"
        | "unchanged"
        | "too_recent"
        | "quota"
        | "no_target";
    };

/**
 * One refresh of one community template (S10), under the caller's locks
 * (owner admission → placement). A system build anchored on `latest`
 * (`triggeredByRevisionId`, D-F). `bypassAge`: "Refresh now" and
 * refresh-on-miss skip the 7-day minimum (and the owner's switch).
 */
async function refreshCommunityTemplateLocked(
  tx: Prisma.TransactionClient,
  input: {
    ownerId: string;
    templateId: string;
    pin: UpstreamPin;
    bypassAge: boolean;
    now: Date;
    /** Refresh-on-miss: rebuild even from the same pin (the image is gone). */
    rebuild?: boolean;
  },
): Promise<RefreshOutcome> {
  const [row] = await tx.$queryRaw<
    {
      archivedAt: Date | null;
      communitySource: string | null;
      communityRefresh: boolean;
    }[]
  >`SELECT "archivedAt", "communitySource", "communityRefresh" FROM sandbox_logical_template
    WHERE id = ${input.templateId} AND "userId" = ${input.ownerId} FOR UPDATE`;
  const entry = row?.communitySource ? communityImage(row.communitySource) : null;
  if (!row || !entry || row.archivedAt) return { kind: "skipped", reason: "archived" };
  if (!input.bypassAge && !row.communityRefresh) return { kind: "skipped", reason: "refresh_off" };
  const owner = await tx.user.findUnique({
    where: { id: input.ownerId },
    select: { deletionRequestedAt: true, banned: true, banExpires: true },
  });
  if (
    !owner ||
    owner.deletionRequestedAt ||
    (owner.banned === true && (!owner.banExpires || owner.banExpires > input.now))
  )
    return { kind: "skipped", reason: "owner_inactive" };
  const config = templateBuildsConfig();
  if (!config.enabled || imageDistributionMode() === "off")
    return { kind: "skipped", reason: "builds_disabled" };
  const timeoutMinutes = communityTimeoutMinutes(entry);
  if (
    timeoutMinutes > config.maxMinutes ||
    (timeoutMinutes + config.captureWindowMinutes + TEMPLATE_BUILD_LEASE_SLACK_MINUTES) * 60_000 >
      config.leaseCeilingMs
  )
    return { kind: "skipped", reason: "timeout_misfit" };
  const latest = await tx.sandboxTemplateTag.findFirst({
    where: { userId: input.ownerId, templateId: input.templateId, tag: "latest" },
    select: { revisionId: true },
  });
  if (!latest) return { kind: "skipped", reason: "no_latest" };
  const active = await activeCommunityBuild(tx, input.ownerId, input.templateId);
  if (active) return { kind: "active", buildId: active.id };
  // Unchanged upstream: the latest revision was built from this exact pin.
  const built = await tx.sandboxTemplateRevision.findFirst({
    where: { id: latest.revisionId, userId: input.ownerId },
    select: { buildId: true },
  });
  const source = built?.buildId
    ? await tx.sandboxTemplateBuild.findFirst({
        where: { id: built.buildId, userId: input.ownerId },
        select: { baseFingerprint: true },
      })
    : null;
  if (!input.rebuild && source?.baseFingerprint === input.pin.fingerprint)
    return { kind: "skipped", reason: "unchanged" };
  if (!input.bypassAge) {
    const success = await tx.sandboxTemplateBuild.findFirst({
      where: {
        userId: input.ownerId,
        templateId: input.templateId,
        origin: "COMMUNITY_PREP",
        state: "SUCCEEDED",
      },
      orderBy: { completedAt: "desc" },
      select: { completedAt: true },
    });
    if (
      success?.completedAt &&
      input.now.getTime() - success.completedAt.getTime() < COMMUNITY_REFRESH_MIN_AGE_MS
    )
      return { kind: "skipped", reason: "too_recent" };
  }
  const target = await lastTarget(tx, input.ownerId, input.templateId);
  if (!target) return { kind: "skipped", reason: "no_target" };
  const base = await upsertUpstreamRevision(tx, input.ownerId, input.templateId, entry, input.pin);
  // Older pins that no active build uses retire as `superseded`.
  await tx.sandboxTemplateRevision.updateMany({
    where: {
      userId: input.ownerId,
      templateId: input.templateId,
      sourceKind: "UPSTREAM",
      retiredAt: null,
      id: { not: base.id },
    },
    data: { retiredAt: input.now, retiredReason: "superseded" },
  });
  try {
    const build = await insertCommunityBuild(tx, {
      ownerId: input.ownerId,
      templateId: input.templateId,
      entry,
      base,
      target,
      accepting: {
        principalKind: "system",
        authorizingKeyId: null,
        principalKey: "sys",
        triggeredByRevisionId: latest.revisionId,
      },
      idempotencyKey: `tb:community:${input.templateId}:${randomUUID()}`,
      requestBodyHash: await sha256Hex(
        canonicalJson({ kind: "refresh", templateId: input.templateId, base: base.id }),
      ),
      timeoutMinutes,
      now: input.now,
      config,
    });
    return { kind: "started", buildId: build.id };
  } catch (error) {
    if (error instanceof ORPCError && error.code === "CONFLICT")
      return { kind: "skipped", reason: "quota" };
    throw error;
  }
}

/**
 * "Refresh now" (S12): with a `latest`, a system refresh that bypasses the
 * age check; without one, the same as "Try again" (D-F, user principal).
 */
export async function refreshCommunityTemplate(
  principal: Principal,
  input: { templateId: string; idempotencyKey: string },
  now: Date = new Date(),
  index: CommunityIndexClient = communityIndexClient(),
): Promise<CommunityTemplateResult | RefreshOutcome> {
  const probe = await prisma.sandboxTemplate.findFirst({
    where: { AND: [serviceResourceFilter(principal, "template"), { id: input.templateId }] },
    select: {
      communitySource: true,
      Tags: { where: { tag: "latest" }, select: { revisionId: true }, take: 1 },
    },
  });
  if (!probe) throw templateNotFound();
  const entry = probe.communitySource ? communityImage(probe.communitySource) : null;
  if (!entry) throw communityManaged();
  if (probe.Tags.length === 0) return retryCommunityTemplate(principal, input, now, index);
  preflight(principal, entry);
  const pin = await readPin(entry, index);
  const outcome = await prisma.$transaction(async (tx) => {
    await lockOwnerForAdmission(tx, principal.ownerId);
    await authorizeServiceIntent(principal, "templates.build", tx);
    await lockOwnerPlacement(tx, principal.ownerId);
    await lockCommunityTemplate(tx, principal, input.templateId);
    return refreshCommunityTemplateLocked(tx, {
      ownerId: principal.ownerId,
      templateId: input.templateId,
      pin,
      bypassAge: true,
      now,
    });
  });
  if (outcome.kind === "started") notifyTemplateBuildsChanged();
  return outcome;
}

/** The per-template refresh switch (default on). */
export async function setCommunityRefresh(
  principal: Principal,
  input: { templateId: string; refresh: boolean },
): Promise<{ ok: true }> {
  await prisma.$transaction(async (tx) => {
    await lockOwnerForAdmission(tx, principal.ownerId);
    await authorizeServiceIntent(principal, "templates.build", tx);
    await lockCommunityTemplate(tx, principal, input.templateId);
    await tx.sandboxTemplate.update({
      where: { id: input.templateId },
      data: { communityRefresh: input.refresh },
    });
  });
  return { ok: true };
}

/** Templates refreshed per scan page (I8). */
const REFRESH_PAGE = 32;

/**
 * The daily refresh scan (S10): every live community template, paged by
 * cursor, `take: 32`. One index read per catalog entry per scan (outside any
 * transaction); each template is refreshed in its own short transaction.
 * Server-only: a new upstream revision's private defaults row is MACed with
 * the server's request secret (`refresh-schedule.ts` runs it). `shouldStop`
 * is checked between templates; a stopped scan reports `stopped: true`.
 */
export async function runCommunityRefreshScan(
  now: Date = new Date(),
  index: CommunityIndexClient = communityIndexClient(),
  shouldStop: () => boolean = () => false,
): Promise<{ started: number; skipped: number; stopped: boolean }> {
  // Builds or image distribution off: no index read and nothing to accept.
  if (communityDisabledReason() !== null) return { started: 0, skipped: 0, stopped: false };
  const pins = new Map<string, UpstreamPin | null>();
  let started = 0;
  let skipped = 0;
  let stopped = false;
  let cursor: string | null = null;
  scan: for (;;) {
    const page: { id: string; userId: string; communitySource: string | null }[] =
      await prisma.sandboxTemplate.findMany({
        where: {
          communitySource: { not: null },
          communityRefresh: true,
          archivedAt: null,
          ...(cursor ? { id: { gt: cursor } } : {}),
        },
        select: { id: true, userId: true, communitySource: true },
        orderBy: { id: "asc" },
        take: REFRESH_PAGE,
      });
    for (const template of page) {
      if (shouldStop()) {
        stopped = true;
        break scan;
      }
      const entry = template.communitySource ? communityImage(template.communitySource) : null;
      if (!entry) continue;
      if (!pins.has(entry.id)) pins.set(entry.id, await index.newest(entry).catch(() => null));
      const pin = pins.get(entry.id);
      if (!pin) {
        skipped++;
        continue;
      }
      try {
        const outcome = await prisma.$transaction(async (tx) => {
          await lockOwnerForAdmission(tx, template.userId);
          await lockOwnerPlacement(tx, template.userId);
          return refreshCommunityTemplateLocked(tx, {
            ownerId: template.userId,
            templateId: template.id,
            pin,
            bypassAge: false,
            now,
          });
        });
        if (outcome.kind === "started") started++;
        else skipped++;
      } catch (error) {
        skipped++;
        console.warn(
          "[community] Refresh of a template failed; the next scan retries:",
          error instanceof Error ? error.name : "error",
        );
      }
    }
    if (page.length < REFRESH_PAGE) break;
    cursor = page.at(-1)?.id ?? null;
  }
  if (started > 0) notifyTemplateBuildsChanged();
  return { started, skipped, stopped };
}

/**
 * Refresh-on-miss (D-H, S10 `rebuild.ts` community branch): the latest
 * revision's image is gone everywhere. Under the caller's locks, a system
 * prep build from the template's newest recorded pin (no index read under
 * locks; a pin gone upstream fails `build_upstream_unavailable` and the next
 * daily scan re-pins).
 */
export async function communityRefreshOnMissLocked(
  tx: Prisma.TransactionClient,
  ownerId: string,
  templateId: string,
  now: Date,
): Promise<RefreshOutcome> {
  const image = await tx.sandboxUpstreamImage.findFirst({
    where: { userId: ownerId, templateId },
    orderBy: { createdAt: "desc" },
  });
  if (!image) return { kind: "skipped", reason: "no_target" };
  return refreshCommunityTemplateLocked(tx, {
    ownerId,
    templateId,
    pin: {
      product: image.product,
      version: image.version,
      fingerprint: image.fingerprint,
      architecture: image.architecture,
      metaPath: image.metaPath,
      metaSha256: image.metaSha256,
      metaSize: Number(image.metaSize),
      diskPath: image.diskPath,
      diskSha256: image.diskSha256,
      diskSize: Number(image.diskSize),
    },
    bypassAge: true,
    rebuild: true,
    now,
  });
}

/**
 * The first-create window (S10): a create of a visible community template
 * whose first prep build is still running maps `template_not_found` to
 * `rebuilding`, but only after re-proving the caller can see the template
 * (an ALLOWLIST key keeps `not_found`).
 */
export async function communityFirstCreateBuildLocked(
  tx: Prisma.TransactionClient,
  principal: Principal,
  selector: string,
): Promise<string | null> {
  const name = selector.split(":")[0] ?? "";
  if (!name || selector.includes("/")) return null;
  const template = await tx.sandboxTemplate.findFirst({
    where: {
      AND: [
        serviceResourceFilter(principal, "template"),
        { OR: [{ id: name }, { slug: name }], archivedAt: null, communitySource: { not: null } },
      ],
    },
    select: { id: true },
  });
  if (!template) return null;
  const active = await activeCommunityBuild(tx, principal.ownerId, template.id);
  return active?.id ?? null;
}
