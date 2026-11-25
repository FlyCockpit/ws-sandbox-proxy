import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { validScrubPath } from "@wssp/sandbox-contracts";
import { z } from "zod";
import { cursorPage, cursorPageInput, pageTake, withCursor } from "../../lib/pagination";
import { entityId } from "../../lib/schemas";
import { serviceProcedure } from "../../lib/sdk-key-access";
import { consumeSandboxWriteBudget } from "../budgets";
import type { Principal } from "../contracts";
import { lockOwnerPlacement } from "../direct-placement";
import { templateNotFound } from "../errors";
import { launchableRevisionWhere } from "../template-resolution";
import {
  accountImageQuotas,
  accountStoredImageBytes,
  hostImageFeatures,
  imageDistributionMode,
  wakeImageScheduler,
} from "./config";

/**
 * Session-only image settings (dashboard): template placement and retention,
 * publish-now and prune-now, the account default and quotas, a host's cache.
 * Every write is owner-scoped and charged to the "image" budget family.
 */

export const updateImageSettingsInput = z
  .object({
    templateId: entityId,
    imagePlacement: z.enum(["INHERIT", "ANY_NODE", "OWNED_NODES_ONLY"]).optional(),
    captureKeep: z.number().int().min(1).max(50).optional(),
    pruneAfterDays: z.number().int().min(1).max(3650).nullable().optional(),
    captureScrubPaths: z
      .array(z.string().min(1).max(4096))
      .max(64)
      .refine((paths) => paths.every(validScrubPath), { message: "invalid scrub path" })
      .optional(),
  })
  .strict();
export const publishRevisionInput = z.object({ revisionId: entityId }).strict();
export const pruneNowInput = z.object({ templateId: entityId }).strict();
export const setImagePolicyInput = z
  .object({
    imagePlacement: z.enum(["ANY_NODE", "OWNED_NODES_ONLY"]).optional(),
    /** Owner consent to run this account's builds on other owners' builder nodes. */
    allowForeignBuilds: z.boolean().optional(),
    /** Turning foreign builds on requires acknowledging the warning. */
    acknowledgeForeignBuilds: z.literal(true).optional(),
  })
  .strict()
  .refine(
    (input) => input.imagePlacement !== undefined || input.allowForeignBuilds !== undefined,
    "Nothing to change.",
  )
  .refine(
    (input) => input.allowForeignBuilds !== true || input.acknowledgeForeignBuilds === true,
    "Acknowledge the foreign builds warning to turn them on.",
  );
export const hostImageCacheInput = cursorPageInput.extend({ hostId: entityId }).strict();

const templateImageSettingsSelect = {
  id: true,
  imagePlacement: true,
  captureKeep: true,
  pruneAfterDays: true,
  captureScrubPaths: true,
} satisfies Prisma.SandboxTemplateSelect;

async function lockTemplate(tx: Prisma.TransactionClient, ownerId: string, templateId: string) {
  const [row] = await tx.$queryRaw<{ id: string; archivedAt: Date | null }[]>`
    SELECT id, "archivedAt" FROM sandbox_logical_template
    WHERE id = ${templateId} AND "userId" = ${ownerId} FOR UPDATE`;
  if (!row || row.archivedAt) throw templateNotFound();
}

export const getTemplateImageSettings = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: z.infer<typeof pruneNowInput>) => {
    const row = await prisma.sandboxTemplate.findFirst({
      where: { id: input.templateId, userId: owner.ownerId },
      select: templateImageSettingsSelect,
    });
    if (!row) throw templateNotFound();
    return { ...row, mode: imageDistributionMode() };
  },
);

export const updateTemplateImageSettings = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: z.infer<typeof updateImageSettingsInput>) => {
    await consumeSandboxWriteBudget(owner.ownerId, "image");
    const updated = await prisma.$transaction(async (tx) => {
      await lockOwnerForAdmission(tx, owner.ownerId);
      // Placement is a placement input: serialize with owner placement (lock order).
      await lockOwnerPlacement(tx, owner.ownerId);
      await lockTemplate(tx, owner.ownerId, input.templateId);
      return tx.sandboxTemplate.update({
        where: { id: input.templateId, userId: owner.ownerId },
        data: {
          imagePlacement: input.imagePlacement,
          captureKeep: input.captureKeep,
          pruneAfterDays: input.pruneAfterDays,
          captureScrubPaths: input.captureScrubPaths,
        },
        select: templateImageSettingsSelect,
      });
    });
    // A tightened placement releases foreign copies on the next sweep (P2-5).
    wakeImageScheduler();
    return updated;
  },
);

export type PublishRevisionStatus = "stored" | "in_progress" | "queued" | "no_source";

/**
 * Publish to the image store now (S3 mode): the scheduler's backfill uploads
 * every live revision lacking a STORED artifact; this checks the revision and
 * wakes it rather than issuing a second, competing publish. A revision of an
 * archived template is not live (the backfill never uploads it): not found.
 */
export const publishTemplateRevision = serviceProcedure(
  { sessionOnly: true },
  async (
    owner: Principal,
    input: z.infer<typeof publishRevisionInput>,
  ): Promise<{ status: PublishRevisionStatus }> => {
    await consumeSandboxWriteBudget(owner.ownerId, "image");
    const revision = await prisma.sandboxTemplateRevision.findFirst({
      where: {
        id: input.revisionId,
        userId: owner.ownerId,
        retiredAt: null,
        Template: { archivedAt: null },
        ...launchableRevisionWhere(),
      },
      select: { incusFingerprint: true },
    });
    if (!revision) throw templateNotFound();
    if (imageDistributionMode() !== "s3")
      throw new ORPCError("PRECONDITION_FAILED", {
        data: { code: "sandbox.template_store_unavailable" },
      });
    const artifact = await prisma.sandboxImageArtifact.findUnique({
      where: {
        userId_fingerprint: { userId: owner.ownerId, fingerprint: revision.incusFingerprint },
      },
      select: { state: true },
    });
    if (artifact?.state === "STORED") return { status: "stored" };
    if (artifact && (artifact.state === "UPLOADING" || artifact.state === "VERIFYING"))
      return { status: "in_progress" };
    const source = await prisma.sandboxTemplateAvailability.findFirst({
      where: {
        revisionId: input.revisionId,
        userId: owner.ownerId,
        status: "AVAILABLE",
        hostOwnerId: owner.ownerId,
        Host: { is: { status: "CONNECTED" } },
      },
      select: {
        verifiedConnectionEpoch: true,
        Host: { select: { connectionEpoch: true, daemonFeatures: true } },
      },
    });
    if (
      !source?.Host ||
      source.verifiedConnectionEpoch !== source.Host.connectionEpoch ||
      !hostImageFeatures(source.Host.daemonFeatures)?.publish
    )
      return { status: "no_source" };
    wakeImageScheduler();
    return { status: "queued" };
  },
);

/**
 * Prune now: the daily auto-prune for one template, run at once and with no
 * age threshold. Untagged revisions outside the newest `captureKeep` of their
 * capture tag retire (`manual`); a revision any live sandbox uses never does.
 * At most 100 per call.
 */
export const pruneTemplateNow = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: z.infer<typeof pruneNowInput>) => {
    await consumeSandboxWriteBudget(owner.ownerId, "image");
    return prisma.$transaction(async (tx) => {
      await lockOwnerForAdmission(tx, owner.ownerId);
      await lockOwnerPlacement(tx, owner.ownerId);
      await lockTemplate(tx, owner.ownerId, input.templateId);
      const template = await tx.sandboxTemplate.findFirstOrThrow({
        where: { id: input.templateId, userId: owner.ownerId },
        select: { captureKeep: true },
      });
      const retired = await tx.$executeRaw`
        UPDATE sandbox_template_revision r SET "retiredAt" = (clock_timestamp() AT TIME ZONE 'UTC'), "retiredReason" = 'manual'
        WHERE r.id IN (
          SELECT c.id FROM sandbox_template_revision c
          WHERE c."templateId" = ${input.templateId} AND c."userId" = ${owner.ownerId}
            AND c."retiredAt" IS NULL
            -- Never a revision pending its verify VM, nor an active build's base (community-base I1).
            AND c."pendingVerifyBuildId" IS NULL
            AND NOT EXISTS (SELECT 1 FROM sandbox_template_build b
              WHERE b."baseRevisionId" = c.id AND b."userId" = c."userId"
                AND b.state::text IN ('AWAITING_CONTEXT', 'QUEUED', 'PLACING', 'RUNNING', 'STOPPING', 'CAPTURING', 'CANCELLING'))
            AND NOT EXISTS (SELECT 1 FROM sandbox_template_tag g WHERE g."revisionId" = c.id)
            AND NOT EXISTS (SELECT 1 FROM sandbox_instance s
              WHERE s."templateRevisionId" = c.id AND s.state <> 'DELETED')
            AND c.id NOT IN (SELECT k.id FROM sandbox_template_revision k
              WHERE k."templateId" = c."templateId" AND k."retiredAt" IS NULL
                AND k."captureTag" IS NOT DISTINCT FROM c."captureTag"
              ORDER BY k.revision DESC LIMIT ${template.captureKeep})
          ORDER BY c.revision ASC LIMIT 100)`;
      return { retired };
    });
  },
);

/** The account's default placement, quotas and current usage. */
export const getAccountImagePolicy = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, _input: undefined) => {
    const policy = await prisma.accountImagePolicy.findUnique({
      where: { userId: owner.ownerId },
      select: { imagePlacement: true, allowForeignBuilds: true },
    });
    const quotas = await accountImageQuotas(prisma, owner.ownerId);
    const storedBytes = await accountStoredImageBytes(prisma, owner.ownerId);
    const downloadsLastHour = await prisma.sandboxImageTransfer.count({
      where: {
        userId: owner.ownerId,
        countedDownload: true,
        createdAt: { gt: new Date(Date.now() - 3_600_000) },
      },
    });
    return {
      mode: imageDistributionMode(),
      imagePlacement: policy?.imagePlacement ?? ("ANY_NODE" as const),
      allowForeignBuilds: policy?.allowForeignBuilds ?? false,
      quotas,
      usage: { storedBytes: storedBytes.toString(), downloadsLastHour },
    };
  },
);

export const setAccountImagePolicy = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: z.infer<typeof setImagePolicyInput>) => {
    await consumeSandboxWriteBudget(owner.ownerId, "image");
    const updated = await prisma.$transaction(async (tx) => {
      await lockOwnerForAdmission(tx, owner.ownerId);
      await lockOwnerPlacement(tx, owner.ownerId);
      const data = {
        ...(input.imagePlacement !== undefined ? { imagePlacement: input.imagePlacement } : {}),
        ...(input.allowForeignBuilds !== undefined
          ? { allowForeignBuilds: input.allowForeignBuilds }
          : {}),
      };
      const row = await tx.accountImagePolicy.upsert({
        where: { userId: owner.ownerId },
        create: { userId: owner.ownerId, ...data },
        update: data,
        select: { imagePlacement: true, allowForeignBuilds: true },
      });
      return row;
    });
    wakeImageScheduler();
    return updated;
  },
);

/**
 * A host's managed image cache, for its owner only. The owner's own entries
 * are listed (paged); images of other accounts are one aggregate byte count.
 */
export const listHostImageCache = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: z.infer<typeof hostImageCacheInput>) => {
    const host = await prisma.sandboxHost.findFirst({
      where: { id: input.hostId, userId: owner.ownerId },
      select: {
        connectionEpoch: true,
        daemonFeatures: true,
        imageCacheCapBytes: true,
        imageCacheUsedBytes: true,
        imageCacheForeignBytes: true,
        imageCacheEpoch: true,
      },
    });
    if (!host) throw new ORPCError("NOT_FOUND");
    const rows = await prisma.sandboxHostImageCache.findMany({
      where: withCursor(
        { hostId: input.hostId, hostOwnerId: owner.ownerId, imageOwnerId: owner.ownerId },
        "reportedAt",
        input.cursor,
        "desc",
      ),
      orderBy: [{ reportedAt: "desc" }, { id: "desc" }],
      take: pageTake(input.limit),
      select: {
        id: true,
        fingerprint: true,
        compressedBytes: true,
        unpackedBytes: true,
        origin: true,
        pinned: true,
        reportedAt: true,
      },
    });
    const page = cursorPage(rows, input.limit, "reportedAt");
    // `slug vN` for each listed image: the owner's newest revision with that
    // fingerprint. One `LIMIT 1` read per distinct fingerprint on this
    // already-bounded page (Prisma's `distinct` filters in memory after an
    // unbounded SELECT, so a long-reused fingerprint would load its history).
    const fingerprints = [...new Set(page.items.map((row) => row.fingerprint))];
    const revisions = (
      await Promise.all(
        fingerprints.map((fingerprint) =>
          prisma.sandboxTemplateRevision.findFirst({
            where: { userId: owner.ownerId, incusFingerprint: fingerprint },
            orderBy: [{ createdAt: "desc" }, { id: "desc" }],
            select: {
              incusFingerprint: true,
              revision: true,
              Template: { select: { slug: true } },
            } satisfies Prisma.SandboxTemplateRevisionSelect,
          }),
        ),
      )
    ).flatMap((row) => (row ? [row] : []));
    const byFingerprint = new Map(
      revisions.map((row) => [
        row.incusFingerprint,
        { slug: row.Template.slug, revision: row.revision },
      ]),
    );
    const features = hostImageFeatures(host.daemonFeatures);
    const bytes = (value: bigint | null) => (value === null ? null : value.toString());
    return {
      summary: {
        enabled: host.imageCacheCapBytes !== null,
        current: host.imageCacheEpoch !== null && host.imageCacheEpoch === host.connectionEpoch,
        capBytes: bytes(host.imageCacheCapBytes),
        usedBytes: bytes(host.imageCacheUsedBytes),
        foreignBytes: bytes(host.imageCacheForeignBytes),
        acceptForeign: features?.acceptForeign ?? false,
        builder: features?.build ?? false,
        acceptForeignBuilds: features?.acceptForeignBuilds ?? false,
      },
      items: page.items.map((row) => ({
        ...row,
        compressedBytes: row.compressedBytes.toString(),
        unpackedBytes: bytes(row.unpackedBytes),
        revision: byFingerprint.get(row.fingerprint) ?? null,
      })),
      nextCursor: page.nextCursor,
    };
  },
);
