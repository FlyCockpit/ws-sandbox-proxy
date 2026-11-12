import { createHash } from "node:crypto";
import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { z } from "zod";
import { cursorPage, pageTake, withCursor } from "../../lib/pagination";
import { isPrismaUniqueViolation } from "../../lib/prisma-errors";
import {
  authorizeServiceAction,
  serviceAdmissionError,
  serviceProcedure,
  serviceResourceFilter,
} from "../../lib/sdk-key-access";
import { refuseCommunityWrite } from "../../template-builds/community/managed";
import { consumeSandboxWriteBudget } from "../budgets";
import type { Principal, SandboxIdInput } from "../contracts";
import { lockOwnerPlacement } from "../direct-placement";
import {
  hostDrainingConflict,
  hostNotFound,
  hostUnavailable,
  poolNotFound,
  templateImageMissing,
  templateImageRejected,
  templateNotFound,
  templateRevisionExists,
} from "../errors";
import { executionEnvPairs } from "../execution-config";
import { normalizeGuestIdentity } from "../guest-identity";
import { lockAdmissionHost, lockWorkAdmissionHost } from "../host-admission";
import {
  HostImageMissing,
  HostImageRejected,
  verifyHostImageRegistration,
} from "../host-image-verifier";
import { isIncusImageRef, normalizeIncusFingerprint } from "../incus-image";
import { lockPoolGraph } from "../pool-locks";
import { hostDatabaseNow } from "../relay-fence";
import { writeRevisionDefaults } from "../revision-config";
import { lockSharingPrincipals, requirePoolUse } from "../sharing-authority";
import {
  type AppendRevisionInput,
  associateAvailabilityInput,
  type CreateTemplateInput,
  type ListTemplatesInput,
  listAvailabilityInput,
  listRevisionsInput,
  setTemplateTagInput,
  type TemplateIdInput,
} from "../template-input";
import {
  type ImageTargetInput,
  launchableRevisionWhere,
  resolveTemplateImageTarget,
  revisionPublicSelect,
  visibleLogicalTemplate,
} from "../template-resolution";
import { revisionVmSize } from "../vm-size-input";

const templateSelect = {
  id: true,
  slug: true,
  label: true,
  archivedAt: true,
  createdAt: true,
  updatedAt: true,
  imagePlacement: true,
  captureKeep: true,
  pruneAfterDays: true,
  communitySource: true,
  communityRefresh: true,
} satisfies Prisma.SandboxTemplateSelect;

export const listTemplates = serviceProcedure(
  { action: "templates.list" },
  async (owner: Principal, input: ListTemplatesInput) => {
    const rows = await prisma.sandboxTemplate.findMany({
      where: withCursor(
        {
          ...serviceResourceFilter(owner, "template"),
          ...(input.status === "active"
            ? { archivedAt: null }
            : input.status === "retired"
              ? { archivedAt: { not: null } }
              : {}),
        },
        "createdAt",
        input.cursor,
        "desc",
      ),
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: pageTake(input.limit),
      select: templateSelect,
    });
    return cursorPage(rows, input.limit, "createdAt");
  },
);
export const getTemplate = serviceProcedure(
  {
    action: "templates.list",
    target: (input: TemplateIdInput) => ({ logicalTemplateId: input.id }),
  },
  async (owner, input) => visibleLogicalTemplate(prisma, owner, input.id),
);

type ImageTarget = Awaited<ReturnType<typeof resolveTemplateImageTarget>>;
const pendingImageChecks = new Map<string, number>();
async function withImageCheck<T>(creatorId: string, hostId: string, work: () => Promise<T>) {
  const keys = [`creator:${creatorId}`, `host:${hostId}`];
  if ((pendingImageChecks.get(keys[0]!) ?? 0) >= 4 || (pendingImageChecks.get(keys[1]!) ?? 0) >= 8)
    throw hostUnavailable("Image verifier is busy.");
  for (const key of keys) pendingImageChecks.set(key, (pendingImageChecks.get(key) ?? 0) + 1);
  try {
    return await work();
  } finally {
    for (const key of keys) {
      const count = (pendingImageChecks.get(key) ?? 1) - 1;
      if (count) pendingImageChecks.set(key, count);
      else pendingImageChecks.delete(key);
    }
  }
}
async function lockImageTarget(
  tx: Prisma.TransactionClient,
  owner: Principal,
  input: ImageTargetInput,
  target: ImageTarget,
  epoch: number,
  action: "templates.create" | "templates.append" | "templates.associate",
  context: { logicalTemplateId?: string; templateRevisionId?: string } = {},
) {
  await lockSharingPrincipals(tx, [owner.ownerId, target.poolOwnerId, target.hostOwnerId]);
  await authorizeServiceAction(
    owner,
    action,
    { ...context, sandboxHostId: target.hostId, originPoolId: target.poolId },
    tx,
  );
  await lockOwnerPlacement(tx, owner.ownerId);
  if (target.poolId) await lockPoolGraph(tx, [target.poolId]);
  const current = await resolveTemplateImageTarget(tx, owner, input);
  if (JSON.stringify(current) !== JSON.stringify(target))
    throw hostUnavailable("Image verification target changed.");
  await lockVerifiedHost(tx, target, epoch);
}

async function verify(
  owner: Principal,
  input: { hostId: string; imageRef: string; architecture: string },
  allowMissing = false,
  hostOwnerId = owner.ownerId,
) {
  const host = await prisma.sandboxHost.findFirst({
    where: { id: input.hostId, userId: hostOwnerId },
    select: { connectionEpoch: true, status: true, draining: true },
  });
  if (!host) throw hostNotFound();
  if (host.draining) throw hostDrainingConflict();
  if (host.status !== "CONNECTED") throw hostUnavailable("Host is unavailable.");
  try {
    const image = await withImageCheck(owner.ownerId, input.hostId, () =>
      verifyHostImageRegistration({
        ownerId: hostOwnerId,
        hostId: input.hostId,
        imageRef: input.imageRef,
        expectedArchitecture: input.architecture,
      }),
    );
    const fingerprint = normalizeIncusFingerprint(image.incusFingerprint);
    if (image.architecture !== input.architecture)
      throw templateImageRejected("Image does not match the revision.");
    return {
      fingerprint,
      epoch: host.connectionEpoch,
      missing: false,
      hostId: input.hostId,
      hostOwnerId,
      imageFacts: {
        ...(image.sizeBytes ? { sizeBytes: BigInt(image.sizeBytes) } : {}),
        ...(image.format ? { imageFormat: image.format } : {}),
      },
    };
  } catch (error) {
    if (error instanceof HostImageMissing) {
      if (allowMissing)
        return {
          fingerprint: input.imageRef,
          epoch: host.connectionEpoch,
          missing: true,
          hostId: input.hostId,
          hostOwnerId,
        };
      throw templateImageMissing();
    }
    if (error instanceof HostImageRejected)
      throw templateImageRejected("Image does not match the revision.");
    if (error instanceof ORPCError) throw error;
    throw hostUnavailable("Host could not verify the image.");
  }
}

async function append(
  tx: Prisma.TransactionClient,
  owner: Principal,
  templateId: string,
  input: CreateTemplateInput | AppendRevisionInput,
  verified: Awaited<ReturnType<typeof verify>>,
) {
  await refuseCommunityWrite(tx, owner.ownerId, templateId);
  const guest = normalizeGuestIdentity(input);
  const size = revisionVmSize(input);
  await tx.$queryRaw`SELECT id FROM sandbox_template_tag WHERE "templateId" = ${templateId} AND "userId" = ${owner.ownerId} ORDER BY id FOR UPDATE`;
  const last = await tx.sandboxTemplateRevision.findFirst({
    where: { templateId, userId: owner.ownerId },
    orderBy: { revision: "desc" },
    select: { revision: true },
  });
  const manifest = {
    incusFingerprint: verified.fingerprint,
    architecture: input.architecture,
    ...guest,
    guestVersion: input.guestVersion ?? null,
  };
  const revision = await tx.sandboxTemplateRevision.create({
    data: {
      userId: owner.ownerId,
      templateId,
      revision: (last?.revision ?? 0) + 1,
      ...manifest,
      ...size,
      manifestDigest: createHash("sha256").update(JSON.stringify(manifest)).digest("hex"),
    },
    select: revisionPublicSelect,
  });
  await writeRevisionDefaults(tx, owner.ownerId, revision.id, input.envs ?? {});
  await tx.sandboxTemplateAvailability.create({
    data: {
      userId: owner.ownerId,
      revisionId: revision.id,
      hostOwnerId: verified.hostOwnerId,
      hostId: verified.hostId,
      localFingerprint: revision.incusFingerprint,
      architecture: revision.architecture,
      manifestDigest: revision.manifestDigest,
      status: "AVAILABLE",
      verifiedConnectionEpoch: verified.epoch,
      observedAt: await hostDatabaseNow(tx),
      ...("imageFacts" in verified ? verified.imageFacts : {}),
    },
  });
  await tx.sandboxTemplateTag.upsert({
    where: { templateId_tag: { templateId, tag: "latest" } },
    create: { userId: owner.ownerId, templateId, revisionId: revision.id, tag: "latest" },
    update: { revisionId: revision.id },
  });
  return revision;
}

async function lockVerifiedHost(tx: Prisma.TransactionClient, target: ImageTarget, epoch: number) {
  // User/K/creator-placement/G are already held by lockImageTarget.
  // Never acquire a transport owner's placement advisory from this suffix.
  const { hostId, hostOwnerId } = target;
  await lockAdmissionHost(tx, hostId, hostOwnerId);
  await lockWorkAdmissionHost(tx, hostId, hostOwnerId);
  const host = await tx.sandboxHost.findFirst({
    where: { id: hostId, userId: hostOwnerId, connectionEpoch: epoch, status: "CONNECTED" },
    select: { id: true },
  });
  if (!host) throw hostUnavailable("Host changed during image verification.");
}

export const createTemplate = serviceProcedure(
  {
    action: "templates.create",
    intentOnly: true,
    target: (input: CreateTemplateInput) => ({ sandboxHostId: input.hostId }),
  },
  async (owner, input) => {
    revisionVmSize(input);
    executionEnvPairs(input.envs ?? {});
    const collision = await prisma.sandboxTemplate.findFirst({
      where: { userId: owner.ownerId, slug: input.slug },
      select: { id: true },
    });
    if (collision) {
      await visibleLogicalTemplate(prisma, owner, collision.id);
      throw templateRevisionExists();
    }
    const target = await resolveTemplateImageTarget(prisma, owner, input);
    if (target.poolId && !/^sha256:[a-f0-9]{64}$/.test(input.imageRef))
      throw templateImageRejected("Pool verification requires an exact fingerprint.");
    if (!target.poolId && !isIncusImageRef(input.imageRef))
      throw templateImageRejected("Image alias is invalid.");
    await authorizeServiceAction(owner, "templates.create", {
      sandboxHostId: target.hostId,
      originPoolId: target.poolId,
    });
    const verified = await verify(
      owner,
      { ...input, hostId: target.hostId },
      false,
      target.hostOwnerId,
    );
    if (target.poolId && verified.fingerprint !== input.imageRef)
      throw templateImageRejected("Image does not match the requested fingerprint.");
    try {
      return await prisma.$transaction(async (tx) => {
        await lockImageTarget(tx, owner, input, target, verified.epoch, "templates.create");
        await authorizeServiceAction(
          owner,
          "templates.create",
          { sandboxHostId: target.hostId, originPoolId: target.poolId },
          tx,
        );
        const existing = await tx.sandboxTemplate.findFirst({
          where: { userId: owner.ownerId, slug: input.slug },
          select: { id: true },
        });
        if (existing) {
          await visibleLogicalTemplate(tx, owner, existing.id);
          throw templateRevisionExists();
        }
        const logical = await tx.sandboxTemplate.create({
          data: { userId: owner.ownerId, slug: input.slug, label: input.label },
          select: templateSelect,
        });
        const revision = await append(tx, owner, logical.id, input, verified);
        return { ...logical, firstRevisionId: revision.id };
      });
    } catch (error) {
      if (isPrismaUniqueViolation(error)) throw templateRevisionExists();
      throw serviceAdmissionError(error);
    }
  },
);

export const appendTemplateRevision = serviceProcedure(
  {
    action: "templates.append",
    intentOnly: true,
    target: (input: AppendRevisionInput) => ({
      sandboxHostId: input.hostId,
      logicalTemplateId: input.templateId,
    }),
  },
  async (owner, input) => {
    revisionVmSize(input);
    executionEnvPairs(input.envs ?? {});
    await visibleLogicalTemplate(prisma, owner, input.templateId);
    const target = await resolveTemplateImageTarget(prisma, owner, input);
    if (target.poolId && !/^sha256:[a-f0-9]{64}$/.test(input.imageRef))
      throw templateImageRejected("Pool verification requires an exact fingerprint.");
    if (!target.poolId && !isIncusImageRef(input.imageRef))
      throw templateImageRejected("Image alias is invalid.");
    await authorizeServiceAction(owner, "templates.append", {
      sandboxHostId: target.hostId,
      originPoolId: target.poolId,
    });
    const verified = await verify(
      owner,
      { ...input, hostId: target.hostId },
      false,
      target.hostOwnerId,
    );
    if (target.poolId && verified.fingerprint !== input.imageRef)
      throw templateImageRejected("Image does not match the requested fingerprint.");
    try {
      return await prisma.$transaction(async (tx) => {
        await lockImageTarget(tx, owner, input, target, verified.epoch, "templates.append", {
          logicalTemplateId: input.templateId,
        });
        await authorizeServiceAction(
          owner,
          "templates.append",
          {
            sandboxHostId: target.hostId,
            originPoolId: target.poolId,
            logicalTemplateId: input.templateId,
          },
          tx,
        );
        await tx.$queryRaw`SELECT id FROM sandbox_logical_template WHERE id = ${input.templateId} AND "userId" = ${owner.ownerId} FOR UPDATE`;
        const logical = await visibleLogicalTemplate(tx, owner, input.templateId);
        if (logical.archivedAt) throw templateNotFound();
        return append(tx, owner, logical.id, input, verified);
      });
    } catch (error) {
      throw serviceAdmissionError(error);
    }
  },
);

export const listTemplateRevisions = serviceProcedure(
  {
    action: "templates.revisions",
    target: (input: z.infer<typeof listRevisionsInput>) => ({
      logicalTemplateId: input.templateId,
    }),
  },
  async (owner, input) => {
    await visibleLogicalTemplate(prisma, owner, input.templateId);
    const rows = await prisma.sandboxTemplateRevision.findMany({
      where: withCursor(
        { ...serviceResourceFilter(owner, "revision"), templateId: input.templateId },
        "createdAt",
        input.cursor,
        "desc",
      ),
      // Build provenance for the dashboard badges; the /v1 DTO maps fields explicitly.
      select: { ...revisionPublicSelect, buildId: true, builtWithRoot: true },
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: pageTake(input.limit),
    });
    const page = cursorPage(rows, input.limit, "createdAt");
    return { ...page, items: await withRevisionImages(owner.ownerId, page.items) };
  },
);
/** The image-store state of each revision's image (one bounded lookup per page). */
async function withRevisionImages<T extends { incusFingerprint: string }>(
  ownerId: string,
  rows: T[],
) {
  const fingerprints = [...new Set(rows.map((row) => row.incusFingerprint))];
  // pagination:audited — `fingerprint in` one already-bounded page; unique per owner.
  const artifacts = fingerprints.length
    ? await prisma.sandboxImageArtifact.findMany({
        where: { userId: ownerId, fingerprint: { in: fingerprints } },
        select: { fingerprint: true, state: true, storeKind: true, sizeBytes: true },
      })
    : [];
  const byFingerprint = new Map(artifacts.map((a) => [a.fingerprint, a]));
  return rows.map((row) => {
    const artifact = byFingerprint.get(row.incusFingerprint);
    return {
      ...row,
      image: artifact
        ? {
            state: artifact.state,
            store: artifact.storeKind,
            sizeBytes: artifact.sizeBytes.toString(),
          }
        : null,
    };
  });
}

export const listTemplateAvailability = serviceProcedure(
  {
    action: "templates.availability",
    target: (input: z.infer<typeof listAvailabilityInput>) => ({
      logicalTemplateId: input.templateId,
      templateRevisionId: input.revisionId,
    }),
  },
  async (owner, input) => {
    const row = await prisma.sandboxTemplateRevision.findFirst({
      where: {
        ...serviceResourceFilter(owner, "revision"),
        id: input.revisionId,
        templateId: input.templateId,
      },
      select: { id: true },
    });
    if (!row) throw templateNotFound();
    const hosts = serviceResourceFilter(owner, "host");
    const rows = await prisma.sandboxTemplateAvailability.findMany({
      where: withCursor(
        // Owned hosts only: a fetched copy on another account's host is
        // placement evidence, never something its owner may see (no foreign host IDs).
        { userId: owner.ownerId, hostOwnerId: owner.ownerId, revisionId: row.id, Host: hosts },
        "createdAt",
        input.cursor,
        "desc",
      ),
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: pageTake(input.limit),
      select: {
        id: true,
        createdAt: true,
        revisionId: true,
        hostId: true,
        Host: { select: { id: true, label: true, slug: true } },
        status: true,
        verifiedConnectionEpoch: true,
        observedAt: true,
      },
    });
    return cursorPage(
      rows.map((row) => {
        if (!row.Host) throw hostNotFound();
        return { ...row, Host: row.Host };
      }),
      input.limit,
      "createdAt",
    );
  },
);
export const associateTemplateAvailability = serviceProcedure(
  {
    action: "templates.associate",
    intentOnly: true,
    target: (input: z.infer<typeof associateAvailabilityInput>) => ({
      logicalTemplateId: input.templateId,
      templateRevisionId: input.revisionId,
      sandboxHostId: input.hostId,
    }),
  },
  async (owner, input) => {
    const revision = await prisma.sandboxTemplateRevision.findFirst({
      where: {
        ...serviceResourceFilter(owner, "revision"),
        ...launchableRevisionWhere(),
        id: input.revisionId,
        templateId: input.templateId,
        retiredAt: null,
      },
      select: revisionPublicSelect,
    });
    if (!revision) throw templateNotFound();
    const target = await resolveTemplateImageTarget(prisma, owner, input);
    await authorizeServiceAction(owner, "templates.associate", {
      sandboxHostId: target.hostId,
      originPoolId: target.poolId,
      templateRevisionId: revision.id,
    });
    // A verification response can arrive after a newer same-epoch census.
    // Compare database clocks, never the web process's wall clock.
    const verificationStartedAt = await hostDatabaseNow(prisma);
    const verified = await verify(
      owner,
      {
        hostId: target.hostId,
        imageRef: revision.incusFingerprint,
        architecture: revision.architecture,
      },
      true,
      target.hostOwnerId,
    );
    if (verified.fingerprint !== revision.incusFingerprint)
      throw templateImageRejected("Image does not match the revision.");
    const association = await prisma.$transaction(async (tx) => {
      await lockImageTarget(tx, owner, input, target, verified.epoch, "templates.associate", {
        logicalTemplateId: input.templateId,
        templateRevisionId: revision.id,
      });
      await authorizeServiceAction(
        owner,
        "templates.associate",
        {
          logicalTemplateId: input.templateId,
          templateRevisionId: input.revisionId,
          sandboxHostId: target.hostId,
          originPoolId: target.poolId,
        },
        tx,
      );
      await tx.$queryRaw`SELECT id FROM sandbox_template_revision WHERE id = ${revision.id} AND "userId" = ${owner.ownerId} FOR SHARE`;
      const active = await tx.sandboxTemplateRevision.findFirst({
        where: { id: revision.id, userId: owner.ownerId, retiredAt: null },
        select: { id: true },
      });
      if (!active) throw templateNotFound();
      const current = await tx.sandboxTemplateAvailability.findUnique({
        where: { revisionId_hostId: { revisionId: revision.id, hostId: target.hostId } },
        select: { id: true, verifiedConnectionEpoch: true, observedAt: true },
      });
      // H serializes every availability writer. Keep a verdict received after
      // this verification began, including ties at timestamp precision.
      if (
        current?.verifiedConnectionEpoch === verified.epoch &&
        current.observedAt &&
        current.observedAt >= verificationStartedAt
      )
        return current;
      const observedAt = await hostDatabaseNow(tx);
      return tx.sandboxTemplateAvailability.upsert({
        where: { revisionId_hostId: { revisionId: revision.id, hostId: target.hostId } },
        create: {
          userId: owner.ownerId,
          revisionId: revision.id,
          hostOwnerId: target.hostOwnerId,
          hostId: target.hostId,
          localFingerprint: revision.incusFingerprint,
          architecture: revision.architecture,
          manifestDigest: revision.manifestDigest,
          status: verified.missing ? "MISSING" : "AVAILABLE",
          verifiedConnectionEpoch: verified.epoch,
          observedAt,
          ...("imageFacts" in verified ? verified.imageFacts : {}),
        },
        update: {
          status: verified.missing ? "MISSING" : "AVAILABLE",
          verifiedConnectionEpoch: verified.epoch,
          observedAt,
          ...("imageFacts" in verified ? verified.imageFacts : {}),
        },
        select: { id: true, verifiedConnectionEpoch: true },
      });
    });
    // Persist the observation before the action receipt records the refusal.
    if (verified.missing) throw templateImageMissing();
    return association;
  },
);
export const setTemplateTag = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: z.infer<typeof setTemplateTagInput>) => {
    await consumeSandboxWriteBudget(owner.ownerId, "tag");
    return prisma.$transaction(async (tx) => {
      await lockOwnerForAdmission(tx, owner.ownerId);
      await authorizeServiceAction(owner, "templates.list", {}, tx);
      await lockOwnerPlacement(tx, owner.ownerId);
      await tx.$queryRaw`SELECT id FROM sandbox_logical_template WHERE id = ${input.templateId} AND "userId" = ${owner.ownerId} FOR UPDATE`;
      await refuseCommunityWrite(tx, owner.ownerId, input.templateId);
      const revision = await tx.sandboxTemplateRevision.findFirst({
        where: {
          id: input.revisionId,
          templateId: input.templateId,
          userId: owner.ownerId,
          retiredAt: null,
          // No tag ever points at an UPSTREAM pin or a pending revision (I1t).
          ...launchableRevisionWhere(),
        },
        select: { id: true },
      });
      if (!revision) throw templateNotFound();
      await tx.sandboxTemplateTag.upsert({
        where: { templateId_tag: { templateId: input.templateId, tag: input.tag } },
        create: {
          userId: owner.ownerId,
          templateId: input.templateId,
          revisionId: input.revisionId,
          tag: input.tag,
        },
        update: { revisionId: input.revisionId },
      });
      return { ok: true as const };
    });
  },
);
export const retireTemplate = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: SandboxIdInput) => {
    await consumeSandboxWriteBudget(owner.ownerId, "tag");
    return prisma.$transaction(async (tx) => {
      await lockOwnerForAdmission(tx, owner.ownerId);
      await authorizeServiceAction(owner, "templates.list", {}, tx);
      await lockOwnerPlacement(tx, owner.ownerId);
      await tx.$queryRaw`SELECT id FROM sandbox_logical_template WHERE id = ${input.id} AND "userId" = ${owner.ownerId} FOR UPDATE`;
      await visibleLogicalTemplate(tx, owner, input.id);
      await tx.sandboxTemplate.update({
        where: { id: input.id, userId: owner.ownerId },
        data: { archivedAt: new Date() },
      });
      return { ok: true as const };
    });
  },
);

export const listRevisionChoices = serviceProcedure(
  { sessionOnly: true },
  async (
    owner: Principal,
    input: z.infer<typeof import("../template-input").revisionChoicesInput>,
  ) => {
    if (input.poolId) await requirePoolUse(prisma, owner, input.poolId);
    const association: Prisma.SandboxTemplateAvailabilityWhereInput = {
      userId: owner.ownerId,
      ...(input.poolId ? {} : { hostId: { in: input.hostIds } }),
      Host: {
        ...(input.poolId
          ? {
              deletionRequestedAt: null,
              User: {
                deletionRequestedAt: null,
                OR: [
                  { banned: { not: true } },
                  { banned: null },
                  { banExpires: { lte: new Date() } },
                ],
              },
            }
          : { userId: owner.ownerId }),
        ...(input.poolId
          ? {
              PoolMemberships: {
                some: {
                  poolId: input.poolId,
                  enabled: true,
                  removedAt: null,
                },
              },
            }
          : {}),
      },
      status: { in: input.includePending ? ["AVAILABLE", "PENDING"] : ["AVAILABLE"] },
    };
    const rows = await prisma.sandboxTemplateRevision.findMany({
      where: withCursor(
        {
          userId: owner.ownerId,
          retiredAt: null,
          ...launchableRevisionWhere(),
          Template: { archivedAt: null },
          Availability: { some: association },
        },
        "createdAt",
        input.cursor,
        "desc",
      ),
      take: pageTake(input.limit),
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      select: {
        ...revisionPublicSelect,
        Template: { select: { slug: true, label: true } },
        Availability: { where: association, take: 200, select: { hostId: true, status: true } },
      },
    });
    const page = cursorPage(rows, input.limit, "createdAt");
    if (input.poolId) {
      await requirePoolUse(prisma, owner, input.poolId);
      const current = await prisma.sandboxTemplateRevision.count({
        where: {
          id: { in: page.items.map((row) => row.id) },
          userId: owner.ownerId,
          retiredAt: null,
          Template: { archivedAt: null },
          Availability: { some: association },
        },
      });
      if (current !== page.items.length) throw poolNotFound();
    }
    return {
      items: page.items.map(({ Template, Availability, ...row }) => ({
        ...row,
        slug: Template.slug,
        label: `${Template.label} #${row.revision}`,
        availability: Availability,
      })),
      nextCursor: page.nextCursor,
    };
  },
);
export const getTemplateRevision = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: TemplateIdInput) => {
    const row = await prisma.sandboxTemplateRevision.findFirst({
      where: { id: input.id, userId: owner.ownerId },
      select: revisionPublicSelect,
    });
    if (!row) throw templateNotFound();
    return row;
  },
);
export const retireTemplateRevision = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: TemplateIdInput) => {
    await consumeSandboxWriteBudget(owner.ownerId, "tag");
    return prisma.$transaction(async (tx) => {
      await lockOwnerForAdmission(tx, owner.ownerId);
      await authorizeServiceAction(owner, "templates.list", {}, tx);
      await lockOwnerPlacement(tx, owner.ownerId);
      const revision = await tx.sandboxTemplateRevision.findFirst({
        where: { id: input.id, userId: owner.ownerId },
        select: { templateId: true },
      });
      if (!revision) throw templateNotFound();
      await tx.$queryRaw`SELECT id FROM sandbox_logical_template WHERE id = ${revision.templateId} AND "userId" = ${owner.ownerId} FOR UPDATE`;
      await tx.$queryRaw`SELECT id FROM sandbox_template_revision WHERE id = ${input.id} AND "userId" = ${owner.ownerId} FOR UPDATE`;
      await tx.sandboxTemplateRevision.update({
        where: { id: input.id, userId: owner.ownerId },
        data: { retiredAt: new Date() },
      });
      return { ok: true as const };
    });
  },
);
