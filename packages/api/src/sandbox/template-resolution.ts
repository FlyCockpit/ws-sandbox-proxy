import { ORPCError } from "@orpc/server";
import type { Prisma } from "@wssp/db";
import { parseTemplateSelector } from "@wssp/sandbox-contracts";
import { authorizeServiceAction, serviceResourceFilter } from "../lib/sdk-key-access";
import type { Principal } from "./contracts";
import { hostNotFound, templateNotFound } from "./errors";
import { buildIdOf } from "./principal-kinds";
import { requirePoolContribution, requirePoolUse } from "./sharing-authority";

export const revisionPublicSelect = {
  id: true,
  userId: true,
  templateId: true,
  revision: true,
  cpuCount: true,
  memoryMiB: true,
  diskGiB: true,
  incusFingerprint: true,
  architecture: true,
  guestUid: true,
  guestGid: true,
  guestHome: true,
  guestShell: true,
  guestVersion: true,
  manifestDigest: true,
  retiredAt: true,
  retiredReason: true,
  createdAt: true,
  sourceKind: true,
  parentRevisionId: true,
  captureTag: true,
  // Root-taint disclosure (badge and create hint). Policy reads these
  // explicitly in materializePlacement, never through this projection.
  capturedWithGuestRoot: true,
  builtWithWsspRecipe: true,
  pendingVerifyBuildId: true,
} satisfies Prisma.SandboxTemplateRevisionSelect;

/**
 * Launchable revisions (community-base I1/I5): never an UPSTREAM pin and never
 * a revision still pending its verify VM. Every grant, tag, association,
 * publish and listing site that loads a revision by id ANDs this in.
 */
export function launchableRevisionWhere(): Prisma.SandboxTemplateRevisionWhereInput {
  return { sourceKind: { not: "UPSTREAM" }, pendingVerifyBuildId: null };
}

/**
 * The resolver's form of the same predicate (I1, I12). Only a build
 * principal gets an exemption, and only for its own build, from durable facts
 * read here (never a caller flag):
 * - its build VM create (build QUEUED/PLACING) may resolve its own UPSTREAM
 *   base (`baseRevisionId`), nothing else that is UPSTREAM;
 * - its verify VM create (build CAPTURING with `verifyRequired`) may resolve
 *   its own pending output (`pendingVerifyBuildId = build.id`).
 * Every other caller, including a user build's `from:` base, gets neither.
 */
async function resolvableRevisionWhere(
  tx: Prisma.TransactionClient,
  owner: Principal,
): Promise<Prisma.SandboxTemplateRevisionWhereInput> {
  const buildId = buildIdOf(owner);
  if (buildId === null) return launchableRevisionWhere();
  const build = await tx.sandboxTemplateBuild.findFirst({
    where: { id: buildId, userId: owner.ownerId },
    select: { state: true, verifyRequired: true, baseRevisionId: true },
  });
  if (!build) return launchableRevisionWhere();
  if (build.state === "QUEUED" || build.state === "PLACING")
    return {
      pendingVerifyBuildId: null,
      OR: [{ sourceKind: { not: "UPSTREAM" } }, { id: build.baseRevisionId }],
    };
  if (build.state === "CAPTURING" && build.verifyRequired)
    return {
      sourceKind: { not: "UPSTREAM" },
      OR: [{ pendingVerifyBuildId: null }, { pendingVerifyBuildId: buildId }],
    };
  return launchableRevisionWhere();
}

export async function visibleLogicalTemplate(
  tx: Prisma.TransactionClient,
  owner: Principal,
  id: string,
) {
  const row = await tx.sandboxTemplate.findFirst({
    where: { AND: [serviceResourceFilter(owner, "template"), { id }] },
    select: {
      id: true,
      userId: true,
      slug: true,
      label: true,
      archivedAt: true,
      createdAt: true,
      updatedAt: true,
    },
  });
  if (!row) throw templateNotFound();
  return row;
}

/** Resolve once, using grant-filtered joins. No ungranted revision is loaded,
 * even when the caller knows a logical ID or a tag on a visible template. */
export async function resolveTemplateRevision(
  tx: Prisma.TransactionClient,
  owner: Principal,
  selector: string,
) {
  let parsed: ReturnType<typeof parseTemplateSelector>;
  try {
    parsed = parseTemplateSelector(selector);
  } catch {
    throw new ORPCError("BAD_REQUEST", { message: "Invalid template selector." });
  }
  const visibility = serviceResourceFilter(owner, "revision");
  const launchable = await resolvableRevisionWhere(tx, owner);
  if (parsed.kind === "revision") {
    const row = await tx.sandboxTemplateRevision.findFirst({
      where: {
        AND: [
          visibility,
          launchable,
          { id: parsed.id, retiredAt: null, Template: { archivedAt: null } },
        ],
      },
      select: revisionPublicSelect,
    });
    if (!row) throw templateNotFound();
    return row;
  }
  const logicalWhere: Prisma.SandboxTemplateWhereInput =
    parsed.kind === "template"
      ? { id: parsed.id }
      : parsed.kind === "tag"
        ? { slug: parsed.slug }
        : parsed.kind === "name"
          ? { OR: [{ id: parsed.name }, { slug: parsed.name }] }
          : { id: parsed.id };
  const logical = await tx.sandboxTemplate.findMany({
    where: { AND: [serviceResourceFilter(owner, "template"), logicalWhere, { archivedAt: null }] },
    select: { id: true },
    take: 2,
  });
  if (logical.length !== 1) throw templateNotFound();
  const row = await tx.sandboxTemplateRevision.findFirst({
    where: {
      AND: [
        visibility,
        launchable,
        {
          templateId: logical[0]!.id,
          retiredAt: null,
          Tags: {
            some: {
              userId: owner.ownerId,
              templateId: logical[0]!.id,
              tag: parsed.kind === "tag" ? parsed.tag : "latest",
            },
          },
        },
      ],
    },
    select: revisionPublicSelect,
  });
  if (!row) throw templateNotFound();
  return row;
}

export type ImageTargetInput = { hostId?: string; poolId?: string; memberId?: string };
export async function resolveTemplateImageTarget(
  tx: Prisma.TransactionClient,
  owner: Principal,
  input: ImageTargetInput,
) {
  if (input.hostId && !input.poolId && !input.memberId) {
    // All image writes share templates:write and the direct host grant.
    // Check it before existence so an ungranted host cannot change the error.
    // Append/associate repeat their revision-specific action checks below.
    await authorizeServiceAction(owner, "templates.create", { sandboxHostId: input.hostId }, tx);
    const host = await tx.sandboxHost.findFirst({
      where: { id: input.hostId, userId: owner.ownerId },
      select: { id: true },
    });
    if (!host) throw hostNotFound();
    return {
      hostId: host.id,
      hostOwnerId: owner.ownerId,
      poolOwnerId: owner.ownerId,
      poolId: null,
    };
  }
  if (input.hostId || !input.poolId || !input.memberId)
    throw new ORPCError("BAD_REQUEST", { message: "Choose one image verification target." });
  const { pool } = await requirePoolUse(tx, owner, input.poolId);
  const member = await tx.sandboxPoolMember.findFirst({
    where: { id: input.memberId, poolId: pool.id, enabled: true, removedAt: null },
    select: { sandboxHostId: true, hostOwnerId: true },
  });
  if (!member?.hostOwnerId) throw hostNotFound();
  await requirePoolContribution(tx, member.hostOwnerId, pool.id, member.sandboxHostId);
  return {
    hostId: member.sandboxHostId,
    hostOwnerId: member.hostOwnerId,
    poolOwnerId: pool.userId,
    poolId: pool.id,
  };
}
