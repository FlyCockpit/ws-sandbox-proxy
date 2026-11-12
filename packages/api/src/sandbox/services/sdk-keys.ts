import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { withAuthorityChange } from "@wssp/db/authority";
import { credentialLookupPrefix } from "@wssp/db/credential-security";
import { z } from "zod";
import { cursorPage, cursorPageInput, pageTake, withCursor } from "../../lib/pagination";
import { isPrismaForeignKeyViolation, isPrismaUniqueViolation } from "../../lib/prisma-errors";
import { entityId, shortText } from "../../lib/schemas";
import {
  digestSdkKeySecret,
  generateSdkKeySecret,
  sdkKeyListSelect,
  serviceProcedure,
} from "../../lib/sdk-key-access";
import {
  credentialsUseNeedsLogins,
  SDK_KEY_CREDENTIALS_USE_NEEDS_LOGINS_CODE,
  SDK_KEY_TEMPLATE_NOT_ON_HOST_CODE,
  SDK_KEY_UNUSABLE_SCOPES_CODE,
  SDK_KEY_WEBHOOKS_REQUIRES_ALL_OWNED_CODE,
  unusableScopes,
  webhooksScopeNeedsAllOwned,
} from "../../lib/sdk-key-rules";
import { parseServiceScopeSet, SERVICE_SCOPES } from "../../lib/service-scopes";
import { consumeSandboxWriteBudget } from "../budgets";
import { notifyCapacityChanged } from "../capacity-queue-wake";
import { type Principal, sessionPrincipal } from "../contracts";
import { lockOwnerPlacement } from "../direct-placement";
import { poolNotFound } from "../errors";
import { lockPoolGraph } from "../pool-locks";
import { lockSharingPrincipals, requirePoolUse } from "../sharing-authority";
import { launchableRevisionWhere } from "../template-resolution";

const scopeSchema = z
  .array(z.enum(SERVICE_SCOPES))
  .min(1)
  .max(SERVICE_SCOPES.length)
  .superRefine((scopes, ctx) => {
    try {
      parseServiceScopeSet(scopes);
    } catch (error) {
      ctx.addIssue({
        code: "custom",
        message: error instanceof Error ? error.message : "Invalid scopes.",
      });
    }
  });

export const listSdkKeysInput = cursorPageInput.extend({
  includeRevoked: z.boolean().default(false),
});
export type ListSdkKeysInput = z.infer<typeof listSdkKeysInput>;

export const createSdkKeyInput = z
  .object({
    name: shortText.max(120),
    scopes: scopeSchema,
    resourceMode: z.enum(["ALL_OWNED", "ALLOWLIST"]),
    poolMode: z.enum(["ALL_USABLE", "SELECTED"]).optional(),
    hostIds: z.array(entityId).max(200).default([]),
    templateRevisionIds: z.array(entityId).max(200).default([]),
    poolIds: z.array(entityId).max(200).default([]),
    /** CLI logins an ALLOWLIST key may see and use. */
    credentialIds: z.array(entityId).max(200).default([]),
    expiresAt: z.coerce.date().nullable().optional(),
  })
  .strict()
  .superRefine((input, ctx) => {
    if (input.resourceMode === "ALL_OWNED") {
      if (
        input.hostIds.length > 0 ||
        input.templateRevisionIds.length > 0 ||
        input.credentialIds.length > 0
      ) {
        ctx.addIssue({
          code: "custom",
          message: "ALL_OWNED keys cannot also define host, template or login allowlists.",
          path: ["resourceMode"],
        });
      }
      return;
    }
    if (
      input.templateRevisionIds.length === 0 ||
      (input.hostIds.length === 0 && input.poolMode !== "ALL_USABLE" && input.poolIds.length === 0)
    ) {
      ctx.addIssue({
        code: "custom",
        message: "ALLOWLIST keys require at least one owned revision.",
        path: ["hostIds"],
      });
    }
  });
export type CreateSdkKeyInput = Omit<
  z.infer<typeof createSdkKeyInput>,
  "poolIds" | "credentialIds"
> & {
  poolIds?: string[];
  credentialIds?: string[];
};

export const revokeSdkKeyInput = z.object({ id: entityId });
export type RevokeSdkKeyInput = z.infer<typeof revokeSdkKeyInput>;

/** Retained legacy host links are not structurally owner-composite. Filter
 * before projecting host names, just as credential authorization filters IDs. */
function ownedSdkKeyListSelect(ownerId: string) {
  return {
    ...sdkKeyListSelect,
    HostAllowlist: {
      ...sdkKeyListSelect.HostAllowlist,
      where: { SdkKey: { userId: ownerId }, SandboxHost: { userId: ownerId } },
    },
  } satisfies Prisma.SdkKeySelect;
}

function serializeSdkKey(row: Prisma.SdkKeyGetPayload<{ select: typeof sdkKeyListSelect }>) {
  return {
    id: row.id,
    name: row.name,
    resourceMode: row.resourceMode,
    poolMode: row.poolMode,
    scopes: row.scopes,
    lookupPrefix: row.lookupPrefix,
    lastUsedAt: row.lastUsedAt,
    revokedAt: row.revokedAt,
    expiresAt: row.expiresAt,
    createdAt: row.createdAt,
    hostAllowlist: row.HostAllowlist.map((entry) => ({
      id: entry.sandboxHostId,
      slug: entry.SandboxHost.slug,
      label: entry.SandboxHost.label,
    })),
    poolAllowlist: (row.PoolAllowlist ?? []).map((entry) => {
      if (!entry.Pool) throw poolNotFound();
      return {
        id: entry.poolId,
        slug: entry.Pool.slug,
        label: entry.Pool.label,
      };
    }),
    revisionAllowlist: row.RevisionAllowlist.map((entry) => ({
      id: entry.templateRevisionId,
      label: `${entry.Revision.Template.label} #${entry.Revision.revision}`,
    })),
    credentialAllowlist: (row.CredentialAllowlist ?? []).map((entry) => ({
      id: entry.credentialId,
      name: entry.Credential.name,
    })),
  };
}

/** Runs inside the mint transaction: share-locking the templates makes a
 * concurrent retirement wait for the mint, or the mint see the retirement. */
async function resolveOwnedAllowlists(
  tx: Prisma.TransactionClient,
  ownerId: string,
  hostIds: string[],
  templateRevisionIds: string[],
  poolIds: string[],
  poolMode: "ALL_USABLE" | "SELECTED",
) {
  const uniqueHostIds = [...new Set(hostIds)].sort();
  const uniqueTemplateIds = [...new Set(templateRevisionIds)].sort();

  const uniquePoolIds = poolMode === "SELECTED" ? [...new Set(poolIds)].sort() : [];
  await lockPoolGraph(tx, uniquePoolIds);
  const pools: {
    poolId: string;
    poolOwnerId: string;
    shareId: string | null;
    useWitness: true | null;
  }[] = [];
  for (const poolId of uniquePoolIds) {
    const context = await requirePoolUse(tx, sessionPrincipal(ownerId), poolId);
    pools.push({
      poolId,
      poolOwnerId: context.pool.userId,
      shareId: context.share?.id ?? null,
      useWitness: context.share ? true : null,
    });
  }

  if (uniqueHostIds.length > 0) {
    // Existing H precedes template SHARE and the fresh key/grant inserts. Their
    // FK key-share must reuse H, never seek H after holding a template.
    await tx.$queryRaw`SELECT id FROM sandbox_host WHERE "userId" = ${ownerId} AND id = ANY(${uniqueHostIds}::text[]) ORDER BY id FOR UPDATE`;
    // pagination:audited — bounded by mint input hostIds max 200
    const hosts = await tx.sandboxHost.findMany({
      where: { userId: ownerId, id: { in: uniqueHostIds } },
      select: { id: true },
    });
    if (hosts.length !== uniqueHostIds.length) {
      throw new ORPCError("FORBIDDEN", {
        message: "One or more hosts are not owned by this user.",
      });
    }
  }

  if (uniqueTemplateIds.length > 0) {
    await tx.$queryRaw`SELECT id FROM sandbox_template_revision WHERE "userId" = ${ownerId} AND id = ANY(${uniqueTemplateIds}::text[]) ORDER BY id FOR SHARE`;
    // pagination:audited — bounded by mint input templateRevisionIds max 200
    const templates = await tx.sandboxTemplateRevision.findMany({
      // Only launchable revisions are grantable (community-base I1).
      where: { userId: ownerId, id: { in: uniqueTemplateIds }, ...launchableRevisionWhere() },
      select: {
        id: true,
        retiredAt: true,
        Template: { select: { archivedAt: true } },
        Availability: {
          where: {
            userId: ownerId,
            hostId: { in: uniqueHostIds },
            Host: { userId: ownerId },
            status: { in: ["AVAILABLE", "PENDING"] },
          },
          take: 1,
          select: { hostId: true },
        },
      },
    });
    if (templates.length !== uniqueTemplateIds.length) {
      throw new ORPCError("FORBIDDEN", {
        message: "One or more templates are not owned by this user.",
      });
    }
    if (
      templates.some(
        (revision) =>
          revision.retiredAt !== null ||
          revision.Template.archivedAt !== null ||
          (uniqueHostIds.length > 0 && revision.Availability.length === 0),
      )
    ) {
      throw new ORPCError("BAD_REQUEST", {
        message:
          "Every granted revision needs a pending or available association on a selected owned host.",
        data: { code: SDK_KEY_TEMPLATE_NOT_ON_HOST_CODE },
      });
    }
  }

  return { hosts: uniqueHostIds, templates: uniqueTemplateIds, pools };
}

/** Login grants: share-lock the owner's logins (sorted) so a concurrent delete
 * waits for the mint, or the mint sees the delete. */
async function resolveOwnedCredentials(
  tx: Prisma.TransactionClient,
  ownerId: string,
  credentialIds: string[],
): Promise<string[]> {
  const unique = [...new Set(credentialIds)].sort();
  if (unique.length === 0) return unique;
  const rows = await tx.$queryRaw<{ id: string }[]>`SELECT id FROM credential
    WHERE "userId" = ${ownerId} AND id = ANY(${unique}::text[]) AND "deletedAt" IS NULL
    ORDER BY id FOR SHARE`;
  if (rows.length !== unique.length)
    throw new ORPCError("FORBIDDEN", { message: "One or more logins are not owned by this user." });
  return unique;
}

export const listSdkKeys = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: ListSdkKeysInput) => {
    const parsed = listSdkKeysInput.safeParse(input);
    if (!parsed.success)
      throw new ORPCError("BAD_REQUEST", { message: "Invalid SDK key list input." });
    input = parsed.data;
    const rows = await prisma.sdkKey.findMany({
      where: withCursor(
        {
          userId: owner.ownerId,
          ...(input.includeRevoked ? {} : { revokedAt: null }),
        },
        "createdAt",
        input.cursor,
        "desc",
      ),
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: pageTake(input.limit),
      select: ownedSdkKeyListSelect(owner.ownerId),
    });
    const page = cursorPage(rows, input.limit, "createdAt");
    return {
      items: page.items.map(serializeSdkKey),
      nextCursor: page.nextCursor,
    };
  },
);

export const createSdkKey = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: CreateSdkKeyInput) => {
    const parsed = createSdkKeyInput.safeParse(input);
    if (!parsed.success) throw new ORPCError("BAD_REQUEST", { message: "Invalid SDK key input." });
    input = parsed.data;
    const scopes = parseServiceScopeSet(input.scopes);
    if (unusableScopes(scopes).length > 0) {
      throw new ORPCError("BAD_REQUEST", {
        message: "Every scope must authorize something given the other selected scopes.",
        data: { code: SDK_KEY_UNUSABLE_SCOPES_CODE },
      });
    }
    const poolMode =
      input.poolMode ?? (input.resourceMode === "ALL_OWNED" ? "ALL_USABLE" : "SELECTED");
    if (webhooksScopeNeedsAllOwned(scopes, input.resourceMode, poolMode)) {
      throw new ORPCError("BAD_REQUEST", {
        message: "webhooks:write needs a key over all owned resources and all usable pools.",
        data: { code: SDK_KEY_WEBHOOKS_REQUIRES_ALL_OWNED_CODE },
      });
    }
    if (credentialsUseNeedsLogins(scopes, input.resourceMode, input.credentialIds ?? [])) {
      throw new ORPCError("BAD_REQUEST", {
        message: "credentials:use on an allowlist key needs at least one allowlisted login.",
        data: { code: SDK_KEY_CREDENTIALS_USE_NEEDS_LOGINS_CODE },
      });
    }
    if (poolMode === "ALL_USABLE" && (input.poolIds?.length ?? 0) > 0)
      throw new ORPCError("BAD_REQUEST", { message: "ALL_USABLE keys cannot select pools." });
    await consumeSandboxWriteBudget(owner.ownerId, "pool");
    const credential = generateSdkKeySecret();
    const selectedPools = input.poolIds?.length
      ? await prisma.sandboxPool.findMany({
          where: { id: { in: input.poolIds } },
          take: 200,
          select: { id: true, userId: true },
        })
      : [];
    try {
      const created = await prisma.$transaction(async (tx) => {
        // C21-13: owner lock precedes the owner-row INSERT.
        await lockSharingPrincipals(tx, [
          owner.ownerId,
          ...selectedPools.map((pool) => pool.userId),
        ]);
        await lockOwnerPlacement(tx, owner.ownerId);
        const allowlists = await resolveOwnedAllowlists(
          tx,
          owner.ownerId,
          input.hostIds,
          input.templateRevisionIds,
          input.poolIds ?? [],
          poolMode,
        );
        const credentialIds = await resolveOwnedCredentials(
          tx,
          owner.ownerId,
          input.credentialIds ?? [],
        );
        return tx.sdkKey.create({
          data: {
            userId: owner.ownerId,
            name: input.name,
            resourceMode: input.resourceMode,
            poolMode,
            scopes,
            lookupPrefix: credentialLookupPrefix(credential),
            secretDigest: digestSdkKeySecret(credential.raw),
            expiresAt: input.expiresAt ?? null,
            HostAllowlist: {
              create: allowlists.hosts.map((sandboxHostId) => ({ sandboxHostId })),
            },
            PoolAllowlist: {
              create: allowlists.pools,
            },
            RevisionAllowlist: {
              create: allowlists.templates.map((templateRevisionId) => ({ templateRevisionId })),
            },
            CredentialAllowlist: {
              create: credentialIds.map((credentialId) => ({ credentialId })),
            },
          },
          select: ownedSdkKeyListSelect(owner.ownerId),
        });
      });
      return { key: serializeSdkKey(created), secret: credential.raw };
    } catch (error) {
      if (isPrismaForeignKeyViolation(error)) {
        throw new ORPCError("CONFLICT", {
          message: "An allowlisted resource was removed during mint.",
        });
      }
      if (isPrismaUniqueViolation(error)) {
        throw new ORPCError("CONFLICT", { message: "Could not mint SDK key." });
      }
      throw error;
    }
  },
);

export const revokeSdkKey = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: RevokeSdkKeyInput) => {
    // Unknown ids answer before the change: each change keys process memory by id.
    const known = await prisma.sdkKey.findFirst({
      where: { id: input.id, userId: owner.ownerId, revokedAt: null },
      select: { id: true },
    });
    if (!known) throw new ORPCError("NOT_FOUND", { message: "SDK key not found." });
    const updated = await withAuthorityChange(
      { ownerId: owner.ownerId, credentialId: input.id },
      () =>
        prisma.$transaction(async (tx) => {
          await lockOwnerForAdmission(tx, owner.ownerId);
          return tx.sdkKey.updateMany({
            where: { id: input.id, userId: owner.ownerId, revokedAt: null },
            data: { revokedAt: new Date() },
          });
        }),
    );
    if (updated.count === 0) throw new ORPCError("NOT_FOUND", { message: "SDK key not found." });
    // Committed: this key's waiting creates now fail credential_inactive.
    notifyCapacityChanged("all");
    return { ok: true as const };
  },
);
