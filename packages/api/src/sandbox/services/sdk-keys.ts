import { ORPCError } from "@orpc/server";
import {
  agentTokenBlockedByPolicy,
  agentTokenExpiryRejection,
} from "@wssp/config/agent-token-limits";
import prisma, { type Prisma } from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { withAuthorityChange } from "@wssp/db/authority";
import {
  credentialLookupPrefix,
  generateProductCredentialSecret,
  hmacDigestForProductPurpose,
} from "@wssp/db/credential-security";
import { env } from "@wssp/env/server";
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
  hostScopesNeedHostGrant,
  SDK_KEY_CREDENTIALS_USE_NEEDS_LOGINS_CODE,
  SDK_KEY_HOST_SCOPES_NEED_HOST_CODE,
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
    ownSandboxesOnly: z.boolean().default(false),
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
      (input.templateRevisionIds.length === 0 &&
        input.scopes.some((scope) => !scope.startsWith("hosts:"))) ||
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
  "poolIds" | "credentialIds" | "ownSandboxesOnly"
> & {
  ownSandboxesOnly?: boolean;
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
    kind: row.kind,
    ownSandboxesOnly: row.ownSandboxesOnly,
    name: row.name,
    resourceMode: row.resourceMode,
    poolMode: row.poolMode,
    scopes: row.scopes,
    lookupPrefix: row.lookupPrefix,
    lastUsedAt: row.lastUsedAt,
    revokedAt: row.revokedAt,
    expiresAt: row.expiresAt,
    createdAt: row.createdAt,
    /** An unrevoked no-expiry agent token refused while this deployment
     * disallows no-expiry tokens. It is kept and works again once allowed. */
    blockedByPolicy:
      row.revokedAt === null &&
      agentTokenBlockedByPolicy(row, env.WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY),
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

export const listCredentialKeys = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: ListSdkKeysInput, kind: "API" | "AGENT_TOKEN") => {
    const parsed = listSdkKeysInput.safeParse(input);
    if (!parsed.success)
      throw new ORPCError("BAD_REQUEST", { message: "Invalid SDK key list input." });
    input = parsed.data;
    const rows = await prisma.sdkKey.findMany({
      where: withCursor(
        {
          userId: owner.ownerId,
          kind,
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

export const mintCredentialKey = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: CreateSdkKeyInput, kind: "API" | "AGENT_TOKEN") => {
    const parsed = createSdkKeyInput.safeParse({
      ...input,
      ownSandboxesOnly: input.ownSandboxesOnly ?? kind === "AGENT_TOKEN",
    });
    if (!parsed.success) throw new ORPCError("BAD_REQUEST", { message: "Invalid SDK key input." });
    input = parsed.data;
    const scopes = parseServiceScopeSet(input.scopes);
    // Agent tokens: the caller chose an expiry (a date, or null = never) and it fits the
    // deployment's mint policy. Re-checked here so no shared-mint caller can skip it.
    if (
      kind === "AGENT_TOKEN" &&
      (input.expiresAt === undefined ||
        agentTokenExpiryRejection(input.expiresAt, Date.now(), {
          allowNoExpiry: env.WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY,
          maxLifetimeDays: env.WSSP_AGENT_TOKEN_MAX_LIFETIME_DAYS,
        }) !== null)
    )
      throw new ORPCError("BAD_REQUEST", {
        message: "Agent token expiry is outside this deployment's policy.",
        data: { code: "agent_token.expiry_policy" },
      });
    if (hostScopesNeedHostGrant(scopes, input.resourceMode, input.hostIds))
      throw new ORPCError("BAD_REQUEST", {
        message: "Host scopes need at least one owned host grant.",
        data: { code: SDK_KEY_HOST_SCOPES_NEED_HOST_CODE },
      });
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
    const credential =
      kind === "API" ? generateSdkKeySecret() : generateProductCredentialSecret("agentToken");
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
        if (kind === "AGENT_TOKEN") {
          const active = await tx.sdkKey.count({
            where: {
              userId: owner.ownerId,
              kind,
              revokedAt: null,
              OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
            },
          });
          if (active >= 10)
            throw new ORPCError("CONFLICT", {
              message: "Active agent token limit reached.",
              data: { code: "agent_token.limit" },
            });
        }
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
            kind,
            ownSandboxesOnly: input.ownSandboxesOnly ?? kind === "AGENT_TOKEN",
            name: input.name,
            resourceMode: input.resourceMode,
            poolMode,
            scopes,
            lookupPrefix: credentialLookupPrefix(credential),
            secretDigest:
              kind === "API"
                ? digestSdkKeySecret(credential.raw)
                : hmacDigestForProductPurpose({ purpose: "agentToken", value: credential.raw }),
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

export const revokeCredentialKey = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: RevokeSdkKeyInput, kind: "API" | "AGENT_TOKEN") => {
    // Unknown ids answer before the change: each change keys process memory by id.
    const known = await prisma.sdkKey.findFirst({
      where: { id: input.id, userId: owner.ownerId, kind, revokedAt: null },
      select: { id: true },
    });
    if (!known) throw new ORPCError("NOT_FOUND", { message: "SDK key not found." });
    const updated = await withAuthorityChange(
      { ownerId: owner.ownerId, credentialId: input.id },
      () =>
        prisma.$transaction(async (tx) => {
          await lockOwnerForAdmission(tx, owner.ownerId);
          return tx.sdkKey.updateMany({
            where: { id: input.id, userId: owner.ownerId, kind, revokedAt: null },
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

export const listSdkKeys = serviceProcedure(
  { sessionOnly: true },
  (owner: Principal, input: ListSdkKeysInput) => listCredentialKeys(owner, input, "API"),
);
export const createSdkKey = serviceProcedure(
  { sessionOnly: true },
  (owner: Principal, input: CreateSdkKeyInput) => mintCredentialKey(owner, input, "API"),
);
export const revokeSdkKey = serviceProcedure(
  { sessionOnly: true },
  (owner: Principal, input: RevokeSdkKeyInput) => revokeCredentialKey(owner, input, "API"),
);
