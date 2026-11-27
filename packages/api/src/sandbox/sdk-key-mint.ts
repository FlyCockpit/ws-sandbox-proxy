import { ORPCError } from "@orpc/server";
import prisma, { type Prisma, type SdkKeyOrigin } from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { withAuthorityChange } from "@wssp/db/authority";
import {
  credentialLookupPrefix,
  type generateProductCredentialSecret,
  hmacDigestForProductPurpose,
} from "@wssp/db/credential-security";
import { isPrismaForeignKeyViolation, isPrismaUniqueViolation } from "../lib/prisma-errors";
import {
  digestSdkKeySecret,
  type generateSdkKeySecret,
  sdkKeyListSelect,
} from "../lib/sdk-key-access";
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
} from "../lib/sdk-key-rules";
import type { ServiceScope } from "../lib/service-scopes";
import { notifyCapacityChanged } from "./capacity-queue-wake";
import { sessionPrincipal } from "./contracts";
import { lockOwnerPlacement } from "./direct-placement";
import { lockPoolGraph } from "./pool-locks";
import { lockSharingPrincipals, requirePoolUse } from "./sharing-authority";
import { launchableRevisionWhere } from "./template-resolution";

/**
 * SDK key mint and revoke internals shared by the dashboard (`sdkKeys`,
 * `agentTokens`) and `wssp login` (`userLogins.exchangeDeviceCode`, `DELETE
 * /v1/key`). Callers authorize first; nothing here is a service entry point.
 */

/** Retained legacy host links are not structurally owner-composite. Filter
 * before projecting host names, just as credential authorization filters IDs. */
export function ownedSdkKeyListSelect(ownerId: string) {
  return {
    ...sdkKeyListSelect,
    HostAllowlist: {
      ...sdkKeyListSelect.HostAllowlist,
      where: { SdkKey: { userId: ownerId }, SandboxHost: { userId: ownerId } },
    },
  } satisfies Prisma.SdkKeySelect;
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

/** The grant rules every mint enforces (dashboard keys, agent tokens and CLI logins). */
export function assertMintableGrant(
  scopes: ServiceScope[],
  input: {
    resourceMode: "ALL_OWNED" | "ALLOWLIST";
    poolMode: "ALL_USABLE" | "SELECTED";
    hostIds: readonly string[];
    poolIds: readonly string[];
    credentialIds: readonly string[];
  },
): void {
  if (hostScopesNeedHostGrant(scopes, input.resourceMode, [...input.hostIds]))
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
  if (webhooksScopeNeedsAllOwned(scopes, input.resourceMode, input.poolMode)) {
    throw new ORPCError("BAD_REQUEST", {
      message: "webhooks:write needs a key over all owned resources and all usable pools.",
      data: { code: SDK_KEY_WEBHOOKS_REQUIRES_ALL_OWNED_CODE },
    });
  }
  if (credentialsUseNeedsLogins(scopes, input.resourceMode, [...input.credentialIds])) {
    throw new ORPCError("BAD_REQUEST", {
      message: "credentials:use on an allowlist key needs at least one allowlisted login.",
      data: { code: SDK_KEY_CREDENTIALS_USE_NEEDS_LOGINS_CODE },
    });
  }
  if (input.poolMode === "ALL_USABLE" && input.poolIds.length > 0)
    throw new ORPCError("BAD_REQUEST", { message: "ALL_USABLE keys cannot select pools." });
}

/** Owners of the selected pools, read before the mint transaction so their
 * sharing locks are taken first, in one sorted pass with the owner's. */
export async function selectedPoolOwnerIds(poolIds: readonly string[]): Promise<string[]> {
  if (poolIds.length === 0) return [];
  const pools = await prisma.sandboxPool.findMany({
    where: { id: { in: [...poolIds] } },
    take: 200,
    select: { id: true, userId: true },
  });
  return pools.map((pool) => pool.userId);
}

/**
 * The mint's first locks, in this order: every sharing principal (the owner
 * and the selected pools' owners, sorted; each `lockOwnerForAdmission` plus a
 * ban check), then the owner's placement lock. Active-key caps are counted
 * after these and before `insertSdkKey`.
 */
export async function lockSdkKeyMint(
  tx: Prisma.TransactionClient,
  ownerId: string,
  poolOwnerIds: readonly string[],
): Promise<void> {
  // C21-13: owner lock precedes the owner-row INSERT.
  await lockSharingPrincipals(tx, [ownerId, ...poolOwnerIds]);
  await lockOwnerPlacement(tx, ownerId);
}

export type SdkKeyMintPlan = {
  kind: "API" | "AGENT_TOKEN";
  origin?: SdkKeyOrigin;
  name: string;
  scopes: ServiceScope[];
  resourceMode: "ALL_OWNED" | "ALLOWLIST";
  poolMode: "ALL_USABLE" | "SELECTED";
  hostIds: string[];
  templateRevisionIds: string[];
  poolIds: string[];
  credentialIds: string[];
  ownSandboxesOnly: boolean;
  expiresAt: Date | null;
  maxLiveSandboxes?: number | null;
  credential:
    | ReturnType<typeof generateSdkKeySecret>
    | ReturnType<typeof generateProductCredentialSecret<"agentToken">>;
};

/**
 * Runs after `lockSdkKeyMint` in the same transaction: resolves the allowlists
 * (pool graph, then each pool through `requirePoolUse`, hosts, templates,
 * logins) and inserts the key.
 */
export async function insertSdkKey(
  tx: Prisma.TransactionClient,
  ownerId: string,
  plan: SdkKeyMintPlan,
) {
  const allowlists = await resolveOwnedAllowlists(
    tx,
    ownerId,
    plan.hostIds,
    plan.templateRevisionIds,
    plan.poolIds,
    plan.poolMode,
  );
  const credentialIds = await resolveOwnedCredentials(tx, ownerId, plan.credentialIds);
  return tx.sdkKey.create({
    data: {
      userId: ownerId,
      kind: plan.kind,
      origin: plan.origin ?? "DASHBOARD",
      ownSandboxesOnly: plan.ownSandboxesOnly,
      maxLiveSandboxes: plan.maxLiveSandboxes ?? null,
      name: plan.name,
      resourceMode: plan.resourceMode,
      poolMode: plan.poolMode,
      scopes: plan.scopes,
      lookupPrefix: credentialLookupPrefix(plan.credential),
      secretDigest:
        plan.kind === "API"
          ? digestSdkKeySecret(plan.credential.raw)
          : hmacDigestForProductPurpose({ purpose: "agentToken", value: plan.credential.raw }),
      expiresAt: plan.expiresAt,
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
    select: ownedSdkKeyListSelect(ownerId),
  });
}

/** Mint-time database races as domain conflicts. */
export function rethrowSdkKeyMintError(error: unknown, kind: "API" | "AGENT_TOKEN" = "API"): never {
  if (isPrismaForeignKeyViolation(error)) {
    throw new ORPCError("CONFLICT", {
      message: "An allowlisted resource was removed during mint.",
    });
  }
  if (isPrismaUniqueViolation(error)) {
    throw new ORPCError("CONFLICT", {
      message: kind === "AGENT_TOKEN" ? "Could not mint agent token." : "Could not mint SDK key.",
    });
  }
  throw error;
}

/**
 * Revoke one active key of `ownerId` (the dashboard revoke and a CLI login's
 * `/v1` self-revoke): an authority change for that credential, under the
 * owner's admission lock, then a capacity wake so its waiting creates fail.
 * NOT_FOUND when no matching active key exists.
 */
export async function revokeOwnedKey(
  ownerId: string,
  key: { id: string; kind: "API" | "AGENT_TOKEN"; origin?: SdkKeyOrigin },
): Promise<void> {
  const where = {
    id: key.id,
    userId: ownerId,
    kind: key.kind,
    revokedAt: null,
    ...(key.origin ? { origin: key.origin } : {}),
  } satisfies Prisma.SdkKeyWhereInput;
  // Unknown ids answer before the change: each change keys process memory by id.
  const notFoundMessage =
    key.kind === "AGENT_TOKEN" ? "Agent token not found." : "SDK key not found.";
  const known = await prisma.sdkKey.findFirst({ where, select: { id: true } });
  if (!known) throw new ORPCError("NOT_FOUND", { message: notFoundMessage });
  const updated = await withAuthorityChange({ ownerId, credentialId: key.id }, () =>
    prisma.$transaction(async (tx) => {
      await lockOwnerForAdmission(tx, ownerId);
      return tx.sdkKey.updateMany({ where, data: { revokedAt: new Date() } });
    }),
  );
  if (updated.count === 0) throw new ORPCError("NOT_FOUND", { message: notFoundMessage });
  // Committed: this key's waiting creates now fail credential_inactive.
  notifyCapacityChanged("all");
}
