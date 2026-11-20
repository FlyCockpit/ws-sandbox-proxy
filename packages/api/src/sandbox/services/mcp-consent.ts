import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import { withAuthorityChange } from "@wssp/db/authority";
import {
  isOwnerCredentialPolicySatisfied,
  ownerCredentialPolicyUserSelect,
} from "../../lib/owner-credential-policy";
import {
  credentialsUseNeedsLogins,
  hostScopesNeedHostGrant,
  SDK_KEY_TEMPLATE_NOT_ON_HOST_CODE,
  scopesUnusableForKind,
  unusableScopes,
  webhooksScopeNeedsAllOwned,
} from "../../lib/sdk-key-rules";
import { getForcedTwoFactorSettingsRecord } from "../../lib/two-factor-policy";
import { sessionPrincipal } from "../contracts";
import { lockOwnerPlacement } from "../direct-placement";
import { lockPoolGraph } from "../pool-locks";
import { lockSharingPrincipals, requirePoolUse } from "../sharing-authority";
import { launchableRevisionWhere } from "../template-resolution";
import { createSdkKeyInput } from "./sdk-keys";

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
      take: 200,
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
      take: 200,
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

/** Consent is a person-only operation. The auth plugin supplies the verified session identity. */
export async function recordMcpConsent(input: {
  userId: string;
  sessionId: string;
  clientId: string;
  referenceId: string;
  choices: unknown;
  requestedScopes: string[];
}): Promise<void> {
  const raw =
    input.choices && typeof input.choices === "object"
      ? (input.choices as Record<string, unknown>)
      : {};
  const parsed = createSdkKeyInput.safeParse({
    name: "MCP application",
    scopes: raw.scopes,
    resourceMode: raw.resourceMode,
    hostIds: raw.hostIds,
    templateRevisionIds: raw.templateRevisionIds,
    poolIds: raw.poolIds,
    credentialIds: raw.credentialIds,
    poolMode: raw.poolMode,
    ownSandboxesOnly: raw.ownSandboxesOnly ?? true,
  });
  if (!parsed.success) throw new ORPCError("BAD_REQUEST");
  const choices = parsed.data;
  const poolMode =
    choices.poolMode ?? (choices.resourceMode === "ALL_OWNED" ? "ALL_USABLE" : "SELECTED");
  if (
    choices.scopes.some((scope) => !input.requestedScopes.includes(scope)) ||
    unusableScopes(choices.scopes).length ||
    scopesUnusableForKind(choices.scopes, "OAUTH_GRANT") ||
    hostScopesNeedHostGrant(choices.scopes, choices.resourceMode, choices.hostIds) ||
    webhooksScopeNeedsAllOwned(choices.scopes, choices.resourceMode, poolMode) ||
    credentialsUseNeedsLogins(choices.scopes, choices.resourceMode, choices.credentialIds) ||
    (poolMode === "ALL_USABLE" && choices.poolIds.length)
  )
    throw new ORPCError("BAD_REQUEST");
  const selectedPools = choices.poolIds.length
    ? await prisma.sandboxPool.findMany({
        where: { id: { in: choices.poolIds } },
        take: 200,
        select: { userId: true },
      })
    : [];
  const prior = await prisma.mcpGrant.findUnique({
    where: {
      userId_clientId_referenceId: {
        userId: input.userId,
        clientId: input.clientId,
        referenceId: input.referenceId,
      },
    },
    select: { sdkKeyId: true },
  });
  await withAuthorityChange(
    { ownerId: input.userId, ...(prior ? { credentialId: prior.sdkKeyId } : {}) },
    () =>
      prisma.$transaction(async (tx) => {
        await lockSharingPrincipals(tx, [
          input.userId,
          ...selectedPools.map((pool) => pool.userId),
        ]);
        // User locks precede session locks, matching terminal/admin session gates.
        // DELETE/revocation must wait until this grant transaction commits, or we see no row.
        await tx.$queryRaw`SELECT id FROM session WHERE id = ${input.sessionId} FOR SHARE`;
        const [clock] = await tx.$queryRaw<
          { now: Date }[]
        >`SELECT clock_timestamp() AT TIME ZONE 'UTC' AS now`;
        const now = clock!.now;
        const session = await tx.session.findFirst({
          where: {
            id: input.sessionId,
            userId: input.userId,
            expiresAt: { gt: now },
            impersonatedBy: null,
          },
          select: { id: true },
        });
        if (!session) throw new ORPCError("UNAUTHORIZED");
        await lockOwnerPlacement(tx, input.userId);
        const user = await tx.user.findUnique({
          where: { id: input.userId },
          select: ownerCredentialPolicyUserSelect,
        });
        const policy = await getForcedTwoFactorSettingsRecord(tx);
        if (!user || !(await isOwnerCredentialPolicySatisfied(user, now, policy)))
          throw new ORPCError("FORBIDDEN");
        const existing = await tx.mcpGrant.findUnique({
          where: {
            userId_clientId_referenceId: {
              userId: input.userId,
              clientId: input.clientId,
              referenceId: input.referenceId,
            },
          },
          select: {
            id: true,
            sdkKeyId: true,
            revokedAt: true,
            SdkKey: {
              select: {
                revokedAt: true,
                scopes: true,
                resourceMode: true,
                poolMode: true,
                ownSandboxesOnly: true,
                HostAllowlist: { take: 200, select: { sandboxHostId: true } },
                RevisionAllowlist: { take: 200, select: { templateRevisionId: true } },
                PoolAllowlist: { take: 200, select: { poolId: true } },
                CredentialAllowlist: { take: 200, select: { credentialId: true } },
              },
            },
          },
        });
        // A revoked generation is never resurrected by a remembered approval or code replay.
        if (existing && (existing.revokedAt || existing.SdkKey.revokedAt))
          throw new ORPCError("FORBIDDEN");
        if (existing) {
          const key = existing.SdkKey;
          const subset = (next: string[], previous: string[]) =>
            next.every((id) => previous.includes(id));
          // Signed consent queries can be replayed during their validity window. A generation
          // may only narrow; expanding authority requires a fresh sign-in/authorization flow.
          const remembered =
            typeof raw.scope === "string" && raw.scope.split(/\s+/).includes("offline_access")
              ? await tx.oauthConsent.findFirst({
                  where: {
                    userId: input.userId,
                    clientId: input.clientId,
                    referenceId: input.referenceId,
                  },
                  select: { scopes: true },
                })
              : null;
          if (
            !subset(choices.scopes, key.scopes) ||
            (key.ownSandboxesOnly && !choices.ownSandboxesOnly) ||
            (key.resourceMode === "ALLOWLIST" &&
              (choices.resourceMode !== "ALLOWLIST" ||
                !subset(
                  choices.hostIds,
                  key.HostAllowlist.map((row) => row.sandboxHostId),
                ) ||
                !subset(
                  choices.templateRevisionIds,
                  key.RevisionAllowlist.map((row) => row.templateRevisionId),
                ))) ||
            (key.poolMode === "SELECTED" &&
              (poolMode !== "SELECTED" ||
                !subset(
                  choices.poolIds,
                  key.PoolAllowlist.map((row) => row.poolId),
                ))) ||
            !subset(
              choices.credentialIds,
              key.CredentialAllowlist.map((row) => row.credentialId),
            ) ||
            (typeof raw.scope === "string" &&
              raw.scope.split(/\s+/).includes("offline_access") &&
              !remembered?.scopes.includes("offline_access"))
          )
            throw new ORPCError("FORBIDDEN");
        }
        const allow = await resolveOwnedAllowlists(
          tx,
          input.userId,
          choices.hostIds,
          choices.templateRevisionIds,
          choices.poolIds,
          poolMode,
        );
        const credentialIds = await resolveOwnedCredentials(
          tx,
          input.userId,
          choices.credentialIds,
        );
        const data = {
          name: "MCP application",
          kind: "OAUTH_GRANT" as const,
          userId: input.userId,
          lookupPrefix: null,
          secretDigest: null,
          resourceMode: choices.resourceMode,
          poolMode,
          ownSandboxesOnly: choices.ownSandboxesOnly,
          scopes: choices.scopes,
          expiresAt: null,
          HostAllowlist: { create: allow.hosts.map((sandboxHostId) => ({ sandboxHostId })) },
          RevisionAllowlist: {
            create: allow.templates.map((templateRevisionId) => ({ templateRevisionId })),
          },
          PoolAllowlist: { create: allow.pools },
          CredentialAllowlist: { create: credentialIds.map((credentialId) => ({ credentialId })) },
        };
        if (existing) {
          await tx.sdkKey.update({
            where: { id: existing.sdkKeyId },
            data: {
              ...data,
              HostAllowlist: { deleteMany: {}, ...data.HostAllowlist },
              RevisionAllowlist: { deleteMany: {}, ...data.RevisionAllowlist },
              PoolAllowlist: { deleteMany: {}, ...data.PoolAllowlist },
              CredentialAllowlist: { deleteMany: {}, ...data.CredentialAllowlist },
            },
            select: { id: true },
          });
        } else {
          const key = await tx.sdkKey.create({ data, select: { id: true } });
          await tx.mcpGrant.create({
            data: {
              userId: input.userId,
              clientId: input.clientId,
              referenceId: input.referenceId,
              sdkKeyId: key.id,
            },
            select: { id: true },
          });
        }
      }),
  );
}
/** Exact generation only: refresh, introspection and code exchange never invent authority. */
export async function activeMcpConsent(input: {
  userId: string;
  clientId: string;
  referenceId: string;
}): Promise<string | null> {
  const grant = await prisma.mcpGrant.findUnique({
    where: { userId_clientId_referenceId: input },
    select: {
      id: true,
      revokedAt: true,
      SdkKey: { select: { kind: true, revokedAt: true, expiresAt: true } },
    },
  });
  return grant &&
    !grant.revokedAt &&
    grant.SdkKey.kind === "OAUTH_GRANT" &&
    !grant.SdkKey.revokedAt &&
    (!grant.SdkKey.expiresAt || grant.SdkKey.expiresAt > new Date())
    ? grant.id
    : null;
}
export async function revokeMcpOAuthTokens(userId: string, clientId: string): Promise<void> {
  await prisma.$transaction(async (tx) => {
    await tx.oauthAccessToken.deleteMany({ where: { userId, clientId } });
    await tx.oauthRefreshToken.deleteMany({ where: { userId, clientId } });
  });
}

/** A revoked generation must reauthenticate, obtaining a new consent reference. */
export async function revokedMcpConsent(input: {
  userId: string;
  clientId: string;
  referenceId: string;
}): Promise<boolean> {
  const row = await prisma.mcpGrant.findUnique({
    where: { userId_clientId_referenceId: input },
    select: { revokedAt: true, SdkKey: { select: { revokedAt: true } } },
  });
  return !!(row?.revokedAt || row?.SdkKey.revokedAt);
}
