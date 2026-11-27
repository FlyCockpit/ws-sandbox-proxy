import { ORPCError } from "@orpc/server";
import {
  agentTokenBlockedByPolicy,
  agentTokenExpiryRejection,
} from "@wssp/config/agent-token-limits";
import prisma, { type Prisma } from "@wssp/db";
import { generateProductCredentialSecret } from "@wssp/db/credential-security";
import { env } from "@wssp/env/server";
import { z } from "zod";
import { cursorPage, cursorPageInput, pageTake, withCursor } from "../../lib/pagination";
import { entityId, shortText } from "../../lib/schemas";
import {
  generateSdkKeySecret,
  type sdkKeyListSelect,
  serviceProcedure,
} from "../../lib/sdk-key-access";
import { SDK_KEY_UNUSABLE_SCOPES_CODE, scopesUnusableForKind } from "../../lib/sdk-key-rules";
import { parseServiceScopeSet, SERVICE_SCOPES } from "../../lib/service-scopes";
import { consumeSandboxWriteBudget } from "../budgets";
import { lastConnectByKey } from "../connect-sessions";
import type { Principal } from "../contracts";
import { poolNotFound } from "../errors";
import {
  assertMintableGrant,
  insertSdkKey,
  lockSdkKeyMint,
  ownedSdkKeyListSelect,
  rethrowSdkKeyMintError,
  revokeOwnedKey,
  selectedPoolOwnerIds,
} from "../sdk-key-mint";

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

function serializeSdkKey(row: Prisma.SdkKeyGetPayload<{ select: typeof sdkKeyListSelect }>) {
  return {
    id: row.id,
    kind: row.kind,
    origin: row.origin,
    maxLiveSandboxes: row.maxLiveSandboxes,
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
    // CLI connections: kind API keys only (agent tokens never connect).
    const lastConnect =
      kind === "API"
        ? await lastConnectByKey(
            owner.ownerId,
            page.items.map((row) => row.id),
          )
        : new Map<string, Date>();
    return {
      items: page.items.map((row) => ({
        ...serializeSdkKey(row),
        lastConnectAt: lastConnect.get(row.id) ?? null,
      })),
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
    // CLI shells: kind API only (agent tokens never connect).
    if (scopesUnusableForKind(scopes, kind))
      throw new ORPCError("BAD_REQUEST", {
        message: "Every scope must authorize something given the other selected scopes.",
        data: { code: SDK_KEY_UNUSABLE_SCOPES_CODE },
      });
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
    const poolMode =
      input.poolMode ?? (input.resourceMode === "ALL_OWNED" ? "ALL_USABLE" : "SELECTED");
    assertMintableGrant(scopes, {
      resourceMode: input.resourceMode,
      poolMode,
      hostIds: input.hostIds,
      poolIds: input.poolIds ?? [],
      credentialIds: input.credentialIds ?? [],
    });
    await consumeSandboxWriteBudget(owner.ownerId, "pool");
    const credential =
      kind === "API" ? generateSdkKeySecret() : generateProductCredentialSecret("agentToken");
    const poolOwnerIds = await selectedPoolOwnerIds(input.poolIds ?? []);
    try {
      const created = await prisma.$transaction(async (tx) => {
        await lockSdkKeyMint(tx, owner.ownerId, poolOwnerIds);
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
        return insertSdkKey(tx, owner.ownerId, {
          kind,
          name: input.name,
          scopes,
          resourceMode: input.resourceMode,
          poolMode,
          hostIds: input.hostIds,
          templateRevisionIds: input.templateRevisionIds,
          poolIds: input.poolIds ?? [],
          credentialIds: input.credentialIds ?? [],
          ownSandboxesOnly: input.ownSandboxesOnly ?? kind === "AGENT_TOKEN",
          expiresAt: input.expiresAt ?? null,
          credential,
        });
      });
      return { key: serializeSdkKey(created), secret: credential.raw };
    } catch (error) {
      rethrowSdkKeyMintError(error, kind);
    }
  },
);

export const revokeCredentialKey = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: RevokeSdkKeyInput, kind: "API" | "AGENT_TOKEN") => {
    await revokeOwnedKey(owner.ownerId, { id: input.id, kind });
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
