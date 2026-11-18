import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import type { KeyInfo } from "@wssp/sandbox-contracts";
import { authorizeServiceIntent, serviceProcedure } from "../../lib/sdk-key-access";
import { SERVICE_SCOPES } from "../../lib/service-scopes";
import type { Principal } from "../contracts";
import { countKeyLiveSandboxes } from "../key-sandbox-limit";
import { callingKeyOf, grantOf } from "../principal-kinds";
import { revokeOwnedKey } from "../sdk-key-mint";

/** The disclosure boundary of `GET /v1/key`: no owner email, no secret material. */
const selfKeySelect = {
  id: true,
  name: true,
  origin: true,
  resourceMode: true,
  poolMode: true,
  ownSandboxesOnly: true,
  expiresAt: true,
  maxLiveSandboxes: true,
  // Bounded by the mint input (at most 200 pools).
  PoolAllowlist: {
    select: { poolId: true, Pool: { select: { slug: true, label: true, deletedAt: true } } },
  },
} satisfies Prisma.SdkKeySelect;

function noCallingKey(): ORPCError<"NOT_FOUND", unknown> {
  return new ORPCError("NOT_FOUND", { message: "SDK key not found." });
}

/** `key.get`: the calling key, revalidated at entry (any active key; no scope). */
export const getSelfKey = serviceProcedure(
  { action: "key.get" },
  async (principal: Principal, _input: undefined): Promise<KeyInfo> => {
    const key = callingKeyOf(principal);
    if (!key) throw noCallingKey();
    const row = await prisma.sdkKey.findFirst({
      where: { id: key.keyId, userId: principal.ownerId, revokedAt: null },
      select: selfKeySelect,
    });
    if (!row) throw noCallingKey();
    const grant = grantOf(principal);
    return {
      id: row.id,
      name: row.name,
      origin: row.origin === "CLI_LOGIN" ? "cliLogin" : "dashboard",
      scopes: SERVICE_SCOPES.filter((scope) => grant.has(scope)),
      resourceMode: row.resourceMode === "ALL_OWNED" ? "allOwned" : "allowlist",
      poolMode: row.poolMode === "ALL_USABLE" ? "allUsable" : "selected",
      pools: row.PoolAllowlist.flatMap((entry) =>
        entry.Pool && entry.Pool.deletedAt === null
          ? [{ id: entry.poolId, slug: entry.Pool.slug, label: entry.Pool.label }]
          : [],
      ),
      ownSandboxesOnly: row.ownSandboxesOnly,
      expiresAt: row.expiresAt?.toISOString() ?? null,
      maxLiveSandboxes: row.maxLiveSandboxes,
      liveSandboxes: await countKeyLiveSandboxes(prisma, principal.ownerId, key.keyId),
    };
  },
);

/**
 * `key.revokeSelf` (`DELETE /v1/key`, `wssp logout`): a CLI-login key revokes
 * itself; any other key is refused (`key.self_revoke_forbidden`, 403).
 *
 * Deliberately not a `serviceProcedure`: its result guard would see this very
 * revocation as an authority change and replace the answer with FORBIDDEN. The
 * entry authorization is the same (`authorizeServiceIntent`, which revalidates
 * the key), the answer discloses only the caller's own key id, and the
 * revocation itself is the dashboard's (`revokeOwnedKey`).
 */
export async function revokeSelfKey(
  principal: Principal,
  _input: undefined,
): Promise<{ id: string; revoked: true }> {
  await authorizeServiceIntent(principal, "key.revokeSelf");
  const key = callingKeyOf(principal);
  if (!key) throw noCallingKey();
  const row = await prisma.sdkKey.findFirst({
    where: { id: key.keyId, userId: principal.ownerId, revokedAt: null },
    select: { kind: true, origin: true },
  });
  if (!row) throw noCallingKey();
  if (row.kind !== "API" || row.origin !== "CLI_LOGIN")
    throw new ORPCError("FORBIDDEN", {
      message: "Only a CLI login key can revoke itself.",
      data: { code: "key.self_revoke_forbidden" },
    });
  await revokeOwnedKey(principal.ownerId, { id: key.keyId, kind: "API", origin: "CLI_LOGIN" });
  return { id: key.keyId, revoked: true };
}
