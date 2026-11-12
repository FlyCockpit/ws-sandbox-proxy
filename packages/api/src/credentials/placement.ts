import type { Prisma } from "@wssp/db";
import { Prisma as PrismaValue } from "@wssp/db/client";
import { credentialCapabilitiesV11Schema } from "@wssp/sandbox-contracts";
import { credentialError } from "./errors";
import { loadVerifiedLogin } from "./verified-login";

/**
 * Credential placement context: what a sandbox's
 * attached logins need from a host. Computed from rows read inside the
 * placing transaction (direct placement, queue placement, reconnect).
 *
 * - `requiresOwn`: any attached login lacks `foreignAllowed` → only the
 *   owner's own hosts (static stage `credentialOwner`).
 * - `needs`: the host's credential capability must cover files, env and
 *   proxy delivery (dynamic, waitable stage `credentialCapability`: a daemon
 *   upgrade can satisfy it).
 */

type Tx = Prisma.TransactionClient;

export type CredentialPlacementContext = {
  hasCreds: boolean;
  requiresOwn: boolean;
  needs: { files: boolean; env: boolean; proxy: boolean };
};

const NO_CREDENTIALS: CredentialPlacementContext = {
  hasCreds: false,
  requiresOwn: false,
  needs: { files: false, env: false, proxy: false },
};

/** Context for a list of logins (create request or active attachments). */
export async function credentialPlacementContextFor(
  tx: Tx,
  credentialIds: readonly string[],
  options: { forceOwn?: boolean } = {},
): Promise<CredentialPlacementContext> {
  if (credentialIds.length === 0) return NO_CREDENTIALS;
  const context: CredentialPlacementContext = {
    hasCreds: true,
    requiresOwn: options.forceOwn === true,
    needs: { files: false, env: false, proxy: false },
  };
  for (const credentialId of [...credentialIds].sort()) {
    const login = await loadVerifiedLogin(tx, credentialId);
    if (!login) throw credentialError("credential.definition_corrupt");
    if (!login.foreignAllowed) context.requiresOwn = true;
    const files = login.definition.credentials.files;
    if ((files?.required.length ?? 0) + (files?.optional.length ?? 0) > 0)
      context.needs.files = true;
    if ((login.definition.credentials.env ?? []).length > 0) context.needs.env = true;
    if (login.delivery === "PROXY") context.needs.proxy = true;
  }
  return context;
}

/** Context from a sandbox's active attachments. */
export async function sandboxCredentialPlacementContext(
  tx: Tx,
  sandboxId: string,
): Promise<CredentialPlacementContext> {
  const rows = await tx.sandboxCredential.findMany({
    where: { sandboxId, detachedAt: null },
    select: { credentialId: true },
    orderBy: { credentialId: "asc" },
    take: 8,
  });
  return credentialPlacementContextFor(
    tx,
    rows.map((row) => row.credentialId),
  );
}

/** Static stage: a login without foreign opt-in places only on the owner's hosts. */
export function credentialOwnerSql(
  context: CredentialPlacementContext | null | undefined,
  ownerId: string,
  host: Prisma.Sql = PrismaValue.raw("h"),
): Prisma.Sql {
  if (!context?.requiresOwn) return PrismaValue.sql`TRUE`;
  return PrismaValue.sql`${host}."userId" = ${ownerId}`;
}

/** Dynamic stage: the host's admitted credential capability covers the needs. */
export function credentialCapabilitySql(
  context: CredentialPlacementContext | null | undefined,
  host: Prisma.Sql = PrismaValue.raw("h"),
): Prisma.Sql {
  if (!context?.hasCreds) return PrismaValue.sql`TRUE`;
  const flag = (name: string) =>
    PrismaValue.sql`((${host}."daemonFeatures"->'credentials'->${name}) = 'true'::jsonb)`;
  const parts = [flag("sealedReturn"), flag("specTransfer")];
  if (context.needs.files) parts.push(flag("files"));
  if (context.needs.env) parts.push(flag("env"));
  if (context.needs.proxy) parts.push(flag("proxy"));
  return PrismaValue.sql`(${PrismaValue.join(parts, " AND ")})`;
}

/** The same capability check in TS, for direct placement on a locked host row. */
export function hostCredentialCapable(
  daemonFeatures: Prisma.JsonValue | null,
  context: CredentialPlacementContext,
): boolean {
  if (!context.hasCreds) return true;
  if (!daemonFeatures || typeof daemonFeatures !== "object" || Array.isArray(daemonFeatures))
    return false;
  const parsed = credentialCapabilitiesV11Schema.safeParse(daemonFeatures.credentials);
  if (!parsed.success) return false;
  const c = parsed.data;
  return (
    c.sealedReturn &&
    c.specTransfer &&
    (!context.needs.files || c.files) &&
    (!context.needs.env || c.env) &&
    (!context.needs.proxy || c.proxy)
  );
}

/**
 * Direct placement and reconnect (§8): a foreign host with a login that is
 * not opted in, or a host without the needed capability, is refused
 * `credential.host_forbidden`.
 */
export function requireCredentialHost(
  context: CredentialPlacementContext | null | undefined,
  input: { ownerId: string; hostOwnerId: string; daemonFeatures: Prisma.JsonValue | null },
): void {
  if (!context?.hasCreds) return;
  if (context.requiresOwn && input.hostOwnerId !== input.ownerId)
    throw credentialError("credential.host_forbidden");
  if (!hostCredentialCapable(input.daemonFeatures, context))
    throw credentialError("credential.host_forbidden");
}
