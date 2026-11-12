/**
 * The build principal. A build acts with its own
 * authority, never with the accepting session's or key's: the orchestrator and
 * the stored-principal resolver are the only minters, and both load it from the
 * build row with the owner as a REQUIRED input, so a caller-supplied build id
 * can never mint another owner's build authority (r4 N19).
 *
 * The brand symbol is declared, never exported and never created at runtime:
 * no other module can construct a `BuildPrincipal` (a `kind: "build"` literal or
 * an `as BuildPrincipal` cast elsewhere is refused by the principal-kinds lint).
 * No authority travels in AsyncLocalStorage.
 */
import type { Prisma } from "@wssp/db";
import { revalidateSdkKey, type ServicePrincipal } from "../lib/sdk-key-access";

declare const BUILD_PRINCIPAL: unique symbol;

export type BuildPrincipal = {
  readonly kind: "build";
  readonly ownerId: string;
  readonly buildId: string;
  /** The accepting SDK key (the real key, stored on every keyed build row and
   * operation); null for session and system builds. */
  readonly keyId: string | null;
  /** The accepting key's live grant, refreshed by every step authorization.
   * Null when the build is keyless, or when the key no longer revalidates
   * (revoked, expired, owner policy): a keyed build then sees nothing. */
  key: ServicePrincipal | null;
  readonly [BUILD_PRINCIPAL]: true;
};

/**
 * Load the build principal of `buildId` for `expectedOwnerId`, or null when no
 * such build exists for that owner. A revoked key still yields a principal
 * (cleanup and reads stay possible); every step re-checks the key.
 */
export async function loadBuildPrincipal(
  client: Prisma.TransactionClient,
  buildId: string,
  expectedOwnerId: string,
): Promise<BuildPrincipal | null> {
  if (!buildId || !expectedOwnerId) return null;
  const row = await client.sandboxTemplateBuild.findFirst({
    where: { id: buildId, userId: expectedOwnerId },
    select: { id: true, userId: true, authorizingKeyId: true },
  });
  if (!row || row.id !== buildId || row.userId !== expectedOwnerId) return null;
  const keyId = row.authorizingKeyId || null;
  const key = keyId === null ? null : await revalidateSdkKey(keyId, row.userId, client);
  return {
    kind: "build",
    ownerId: row.userId,
    buildId: row.id,
    keyId,
    key: key && key.ownerId === row.userId && key.keyId === keyId ? key : null,
  } as BuildPrincipal;
}

type AssertFalse<T extends false> = T;
/** Compile-time proof (run by `pnpm check-types`, which skips test files) that
 * a plain object with every visible field still is not a `BuildPrincipal`.
 * Exported only so `noUnusedLocals` keeps it.
 * @public */
export type BuildBrandIsPrivate = AssertFalse<
  {
    readonly kind: "build";
    readonly ownerId: string;
    readonly buildId: string;
    readonly keyId: string | null;
    key: ServicePrincipal | null;
  } extends BuildPrincipal
    ? true
    : false
>;
