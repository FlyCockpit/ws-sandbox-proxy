/**
 * "Which principal did this stored work act for?" answered in one place, never
 * at each reader from a nullable key column. The
 * build fact is checked FIRST, from the immutable `Sandbox.buildId` (CHECKed
 * against `purpose`), never from the key column: keyed build work stores the
 * real accepting key, so a key alone cannot tell a build from its key. Then
 * the recording SDK key, then its owner's browser session. `system` is never
 * inferred: system work exists only as outbox-payload attribution.
 */
import type { Prisma } from "@wssp/db";
import { revalidateSdkKey } from "../lib/sdk-key-access";
import { loadBuildPrincipal } from "../template-builds/principal";
import { type AuthorizingPrincipal, type Principal, sessionPrincipal } from "./contracts";

export type StoredWork = {
  /** The work's owner (`userId` on the operation, wait or transfer row). */
  userId: string;
  /** The SDK key recorded with the work (`authorizingKeyId` / transfer `keyId`). */
  authorizingKeyId: string | null;
  /** `Sandbox.buildId` of the work's sandbox. Required: every reader joins it,
   * so "not a build" is a stored fact, never an omitted field. */
  sandboxBuildId: string | null;
  /** `Sandbox.verifyBuildId` (a community verify VM's build). Required for
   * the same reason: verify-VM work attributes to its build. */
  sandboxVerifyBuildId: string | null;
};

/** The build a stored work's sandbox belongs to (build VM or verify VM). */
function storedBuildIdOf(w: StoredWork): string | null {
  return w.sandboxBuildId || w.sandboxVerifyBuildId || null;
}

/** Pure attribution of stored work. */
export function storedAttributionOf(w: StoredWork): AuthorizingPrincipal {
  const buildId = storedBuildIdOf(w);
  if (buildId) return { kind: "build", buildId, keyId: w.authorizingKeyId || null };
  return w.authorizingKeyId ? { kind: "sdkKey", keyId: w.authorizingKeyId } : { kind: "session" };
}

/** The work's CURRENT principal: the build principal (null when the build row
 * is gone or its recorded key disagrees with the work's), a revalidated key
 * (null once revoked, expired or its owner fails credential policy), or the
 * owner's session principal. */
export async function resolveStoredPrincipal(
  client: Prisma.TransactionClient,
  w: StoredWork,
): Promise<Principal | null> {
  const buildId = storedBuildIdOf(w);
  if (buildId) {
    const build = await loadBuildPrincipal(client, buildId, w.userId);
    return build && build.keyId === (w.authorizingKeyId || null) ? build : null;
  }
  if (w.authorizingKeyId) return revalidateSdkKey(w.authorizingKeyId, w.userId, client);
  return sessionPrincipal(w.userId);
}
