import prisma, { type Prisma } from "@wssp/db";
import { hasActiveAdministrator } from "@wssp/db/admin-governance";

/**
 * Whether an administrator exists, in the admin governance's sense
 * (`hasActiveAdministrator`, packages/db/src/admin-governance.ts): a verified,
 * unbanned, non-deleting user holding the admin role. The same set
 * `assertAdminRemains` keeps non-empty, the `SETUP_KEY` bootstrap
 * (./admin-bootstrap.ts) closes on, and the server's startup hint reports, so
 * the sign-up pages never disagree with them. Pass a transaction client to
 * read inside it.
 */
export function adminUserExists(
  db: Pick<Prisma.TransactionClient, "$queryRaw"> = prisma,
): Promise<boolean> {
  return hasActiveAdministrator(db);
}

/**
 * How long a "yes, an admin exists" answer is reused by
 * {@link adminExistsForAppConfig}. Only the positive answer is cached.
 */
const ADMIN_PRESENCE_TTL_MS = 60_000;

let adminKnownUntil = 0;

/**
 * {@link adminUserExists} for the public `appConfig` procedure, which every
 * landing, sign-in and sign-up page asks: once an admin exists the answer is
 * reused for a minute, so an established server does not run this query per
 * page view. "No admin yet" is never cached: that is the bootstrap state,
 * where the operator must see the setup step the moment it applies, and it
 * flips to "closed" on the first call after the first admin is created. A
 * demoted or deleted last admin re-opens bootstrap within the TTL.
 *
 * Never use this for an authorization decision; `admin-bootstrap.ts` reads
 * `hasActiveAdministrator` fresh, inside the governance lock.
 */
export async function adminExistsForAppConfig(now = Date.now()): Promise<boolean> {
  if (now < adminKnownUntil) return true;
  const exists = await adminUserExists();
  adminKnownUntil = exists ? now + ADMIN_PRESENCE_TTL_MS : 0;
  return exists;
}

/** Forget the cached answer (tests). */
export function resetAdminPresenceCache(): void {
  adminKnownUntil = 0;
}
