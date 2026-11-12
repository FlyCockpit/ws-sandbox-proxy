import type { Prisma } from "../prisma/generated/client";

/** All admin role/ban/delete/settings writes acquire this before any user lock.
 * Transaction-scoped, cross-connection serialization; never held over network IO.
 */
export async function lockAdminGovernance(tx: Prisma.TransactionClient): Promise<void> {
  await tx.$queryRaw`SELECT pg_advisory_xact_lock(490049::bigint)::text`;
}

export class LastAdminError extends Error {
  constructor() {
    super("The last active administrator cannot be removed.");
    this.name = "LastAdminError";
  }
}

// Match parseRoles: ECMAScript trim whitespace and ASCII case, independent
// of PostgreSQL locale (e.g. Turkish I or non-breaking spaces).
const ROLE_SPACE = "[\u0009-\u000d \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]";
const ADMIN_ROLE_PATTERN = `(^|,)${ROLE_SPACE}*[aA][dD][mM][iI][nN]${ROLE_SPACE}*(,|$)`;

/** Caller holds the governance lock. Count only verified, non-deleting, unbanned
 * admins; comma-separated role tokens match the auth role policy.
 */
export async function assertAdminRemains(tx: Prisma.TransactionClient, userId: string) {
  const pattern = ADMIN_ROLE_PATTERN;
  const [row] = await tx.$queryRaw<{ blocked: boolean }[]>`
    SELECT EXISTS (SELECT 1 FROM "user" WHERE id = ${userId} AND role ~ ${pattern})
      AND NOT EXISTS (
        SELECT 1 FROM "user" WHERE id <> ${userId} AND role ~ ${pattern}
        AND "emailVerified" = true AND "deletionRequestedAt" IS NULL
        AND (banned IS DISTINCT FROM true OR "banExpires" < (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'))
      ) AS blocked`;
  if (row?.blocked) throw new LastAdminError();
}

/** Whether at least one ACTIVE administrator exists: the same verified,
 * non-deleting, unbanned admin that `assertAdminRemains` protects. Drives the
 * operator hint in the server startup log (M7-S14), so it agrees with who
 * can actually use the admin area.
 */
export async function hasActiveAdministrator(
  client: Pick<Prisma.TransactionClient, "$queryRaw">,
): Promise<boolean> {
  const [row] = await client.$queryRaw<{ present: boolean }[]>`
    SELECT EXISTS (
      SELECT 1 FROM "user" WHERE role ~ ${ADMIN_ROLE_PATTERN}
      AND "emailVerified" = true AND "deletionRequestedAt" IS NULL
      AND (banned IS DISTINCT FROM true OR "banExpires" < (CURRENT_TIMESTAMP AT TIME ZONE 'UTC'))
    ) AS present`;
  return row?.present === true;
}
