import { ORPCError } from "@orpc/server";
import type { Prisma } from "@wssp/db";
import { env } from "@wssp/env/server";

/** `SANDBOX_MAX_HOSTS_PER_OWNER` default (packages/env/src/vars/server.ts). */
export const DEFAULT_MAX_HOSTS_PER_OWNER = 20;

/** Stable code a client keys off; not part of the public `/v1` catalog (host
 * creation is session/device-plane only). */
const OWNER_HOST_LIMIT_CODE = "sandbox.owner_host_limit";

/** The configured per-owner host cap, or null when the deployment set
 * `unlimited`. A missing value (a partial test env) is the default, never
 * unlimited. */
export function maxHostsPerOwner(): number | null {
  const value: number | null | undefined = env.SANDBOX_MAX_HOSTS_PER_OWNER;
  return value === undefined ? DEFAULT_MAX_HOSTS_PER_OWNER : value;
}

function ownerHostLimitConflict(limit: number) {
  return new ORPCError("CONFLICT", {
    message: `This account has reached its limit of ${limit} hosts. Delete a host, or ask the operator to raise SANDBOX_MAX_HOSTS_PER_OWNER.`,
    data: { code: OWNER_HOST_LIMIT_CODE, limit },
  });
}

/**
 * C52-R2-3: the per-owner host cap, checked inside the transaction that
 * inserts the host. Lock order: the caller already holds the shared owner lock
 * (`lockOwnerForAdmission`, FOR SHARE); this takes the owner's host-creation
 * advisory lock (transaction scoped) and only then counts. Every host INSERT
 * runs this first (`createHost`, device-login enrollment), so two creators for
 * one owner serialize on the advisory lock and the second counts the first's
 * committed row (READ COMMITTED: a fresh statement snapshot). FOR SHARE alone
 * would admit both. The count includes hosts pending deletion: their
 * credentials still connect until finalization.
 */
export async function assertOwnerHostCapacity(
  tx: Prisma.TransactionClient,
  ownerId: string,
): Promise<void> {
  const limit = maxHostsPerOwner();
  await tx.$queryRaw`SELECT 1 AS locked FROM pg_advisory_xact_lock(hashtextextended(${JSON.stringify(["sandbox-host-create", ownerId])}, 0))`;
  if (limit === null) return;
  const count = await tx.sandboxHost.count({ where: { userId: ownerId } });
  if (count >= limit) throw ownerHostLimitConflict(limit);
}

/**
 * Advisory pre-check for device-login approval (no lock): refuses an approval
 * that would create a host past the cap, so the owner sees it in the browser
 * instead of only in the CLI. The enrollment mint re-checks under the lock.
 */
export async function precheckOwnerHostCapacity(
  db: Pick<Prisma.TransactionClient, "sandboxHost">,
  ownerId: string,
): Promise<void> {
  const limit = maxHostsPerOwner();
  if (limit === null) return;
  const count = await db.sandboxHost.count({ where: { userId: ownerId } });
  if (count >= limit) throw ownerHostLimitConflict(limit);
}
