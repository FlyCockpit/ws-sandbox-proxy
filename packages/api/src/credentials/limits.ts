import type { Prisma } from "@wssp/db";
import { env } from "@wssp/env/server";
import limits from "../../../config/src/credential-limits.json";
import { credentialError } from "./errors";

/** Abuse bounds. Every count is checked under the owner lock. */
export const CREDENTIAL_LIMITS = limits;

/** `CREDENTIAL_MAX_INSTANCES_PER_OWNER` default (packages/env/src/vars/server.ts). */
const DEFAULT_MAX_INSTANCES_PER_OWNER = 1000;

/** Configured per-owner instance cap, or null for `unlimited`. A missing value
 * (a partial test env) is the default, never unlimited. */
export function maxInstancesPerOwner(): number | null {
  const value: number | null | undefined = env.CREDENTIAL_MAX_INSTANCES_PER_OWNER;
  return value === undefined ? DEFAULT_MAX_INSTANCES_PER_OWNER : value;
}

/**
 * The owner's credential-count lock: a transaction-scoped advisory lock taken
 * first by every path that creates a definition version, login, account,
 * instance or login session. Two creators for one owner serialize here, so the
 * second counts the first's committed row (READ COMMITTED takes a fresh
 * snapshot per statement). It is a leaf before any credential row lock.
 */
export async function lockOwnerCredentialCounts(
  tx: Prisma.TransactionClient,
  ownerId: string,
): Promise<void> {
  await tx.$queryRaw`SELECT 1 AS locked FROM pg_advisory_xact_lock(hashtextextended(${JSON.stringify(["credential-counts", ownerId])}, 0))`;
}

type CountedResource = "definitions" | "logins" | "accounts" | "instances" | "loginSessions";

function limitFor(resource: CountedResource): number | null {
  switch (resource) {
    case "definitions":
      return limits.definitionVersionsPerOwner;
    case "logins":
      return limits.loginsPerOwner;
    case "accounts":
      return limits.accountsPerOwner;
    case "instances":
      return maxInstancesPerOwner();
    case "loginSessions":
      return limits.activeLoginSessionsPerOwner;
  }
}

async function countFor(
  tx: Prisma.TransactionClient,
  ownerId: string,
  resource: CountedResource,
): Promise<number> {
  switch (resource) {
    case "definitions":
      return tx.credentialDefinition.count({ where: { userId: ownerId } });
    case "logins":
      return tx.credential.count({ where: { userId: ownerId } });
    case "accounts":
      return tx.credentialAccount.count({ where: { userId: ownerId } });
    case "instances":
      return tx.credentialInstance.count({ where: { userId: ownerId } });
    case "loginSessions":
      return tx.credentialLoginSession.count({
        // FAILED keeps its sandbox for a retry until cancel or expiry.
        where: { userId: ownerId, state: { in: ["PROVISIONING", "READY", "SAVING", "FAILED"] } },
      });
  }
}

/** Refuses `credential.limit_reached` when adding `adding` rows would pass the cap.
 * The caller must already hold {@link lockOwnerCredentialCounts}. */
export async function assertOwnerCredentialCapacity(
  tx: Prisma.TransactionClient,
  ownerId: string,
  resource: CountedResource,
  adding = 1,
): Promise<void> {
  const limit = limitFor(resource);
  if (limit === null) return;
  if ((await countFor(tx, ownerId, resource)) + adding > limit)
    throw credentialError("credential.limit_reached", { resource, limit });
}
