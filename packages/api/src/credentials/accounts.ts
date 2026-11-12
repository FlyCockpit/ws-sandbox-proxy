import type { Prisma } from "@wssp/db";
import { credentialError } from "./errors";
import { lockInstancesInClaimOrder } from "./leases";
import { assertOwnerCredentialCapacity, lockOwnerCredentialCounts } from "./limits";

/**
 * Account and instance row writers. They run in
 * the caller's transaction after authorization and take, in order: the owner
 * credential-count lock (creates only), the login FOR SHARE, then the account
 * FOR UPDATE. Claims never lock accounts, so this order cannot cycle with them.
 */

type Tx = Prisma.TransactionClient;

async function lockLogin(tx: Tx, ownerId: string, credentialId: string) {
  const rows = await tx.$queryRaw<{ mode: "EXCLUSIVE" | "SHAREABLE" }[]>`SELECT mode::text AS mode
    FROM credential WHERE id = ${credentialId} AND "userId" = ${ownerId} AND "deletedAt" IS NULL FOR SHARE`;
  const login = rows[0];
  if (!login) throw credentialError("credential.not_found");
  return login;
}

async function lockAccount(tx: Tx, ownerId: string, credentialId: string, accountId: string) {
  const rows = await tx.$queryRaw<
    { id: string; ordinal: number; paused: boolean }[]
  >`SELECT id, ordinal,
      ("pausedAt" IS NOT NULL) AS paused
    FROM credential_account WHERE id = ${accountId} AND "credentialId" = ${credentialId}
      AND "userId" = ${ownerId} FOR UPDATE`;
  const account = rows[0];
  if (!account) throw credentialError("credential.account_not_found");
  return account;
}

function nameTaken(error: unknown): boolean {
  return typeof error === "object" && error !== null && "code" in error && error.code === "P2002";
}

export async function insertAccount(
  tx: Tx,
  ownerId: string,
  input: { credentialId: string; name?: string | null },
): Promise<{ id: string; ordinal: number }> {
  await lockOwnerCredentialCounts(tx, ownerId);
  await lockLogin(tx, ownerId, input.credentialId);
  await assertOwnerCredentialCapacity(tx, ownerId, "accounts");
  // Ordinals are allocated under the owner lock, which serializes every create.
  const last = await tx.credentialAccount.findFirst({
    where: { credentialId: input.credentialId },
    orderBy: { ordinal: "desc" },
    select: { ordinal: true },
  });
  try {
    return await tx.credentialAccount.create({
      data: {
        userId: ownerId,
        credentialId: input.credentialId,
        ordinal: (last?.ordinal ?? 0) + 1,
        name: input.name ?? null,
      },
      select: { id: true, ordinal: true },
    });
  } catch (error) {
    if (nameTaken(error)) throw credentialError("credential.name_taken");
    throw error;
  }
}

/**
 * Adds an instance (an independent token set) to an account. EXCLUSIVE logins
 * get capacity 1; SHAREABLE logins take `maxConcurrent` (null = unlimited).
 * Checked against `CREDENTIAL_MAX_INSTANCES_PER_OWNER` under the owner lock.
 */
export async function insertInstance(
  tx: Tx,
  ownerId: string,
  input: {
    credentialId: string;
    accountId: string;
    name?: string | null;
    maxConcurrent?: number | null;
  },
): Promise<{ id: string; ordinal: number }> {
  await lockOwnerCredentialCounts(tx, ownerId);
  const login = await lockLogin(tx, ownerId, input.credentialId);
  const account = await lockAccount(tx, ownerId, input.credentialId, input.accountId);
  await assertOwnerCredentialCapacity(tx, ownerId, "instances");
  const last = await tx.credentialInstance.findFirst({
    where: { accountId: account.id },
    orderBy: { ordinal: "desc" },
    select: { ordinal: true },
  });
  try {
    return await tx.credentialInstance.create({
      data: {
        userId: ownerId,
        credentialId: input.credentialId,
        accountId: account.id,
        accountOrdinal: account.ordinal,
        ordinal: (last?.ordinal ?? 0) + 1,
        name: input.name ?? null,
        accountPaused: account.paused,
        capacity: login.mode === "EXCLUSIVE" ? 1 : (input.maxConcurrent ?? null),
        state: "EMPTY",
      },
      select: { id: true, ordinal: true },
    });
  } catch (error) {
    if (nameTaken(error)) throw credentialError("credential.name_taken");
    throw error;
  }
}

/**
 * Pause/unpause (§7.2): account FOR UPDATE, then the denormalized flag on every
 * instance of the account. Running sandboxes keep their leases; new claims
 * re-evaluate `accountPaused` in their conditional UPDATE.
 *
 * The bulk UPDATE would lock the instances in scan order; a settlement locks
 * them in the claim order (`lockInstancesInClaimOrder`), so with two
 * instances the two could each hold one and wait for the other. The
 * account's complete instance set is therefore locked in that shared order
 * first, and the UPDATE only re-takes locks this transaction already holds.
 */
export async function setAccountPaused(
  tx: Tx,
  ownerId: string,
  input: { credentialId: string; accountId: string; paused: boolean; by: string },
): Promise<void> {
  await lockLogin(tx, ownerId, input.credentialId);
  await lockAccount(tx, ownerId, input.credentialId, input.accountId);
  await tx.credentialAccount.update({
    where: { id: input.accountId },
    data: input.paused
      ? { pausedAt: new Date(), pausedBy: input.by }
      : { pausedAt: null, pausedBy: null },
    select: { id: true },
  });
  const instances = await tx.$queryRaw<{ id: string }[]>`SELECT id FROM credential_instance
    WHERE "accountId" = ${input.accountId} AND "userId" = ${ownerId}`;
  await lockInstancesInClaimOrder(
    tx,
    instances.map((row) => ({ credentialId: input.credentialId, instanceId: row.id })),
  );
  await tx.$executeRaw`UPDATE credential_instance SET "accountPaused" = ${input.paused},
      "updatedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
    WHERE "accountId" = ${input.accountId} AND "userId" = ${ownerId}`;
}
