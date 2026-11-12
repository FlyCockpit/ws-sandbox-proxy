import type { Prisma } from "@wssp/db";
import { readSandboxOffloadEnv } from "@wssp/env/image-store-config";
import { exactBigint, layerQuota } from "../image-store/config";

/**
 * Offload quota and spend ledger. Both are decided under the owner lock
 * (`lockImageQuota`, owner placement 31), so two hosts never both take the
 * last allowance.
 */

type Tx = Pick<Prisma.TransactionClient, "$queryRaw" | "accountImagePolicy">;

export const GIB = 1_073_741_824n;

/** Live offload states: the rows that count toward the stored quota.
 * CONSUMED (inside its grace or not) never counts (§6a). */
export const LIVE_OFFLOAD_STATES = [
  "PENDING",
  "EXPORTING",
  "UPLOADING",
  "VERIFYING",
  "STORED",
  "EVICTING",
] as const;

/** The account's stored-offload cap in bytes: `SANDBOX_OFFLOAD_MAX_GIB_PER_ACCOUNT`,
 * lowered (never raised) by the admin `adminOffloadGiBMax`. */
export async function offloadQuotaBytes(tx: Tx, ownerId: string): Promise<bigint> {
  const policy = await tx.accountImagePolicy.findUnique({
    where: { userId: ownerId },
    select: { adminOffloadGiBMax: true },
  });
  const gib =
    layerQuota(
      readSandboxOffloadEnv().SANDBOX_OFFLOAD_MAX_GIB_PER_ACCOUNT,
      policy?.adminOffloadGiBMax,
    ) ?? 0;
  return BigInt(gib) * GIB;
}

/**
 * Bytes the account's live offloads hold or are uploading: a completed row's
 * `storedBytes`, else its OPEN session's `storedBytes`. `excludeOffloadId`
 * leaves out the attempt being decided.
 */
export async function offloadUsageBytes(
  tx: Tx,
  ownerId: string,
  excludeOffloadId: string | null = null,
): Promise<bigint> {
  const rows = await tx.$queryRaw<{ total: unknown }[]>`
    SELECT COALESCE(sum(COALESCE(o."storedBytes", (SELECT s."storedBytes"
        FROM sandbox_image_upload_session s WHERE s."liveDiskOffloadId" = o.id), 0)), 0)::bigint AS total
    FROM sandbox_disk_offload o
    WHERE o."userId" = ${ownerId} AND o.state::text = ANY(${[...LIVE_OFFLOAD_STATES]}::text[])
      AND (${excludeOffloadId}::text IS NULL OR o.id <> ${excludeOffloadId})`;
  return exactBigint(rows[0]?.total);
}

/** Start of the UTC day containing `now`. */
export function utcDayStart(now: Date): Date {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
}

/** The daily upload budget in bytes (`SANDBOX_OFFLOAD_GIB_PER_DAY`). */
export function offloadDailyBudgetBytes(): bigint {
  return BigInt(readSandboxOffloadEnv().SANDBOX_OFFLOAD_GIB_PER_DAY) * GIB;
}

/**
 * Upload bytes granted to the owner since the UTC day began: the DB ledger
 * (R11), the sum of `OFFLOAD_UPLOAD` transfer sizes whatever their outcome
 * (a superseded or failed session spent its grant). RESTORE_FETCH bytes are
 * never counted here: restores are never refused.
 */
export async function offloadSpentTodayBytes(
  tx: Pick<Prisma.TransactionClient, "$queryRaw">,
  ownerId: string,
  now: Date,
): Promise<bigint> {
  const rows = await tx.$queryRaw<{ total: unknown }[]>`
    SELECT COALESCE(sum("sizeBytes"), 0)::bigint AS total FROM sandbox_image_transfer
    WHERE "userId" = ${ownerId} AND purpose::text = 'OFFLOAD_UPLOAD'
      AND "createdAt" >= ${utcDayStart(now)}`;
  return exactBigint(rows[0]?.total);
}

/**
 * Whether one more upload of `storedBytes` fits both the stored quota and
 * today's ledger. Caller holds the owner lock.
 */
export async function offloadAdmits(
  tx: Tx,
  input: { ownerId: string; offloadId: string; storedBytes: bigint; now: Date },
): Promise<boolean> {
  const quota = await offloadQuotaBytes(tx, input.ownerId);
  if ((await offloadUsageBytes(tx, input.ownerId, input.offloadId)) + input.storedBytes > quota)
    return false;
  return (
    (await offloadSpentTodayBytes(tx, input.ownerId, input.now)) + input.storedBytes <=
    offloadDailyBudgetBytes()
  );
}
