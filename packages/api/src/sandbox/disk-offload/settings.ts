import type { Prisma } from "@wssp/db";
import { z } from "zod";

/**
 * Consumed-copy grace: how long the S3
 * copy of a disk is kept after a successful start (READY of a restore, or a
 * cached cold reconnect) before it is shredded and deleted. A salvage window
 * only: a CONSUMED copy is never a restore source and never counts toward
 * quota. A deployment-level admin setting on `AppSetting` (no env var);
 * never client-readable.
 */
export const CONSUMED_GRACE_SETTING_KEY = "sandbox.offload.consumedGraceSeconds";
const CONSUMED_GRACE_DEFAULT_SECONDS = 3600;
/** 0 to 7 days; 0 deletes at once after READY. */
const CONSUMED_GRACE_MAX_SECONDS = 604_800;

/** The stored value: a canonical decimal integer string in [0, 7 days]. */
export const consumedGraceValueSchema = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,5})$/)
  .refine((value) => Number(value) <= CONSUMED_GRACE_MAX_SECONDS);

/** The grace a stored value names, or null when it is out of range or unparsable. */
function parseConsumedGraceSeconds(value: string | null | undefined): number | null {
  const parsed = consumedGraceValueSchema.safeParse(value);
  return parsed.success ? Number(parsed.data) : null;
}

/**
 * The grace in seconds, read once by the READY transaction (C6d) that writes
 * `deleteAfter = now + grace` on the CONSUMED row. No row → the default; an
 * out-of-range or unparsable stored value → the default, with a warning that
 * names the key only.
 */
export async function consumedGraceSeconds(
  tx: Pick<Prisma.TransactionClient, "appSetting">,
): Promise<number> {
  const row = await tx.appSetting.findUnique({
    where: { key: CONSUMED_GRACE_SETTING_KEY },
    select: { value: true },
  });
  if (!row) return CONSUMED_GRACE_DEFAULT_SECONDS;
  const grace = parseConsumedGraceSeconds(row.value);
  if (grace === null) {
    console.warn(
      `[disk-offload] invalid ${CONSUMED_GRACE_SETTING_KEY}; using the default ${CONSUMED_GRACE_DEFAULT_SECONDS}s`,
    );
    return CONSUMED_GRACE_DEFAULT_SECONDS;
  }
  return grace;
}
