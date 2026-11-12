import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import type { DataKeyring } from "./data-key";

/**
 * The data-key write fence, shared by every
 * encrypted writer: credential vault values and their rewrap, return-key
 * creation and rewrap, and the webhook endpoint secret writers.
 *
 * The singleton `data_key_epoch` row decides WHICH root kid new ciphertext is
 * sealed under; the env `DATA_ENCRYPTION_KEY` / `_PREVIOUS` pair only supplies
 * key material. A writer reads the row FOR SHARE inside its own transaction
 * and seals under that kid, which it must hold; otherwise it aborts with the
 * retryable `data_key.stale_writer` before writing anything. A switch
 * (`promoteDataKey`) takes the row FOR UPDATE, so it waits for every in-flight
 * writer, and once it commits no transaction can commit a row under the old
 * kid. That makes a zero per-kid count (data-key-status.ts) stable.
 *
 * Bootstrap: the first writer inserts the row with its env current kid
 * (`ON CONFLICT DO NOTHING`). Lock order: the epoch row is taken after the
 * writer's own domain locks and before any ciphertext row; it is only ever
 * held SHARE except by the switch, which holds nothing else.
 */

type Tx = Prisma.TransactionClient;

export type DataKeyEpochRow = {
  currentKid: string;
  previousKid: string | null;
  epoch: bigint;
  switchedAt: Date;
};

/** Retryable: this process lacks the root the epoch row names. Nothing was written. */
export class DataKeyStaleWriter extends Error {
  readonly code = "data_key.stale_writer";
  constructor() {
    super("This process does not hold the current data-encryption key; retry.");
    this.name = "DataKeyStaleWriter";
  }
}

/** The oRPC shape of a stale writer: 503, retryable, no new public code. */
export function staleWriterError(): ORPCError<string, unknown> {
  return new ORPCError("SERVICE_UNAVAILABLE", {
    message: "The data-encryption key is changing; retry shortly.",
    data: { code: "SERVICE_UNAVAILABLE", retryable: true },
  });
}

const KID = /^[0-9a-f]{16}$/;

async function bootstrapEpoch(tx: Tx, kid: string): Promise<void> {
  if (!KID.test(kid)) throw new Error("data key kid is malformed");
  await tx.$executeRaw`INSERT INTO data_key_epoch (id, "currentKid", epoch, "switchedAt")
    VALUES (1, ${kid}, 1, (clock_timestamp() AT TIME ZONE 'UTC')) ON CONFLICT DO NOTHING`;
}

/** Reads the epoch row FOR SHARE, inserting it with `bootstrapKid` first if absent. */
export async function lockDataKeyEpochShared(
  tx: Tx,
  bootstrapKid: string,
): Promise<DataKeyEpochRow> {
  const read = () => tx.$queryRaw<DataKeyEpochRow[]>`SELECT "currentKid", "previousKid", epoch,
    "switchedAt" FROM data_key_epoch WHERE id = 1 FOR SHARE`;
  const [row] = await read();
  if (row) return row;
  await bootstrapEpoch(tx, bootstrapKid);
  const [inserted] = await read();
  if (!inserted) throw new Error("data key epoch is unavailable");
  return inserted;
}

/** The key (of `keys`, env current first) for the epoch's kid, or `stale_writer`. */
export function writeKeyForEpoch<K extends { readonly rootKeyId: string }>(
  keys: readonly K[],
  epoch: Pick<DataKeyEpochRow, "currentKid">,
): K {
  const key = keys.find((candidate) => candidate.rootKeyId === epoch.currentKid);
  if (!key) throw new DataKeyStaleWriter();
  return key;
}

/**
 * The fence for one writer: lock the epoch row FOR SHARE (bootstrapping it
 * with the env current kid, `keys[0]`) and return the key to seal under.
 */
export async function fenceWriteKey<K extends { readonly rootKeyId: string }>(
  tx: Tx,
  keys: readonly K[],
): Promise<K> {
  const first = keys[0];
  if (!first) throw new DataKeyStaleWriter();
  return writeKeyForEpoch(keys, await lockDataKeyEpochShared(tx, first.rootKeyId));
}

/** The epoch row without locking (status, admin card); null before the first writer. */
export async function readDataKeyEpoch(
  client: Pick<Tx, "$queryRaw"> = prisma,
): Promise<DataKeyEpochRow | null> {
  const [row] = await client.$queryRaw<DataKeyEpochRow[]>`SELECT "currentKid", "previousKid",
    epoch, "switchedAt" FROM data_key_epoch WHERE id = 1`;
  return row ?? null;
}

export type PromoteResult =
  | { ok: true; changed: boolean; currentKid: string; previousKid: string | null; epoch: bigint }
  | { ok: false; reason: "kid_malformed" | "key_not_held" };

/**
 * The switch (`pnpm data-key:promote <kid>`, admin action): make `kid` the
 * kid every writer must seal under. Refused unless this process holds that
 * root (a typo would otherwise stall every writer). Takes the epoch row FOR
 * UPDATE, so it waits for in-flight writers; committing it bumps `epoch` and
 * records the old kid as `previousKid`. Promoting the current kid is a no-op.
 */
export async function promoteDataKey(
  ring: DataKeyring,
  kid: string,
  tx?: Tx,
): Promise<PromoteResult> {
  if (!KID.test(kid)) return { ok: false, reason: "kid_malformed" };
  if (ring.current.id !== kid && ring.previous?.id !== kid)
    return { ok: false, reason: "key_not_held" };
  if (!tx) return prisma.$transaction((inner) => promoteDataKey(ring, kid, inner));
  await bootstrapEpoch(tx, ring.current.id);
  const [row] = await tx.$queryRaw<DataKeyEpochRow[]>`SELECT "currentKid", "previousKid", epoch,
    "switchedAt" FROM data_key_epoch WHERE id = 1 FOR UPDATE`;
  if (!row) throw new Error("data key epoch is unavailable");
  if (row.currentKid === kid)
    return {
      ok: true as const,
      changed: false,
      currentKid: row.currentKid,
      previousKid: row.previousKid,
      epoch: row.epoch,
    };
  const [next] = await tx.$queryRaw<DataKeyEpochRow[]>`UPDATE data_key_epoch
    SET "previousKid" = "currentKid", "currentKid" = ${kid}, epoch = epoch + 1,
      "switchedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
    WHERE id = 1 RETURNING "currentKid", "previousKid", epoch, "switchedAt"`;
  if (!next) throw new Error("data key epoch is unavailable");
  return {
    ok: true as const,
    changed: true,
    currentKid: next.currentKid,
    previousKid: next.previousKid,
    epoch: next.epoch,
  };
}
