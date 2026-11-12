import prisma from "@wssp/db";
import {
  DataKeyStaleWriter,
  lockDataKeyEpochShared,
  writeKeyForEpoch,
} from "../crypto/data-key-epoch";
import {
  type DiskRewrapCursor,
  readDiskWrapKeys,
  rewrapDiskKeyBatch,
} from "../sandbox/disk-offload/keys";
import { readVaultKeys } from "./vault/keys";
import { rewrapReturnKeyBatch } from "./vault/return-key-store";
import { type RewrapCursor, rewrapValueBatch } from "./vault/store";

/**
 * Credential maintenance tick, run every 60 s beside
 * the webhooks rekey: after a data-key promote, rewrap every stored DEK and
 * every live return private key still under a kid other than the epoch's.
 * One transaction holds the epoch row FOR SHARE (so a promote waits for it and
 * a rewrap can never commit under a kid that was just retired), then takes
 * ciphertext rows FOR UPDATE SKIP LOCKED in key order. Webhooks keep their own
 * `rekeySecrets` (webhooks/ledger.ts) under the same fence.
 *
 * The in-memory cursor advances past every row looked at, including rows no
 * configured root opens, and a short batch wraps to the front: an unopenable
 * row never pins a batch. It works without `CREDENTIALS_ENABLED` (drain mode):
 * only the key matters.
 *
 * The same tick rewraps disk offload DEKs: every live
 * offload wrap and every OPEN disk session wrap, the two disk status sources.
 */

export const CREDENTIAL_REWRAP_BATCH = 200;

export type CredentialRewrapCursor = {
  value: RewrapCursor;
  returnKey: string | null;
  disk?: DiskRewrapCursor;
};

export function newCredentialRewrapCursor(): CredentialRewrapCursor {
  return { value: null, returnKey: null, disk: { offload: null, session: null } };
}

export type CredentialRewrapResult = {
  values: number;
  returnKeys: number;
  /** Disk offload and OPEN disk-session wraps rewrapped. */
  diskKeys: number;
  /** Rows no configured root could open this tick (a count only). */
  failed: number;
  /** This process lacks the epoch's root: nothing was written. */
  stale: boolean;
};

export async function rewrapCredentialKeys(
  options: {
    client?: Pick<typeof prisma, "$transaction">;
    cursor?: CredentialRewrapCursor;
    batch?: number;
  } = {},
): Promise<CredentialRewrapResult> {
  const none = { values: 0, returnKeys: 0, diskKeys: 0, failed: 0, stale: false };
  const keys = readVaultKeys();
  const diskKeys = readDiskWrapKeys();
  if (!keys || !diskKeys) return none;
  const client = options.client ?? prisma;
  const cursor = options.cursor ?? newCredentialRewrapCursor();
  const batch = options.batch ?? CREDENTIAL_REWRAP_BATCH;
  return client.$transaction(
    async (tx) => {
      const epoch = await lockDataKeyEpochShared(tx, keys.dek.current.rootKeyId);
      let dekKey: (typeof keys.dek.all)[number];
      let returnKey: (typeof keys.returnKey.all)[number];
      let diskKey: (typeof diskKeys.all)[number];
      try {
        dekKey = writeKeyForEpoch(keys.dek.all, epoch);
        returnKey = writeKeyForEpoch(keys.returnKey.all, epoch);
        diskKey = writeKeyForEpoch(diskKeys.all, epoch);
      } catch (error) {
        if (error instanceof DataKeyStaleWriter) return { ...none, stale: true };
        throw error;
      }
      const values = await rewrapValueBatch(tx, dekKey, cursor.value, batch);
      cursor.value = values.scanned < batch ? null : values.last;
      const returns = await rewrapReturnKeyBatch(tx, returnKey, cursor.returnKey, batch);
      cursor.returnKey = returns.scanned < batch ? null : returns.last;
      const disks = await rewrapDiskKeyBatch(
        tx,
        diskKey,
        cursor.disk ?? { offload: null, session: null },
        batch,
        diskKeys.all,
      );
      cursor.disk = disks.next;
      return {
        values: values.rewrapped,
        returnKeys: returns.rewrapped,
        diskKeys: disks.rewrapped,
        failed: values.failed + returns.failed + disks.failed,
        stale: false,
      };
    },
    { timeout: 30_000 },
  );
}
