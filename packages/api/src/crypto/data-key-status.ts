import prisma, { type Prisma } from "@wssp/db";
import { countDiskOffloadWrapKids, countDiskSessionWrapKids } from "../sandbox/disk-offload/keys";
import type { DataKeyring } from "./data-key";
import { type DataKeyEpochRow, readDataKeyEpoch } from "./data-key-epoch";
import {
  type DataKeyHeartbeat,
  type HeartbeatRedis,
  heldKids,
  readDataKeyHeartbeats,
} from "./data-key-heartbeat";

/**
 * Data-key rotation status: `pnpm data-key:status` and
 * the admin data-key card.
 *
 * - Per-table, per-kid row counts from one REGISTRY of every column that
 *   stores the root kid a ciphertext is sealed under. A new encrypted column
 *   must be added here, or `safeToRemove` would lie.
 * - The epoch row (which kid writers must seal under).
 * - ADVISORY Redis heartbeats `{role, keysHeld}` (every 30 s, TTL 120 s) so an
 *   operator can see which processes still lack a key. They never gate.
 *
 * `safeToRemove(old)` ⇔ the epoch's current kid is not `old` and every
 * registered count for `old` is 0. Because the write fence makes a post-switch
 * old-kid commit impossible, a zero count is stable.
 */

type Client = Pick<Prisma.TransactionClient, "$queryRaw">;
type KidCount = { kid: string; rows: number };

/** Kid cardinality is tiny (one per rotation); the cap only bounds a corrupt table. */
const KID_GROUP_CAP = 64;

export const DATA_KEY_COLUMNS = [
  {
    source: "webhook_endpoint.secretKeyId",
    count: (db: Client) => db.$queryRaw<KidCount[]>`SELECT "secretKeyId" AS kid,
      count(*)::int AS rows FROM webhook_endpoint GROUP BY 1 ORDER BY 1 LIMIT ${KID_GROUP_CAP}`,
  },
  {
    source: "webhook_endpoint.previousSecretKeyId",
    count: (db: Client) => db.$queryRaw<KidCount[]>`SELECT "previousSecretKeyId" AS kid,
      count(*)::int AS rows FROM webhook_endpoint WHERE "previousSecretKeyId" IS NOT NULL
      GROUP BY 1 ORDER BY 1 LIMIT ${KID_GROUP_CAP}`,
  },
  {
    source: "credential_secret_version.rootKid",
    count: (db: Client) => db.$queryRaw<KidCount[]>`SELECT "rootKid" AS kid,
      count(*)::int AS rows FROM credential_secret_version GROUP BY 1 ORDER BY 1 LIMIT ${KID_GROUP_CAP}`,
  },
  {
    // A destroyed return key holds no ciphertext (empty `wrappedPrivate`).
    source: "credential_return_key.rootKid",
    count: (db: Client) => db.$queryRaw<KidCount[]>`SELECT "rootKid" AS kid,
      count(*)::int AS rows FROM credential_return_key WHERE "destroyedAt" IS NULL
      GROUP BY 1 ORDER BY 1 LIMIT ${KID_GROUP_CAP}`,
  },
  {
    // Disk offload wraps: a shredded row holds none, so a
    // root stays non-removable exactly while an unshredded disk wrap exists.
    // The SQL lives in disk-offload/keys.ts, the wrap columns' only reader.
    source: "sandbox_disk_offload.rootKid",
    count: (db: Client) => countDiskOffloadWrapKids(db, KID_GROUP_CAP),
  },
  {
    // An OPEN disk upload session holds its own wrap until Complete.
    source: "sandbox_image_upload_session.keyId",
    count: (db: Client) => countDiskSessionWrapKids(db, KID_GROUP_CAP),
  },
] as const;

export type DataKeySource = (typeof DATA_KEY_COLUMNS)[number]["source"];

// --- Status -----------------------------------------------------------------

export type DataKeyStatus = {
  epoch: {
    currentKid: string;
    previousKid: string | null;
    epoch: string;
    switchedAt: string;
  } | null;
  counts: { source: DataKeySource; kid: string; rows: number }[];
  kids: { kid: string; rows: number; current: boolean; safeToRemove: boolean }[];
  /** Kids this process holds (env current first). */
  held: string[];
  /** Advisory only; null when Redis was not consulted or failed. */
  heartbeats: DataKeyHeartbeat[] | null;
};

export function safeToRemove(
  epoch: Pick<DataKeyEpochRow, "currentKid"> | null,
  counts: readonly { kid: string; rows: number }[],
  kid: string,
): boolean {
  if (!epoch || epoch.currentKid === kid) return false;
  return counts.every((count) => count.kid !== kid || count.rows === 0);
}

export async function readDataKeyStatus(options: {
  ring: DataKeyring | null;
  client?: Client;
  redis?: HeartbeatRedis | null;
}): Promise<DataKeyStatus> {
  const client = options.client ?? prisma;
  const epoch = await readDataKeyEpoch(client);
  const counts: DataKeyStatus["counts"] = [];
  for (const column of DATA_KEY_COLUMNS)
    for (const row of await column.count(client))
      counts.push({ source: column.source, kid: row.kid, rows: row.rows });
  const held = heldKids(options.ring);
  let heartbeats: DataKeyHeartbeat[] | null = null;
  if (options.redis) {
    try {
      heartbeats = await readDataKeyHeartbeats(options.redis);
    } catch {
      heartbeats = null;
    }
  }
  const kidSet = new Set<string>([...counts.map((count) => count.kid), ...held]);
  if (epoch) {
    kidSet.add(epoch.currentKid);
    if (epoch.previousKid) kidSet.add(epoch.previousKid);
  }
  const kids = [...kidSet].sort().map((kid) => ({
    kid,
    rows: counts.filter((count) => count.kid === kid).reduce((sum, count) => sum + count.rows, 0),
    current: epoch?.currentKid === kid,
    safeToRemove: safeToRemove(epoch, counts, kid),
  }));
  return {
    epoch: epoch
      ? {
          currentKid: epoch.currentKid,
          previousKid: epoch.previousKid,
          epoch: epoch.epoch.toString(),
          switchedAt: epoch.switchedAt.toISOString(),
        }
      : null,
    counts,
    kids,
    held,
    heartbeats,
  };
}
