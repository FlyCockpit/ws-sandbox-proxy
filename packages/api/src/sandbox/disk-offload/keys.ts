import { randomBytes } from "node:crypto";
import type { Prisma } from "@wssp/db";
import {
  gcmOpen,
  gcmSeal,
  hkdf32,
  KEY_BYTES,
  randomNonce,
  SALT_BYTES,
} from "../../credentials/vault/aead";
import {
  type DataKeyring,
  type DataSubkey,
  deriveSubkeys,
  readDataKeyring,
} from "../../crypto/data-key";
import { fenceWriteKey } from "../../crypto/data-key-epoch";
import { encodeHmacContext } from "../hmac-context";

/**
 * Disk offload data keys.
 *
 * Every upload session draws a fresh 32-byte DEK. The DEK is wrapped directly
 * under the root-derived purpose key K_diskwrap (`sandbox-disk-dek-wrap:v1`),
 * through a per-row key
 *
 *   K_row = HKDF-SHA256(K_diskwrap, salt = wrapSalt (32 random), info = "wssp:sandbox-disk-row:v1")
 *
 * and AES-256-GCM with a random nonce and the AAD
 *
 *   LP("wssp:sandbox-disk-dek:v1") ‖ LP(rootKid) ‖ LP(userId) ‖ LP(sandboxId)
 *     ‖ LP(offloadId) ‖ LP(seq) ‖ LP(sessionId)
 *
 * (`encodeHmacContext`). A wrap therefore opens only for its own owner,
 * sandbox, offload attempt, sequence and upload session, under its own root.
 *
 * A disk session holds a wrap only while OPEN; Complete copies it to the
 * offload row with `completedSessionId`, so every later unwrap rebuilds the
 * AAD from the offload row. `IMAGE_STORE_ENCRYPTION` has no effect here:
 * disks are always encrypted, and template keys (`imageMasterKey`) are a
 * different store.
 *
 * WRITE-ONLY: this file is the only reader and writer of the wrap columns
 * (`wrappedKey`, `wrapSalt`, `wrapNonce` on `SandboxDiskOffload`; `wrappedKey`,
 * `wrappedKeyNonce`, `wrapSalt` on disk upload sessions). The projection lint
 * (`keys.test.ts`) fails on any other selection. A key leaves the server only
 * in the `encryption` field of one upload or fetch grant.
 */

/** HKDF purpose of K_diskwrap. Part of the derivation: never rename. */
export const DISK_DEK_WRAP_PURPOSE = "sandbox-disk-dek-wrap:v1";
const DISK_ROW_INFO = "wssp:sandbox-disk-row:v1";
const DISK_AAD_DOMAIN = "wssp:sandbox-disk-dek:v1";
/** The only record format of a stored disk (the template `aes256gcm-r1` records). */
export const DISK_ENCRYPTION_SCHEME = "aes256gcm-r1";

export type DiskWrapKey = DataSubkey<typeof DISK_DEK_WRAP_PURPOSE>;
export type DiskWrapKeys = { current: DiskWrapKey; all: readonly DiskWrapKey[] };

export type DiskKeyErrorCode =
  | "key_unavailable"
  | "authentication_failed"
  | "malformed"
  | "not_stored"
  | "not_terminal";

/** Carries a code only; never a key, id or row. */
export class DiskKeyError extends Error {
  readonly code: DiskKeyErrorCode;
  constructor(code: DiskKeyErrorCode) {
    super(`disk offload key: ${code}`);
    this.name = "DiskKeyError";
    this.code = code;
  }
}

export function deriveDiskWrapKeys(ring: DataKeyring): DiskWrapKeys {
  return deriveSubkeys(ring, DISK_DEK_WRAP_PURPOSE);
}

/** K_diskwrap from the environment, or null without `DATA_ENCRYPTION_KEY`. */
export function readDiskWrapKeys(): DiskWrapKeys | null {
  const ring = readDataKeyring();
  return ring ? deriveDiskWrapKeys(ring) : null;
}

/**
 * The write fence for a disk wrap (like the vault writers): reads
 * `data_key_epoch` FOR SHARE inside `tx` and returns the key the epoch names,
 * or throws the retryable `DataKeyStaleWriter`. Call before every wrap write.
 */
export async function fenceDiskWrapKey(
  tx: Prisma.TransactionClient,
  keys: DiskWrapKeys | null = readDiskWrapKeys(),
): Promise<DiskWrapKey> {
  if (!keys) throw new DiskKeyError("key_unavailable");
  return fenceWriteKey(tx, keys.all);
}

/** A fresh 32-byte disk DEK for one upload session. The caller zeroes it. */
export function generateDiskDek(): Buffer {
  return randomBytes(KEY_BYTES);
}

/** The identity one wrap is bound to (every AAD field but the root kid). */
export type DiskDekContext = {
  userId: string;
  sandboxId: string;
  offloadId: string;
  seq: number;
  /** The upload session id, generated in code before the wrap (S10/R4). */
  sessionId: string;
};

export type DiskWrap = {
  wrappedKey: Buffer;
  wrapSalt: Buffer;
  wrapNonce: Buffer;
  rootKid: string;
};

const KID = /^[0-9a-f]{16}$/;
/** Every field is length-prefixed, so any non-empty id is unambiguous. */
const idField = (value: unknown) =>
  typeof value === "string" && value.length > 0 && value.length <= 256;

/** The AAD of one wrap. Exported for vectors; it carries no secret. */
export function diskDekAad(rootKid: string, context: DiskDekContext): Buffer {
  if (
    !KID.test(rootKid) ||
    !idField(context.userId) ||
    !idField(context.sandboxId) ||
    !idField(context.offloadId) ||
    !idField(context.sessionId) ||
    !Number.isSafeInteger(context.seq) ||
    context.seq < 0
  )
    throw new DiskKeyError("malformed");
  return encodeHmacContext([
    DISK_AAD_DOMAIN,
    rootKid,
    context.userId,
    context.sandboxId,
    context.offloadId,
    String(context.seq),
    context.sessionId,
  ]);
}

function withRowKey<T>(key: DiskWrapKey, salt: Uint8Array, work: (rowKey: Buffer) => T): T {
  const rowKey = hkdf32(key.key, salt, DISK_ROW_INFO);
  try {
    return work(rowKey);
  } finally {
    rowKey.fill(0);
  }
}

/** Wrap one session DEK under `key` (the fenced writer key). */
export function wrapDiskDek(
  key: DiskWrapKey,
  input: DiskDekContext & { dek: Uint8Array },
): DiskWrap {
  if (input.dek.byteLength !== KEY_BYTES) throw new DiskKeyError("malformed");
  const aad = diskDekAad(key.rootKeyId, input);
  const wrapSalt = randomBytes(SALT_BYTES);
  const wrapNonce = randomNonce();
  const wrappedKey = withRowKey(key, wrapSalt, (rowKey) =>
    gcmSeal(rowKey, wrapNonce, input.dek, aad),
  );
  return { wrappedKey, wrapSalt, wrapNonce, rootKid: key.rootKeyId };
}

/**
 * Open one wrap against the context the server rebuilt from rows. Any
 * mismatch (a tampered AAD field, column or root) is `authentication_failed`;
 * no configured root for the row's kid is `key_unavailable`. The caller
 * zeroes the DEK.
 */
export function unwrapDiskDek(
  wrap: DiskWrap,
  context: DiskDekContext,
  keys: readonly DiskWrapKey[] | undefined = readDiskWrapKeys()?.all,
): Buffer {
  const key = keys?.find((candidate) => candidate.rootKeyId === wrap.rootKid);
  if (!key) throw new DiskKeyError("key_unavailable");
  const aad = diskDekAad(wrap.rootKid, context);
  if (wrap.wrapSalt.byteLength !== SALT_BYTES) throw new DiskKeyError("malformed");
  try {
    return withRowKey(key, wrap.wrapSalt, (rowKey) =>
      gcmOpen(rowKey, wrap.wrapNonce, wrap.wrappedKey, aad),
    );
  } catch {
    throw new DiskKeyError("authentication_failed");
  }
}

// --- Rows -------------------------------------------------------------------

/** The offload columns the key paths need. Used only inside this file. */
const OFFLOAD_KEY_SELECT = {
  id: true,
  userId: true,
  sandboxId: true,
  seq: true,
  completedSessionId: true,
  encryption: true,
  wrappedKey: true,
  wrapSalt: true,
  wrapNonce: true,
  rootKid: true,
} satisfies Prisma.SandboxDiskOffloadSelect;
export type DiskOffloadKeyRow = Prisma.SandboxDiskOffloadGetPayload<{
  select: typeof OFFLOAD_KEY_SELECT;
}>;

/**
 * The object key of a completed offload: the single unwrap path of disk
 * verify and the restore fetch grant. The AAD is rebuilt from the offload row
 * and its `completedSessionId`. The caller zeroes the DEK.
 */
export function diskObjectKey(
  row: DiskOffloadKeyRow,
  keys: readonly DiskWrapKey[] | undefined = readDiskWrapKeys()?.all,
): Buffer {
  if (
    !row.completedSessionId ||
    row.encryption !== DISK_ENCRYPTION_SCHEME ||
    !row.wrappedKey ||
    !row.wrapSalt ||
    !row.wrapNonce ||
    !row.rootKid
  )
    throw new DiskKeyError("not_stored");
  return unwrapDiskDek(
    {
      wrappedKey: Buffer.from(row.wrappedKey),
      wrapSalt: Buffer.from(row.wrapSalt),
      wrapNonce: Buffer.from(row.wrapNonce),
      rootKid: row.rootKid,
    },
    {
      userId: row.userId,
      sandboxId: row.sandboxId,
      offloadId: row.id,
      seq: row.seq,
      sessionId: row.completedSessionId,
    },
    keys,
  );
}

/** Loads one offload's key columns (no lock) and unwraps its object key. */
export async function loadDiskObjectKey(
  client: Pick<Prisma.TransactionClient, "sandboxDiskOffload">,
  offloadId: string,
  keys: readonly DiskWrapKey[] | undefined = readDiskWrapKeys()?.all,
): Promise<Buffer> {
  const row = await client.sandboxDiskOffload.findUnique({
    where: { id: offloadId },
    select: OFFLOAD_KEY_SELECT,
  });
  if (!row) throw new DiskKeyError("not_stored");
  return diskObjectKey(row, keys);
}

/**
 * The DEK of a disk session that is still OPEN (an upload resume re-grant),
 * from the session's own wrap. The AAD's session field is the session id.
 */
export async function loadOpenDiskSessionKey(
  client: Pick<Prisma.TransactionClient, "sandboxImageUploadSession">,
  sessionId: string,
  keys: readonly DiskWrapKey[] | undefined = readDiskWrapKeys()?.all,
): Promise<Buffer> {
  const session = await client.sandboxImageUploadSession.findFirst({
    where: { id: sessionId, state: "OPEN", diskOffloadId: { not: null } },
    select: {
      id: true,
      encryption: true,
      wrappedKey: true,
      wrappedKeyNonce: true,
      wrapSalt: true,
      keyId: true,
      DiskOffload: { select: { id: true, userId: true, sandboxId: true, seq: true } },
    },
  });
  const offload = session?.DiskOffload;
  // A disk session's keyId is the root kid its wrap is sealed under.
  const rootKid = session?.keyId;
  if (
    !session ||
    !offload ||
    session.encryption !== DISK_ENCRYPTION_SCHEME ||
    !session.wrappedKey ||
    !session.wrappedKeyNonce ||
    !session.wrapSalt ||
    !rootKid
  )
    throw new DiskKeyError("not_stored");
  return unwrapDiskDek(
    {
      wrappedKey: Buffer.from(session.wrappedKey),
      wrapSalt: Buffer.from(session.wrapSalt),
      wrapNonce: Buffer.from(session.wrappedKeyNonce),
      rootKid,
    },
    {
      userId: offload.userId,
      sandboxId: offload.sandboxId,
      offloadId: offload.id,
      seq: offload.seq,
      sessionId: session.id,
    },
    keys,
  );
}

/**
 * The session columns that carry a fresh disk session's wrap, for the begin
 * insert (`data: { ...(await newDiskSessionWrap(tx, context, dek)), … }`).
 * Takes the epoch FOR SHARE first: call inside the inserting transaction.
 */
export async function newDiskSessionWrap(
  tx: Prisma.TransactionClient,
  context: DiskDekContext,
  dek: Uint8Array,
  keys: DiskWrapKeys | null = readDiskWrapKeys(),
) {
  const key = await fenceDiskWrapKey(tx, keys);
  const wrap = wrapDiskDek(key, { ...context, dek });
  return {
    encryption: DISK_ENCRYPTION_SCHEME,
    wrappedKey: new Uint8Array(wrap.wrappedKey),
    wrappedKeyNonce: new Uint8Array(wrap.wrapNonce),
    wrapSalt: new Uint8Array(wrap.wrapSalt),
    keyId: wrap.rootKid,
  };
}

/**
 * Complete's two-row CAS, the only move of a wrap from
 * a session to its offload. In `tx`, after the epoch FOR SHARE:
 *
 * 1. the offload `{id, state: UPLOADING, completedSessionId: null}` takes the
 *    OPEN session's wrap, `completedSessionId`, `objectKey`, `storedBytes`
 *    and `partSize`, and moves to VERIFYING;
 * 2. the session `{id, state: OPEN, liveDiskOffloadId: offloadId}` moves to
 *    COMPLETE with `liveDiskOffloadId` and its wrap nulled.
 *
 * Returns false (nothing written) when step 1 matches no row; throws, so the
 * caller's transaction rolls back, if step 2 then fails to match exactly one.
 */
export async function completeDiskSession(
  tx: Prisma.TransactionClient,
  input: { offloadId: string; sessionId: string },
): Promise<boolean> {
  await tx.$queryRaw`SELECT 1 FROM data_key_epoch WHERE id = 1 FOR SHARE`;
  const moved = await tx.$executeRaw`UPDATE sandbox_disk_offload o SET state = 'VERIFYING',
      "completedSessionId" = s.id, "objectKey" = s."objectKey", "storedBytes" = s."storedBytes",
      "partSize" = s."partSize", encryption = s.encryption, "wrappedKey" = s."wrappedKey",
      "wrapSalt" = s."wrapSalt", "wrapNonce" = s."wrappedKeyNonce", "rootKid" = s."keyId",
      "updatedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
    FROM sandbox_image_upload_session s
    WHERE o.id = ${input.offloadId} AND o.state = 'UPLOADING' AND o."completedSessionId" IS NULL
      AND s.id = ${input.sessionId} AND s.state = 'OPEN' AND s."liveDiskOffloadId" = o.id
      AND s.encryption = ${DISK_ENCRYPTION_SCHEME} AND s."wrappedKey" IS NOT NULL`;
  if (moved !== 1) return false;
  const closed = await tx.$executeRaw`UPDATE sandbox_image_upload_session SET state = 'COMPLETE',
      "liveDiskOffloadId" = NULL, "endReason" = 'uploaded', encryption = NULL, "wrappedKey" = NULL,
      "wrappedKeyNonce" = NULL, "wrapSalt" = NULL, "keyId" = NULL,
      "updatedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
    WHERE id = ${input.sessionId} AND state = 'OPEN' AND "liveDiskOffloadId" = ${input.offloadId}`;
  if (closed !== 1) throw new DiskKeyError("not_stored");
  return true;
}

/**
 * Supersede one OPEN disk session (S1, S3): ABORTED with `liveDiskOffloadId`
 * and its wrap nulled in one statement, so `sandbox_image_upload_session_disk_key`
 * holds at every statement. Returns whether it was still OPEN.
 */
export async function abortDiskSession(
  tx: Prisma.TransactionClient,
  sessionId: string,
  reason: string,
): Promise<boolean> {
  const aborted = await tx.$executeRaw`UPDATE sandbox_image_upload_session SET state = 'ABORTED',
      "liveDiskOffloadId" = NULL, "endReason" = ${reason}, encryption = NULL, "wrappedKey" = NULL,
      "wrappedKeyNonce" = NULL, "wrapSalt" = NULL, "keyId" = NULL,
      "updatedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
    WHERE id = ${sessionId} AND state = 'OPEN' AND "diskOffloadId" IS NOT NULL`;
  return aborted === 1;
}

// --- Shredder ---------------------------------------------------------------

/**
 * The one shredder (S3, T13). In `tx`, after the caller moved the offload to
 * a terminal state (a STORED/EVICTING row keeps its wrap by CHECK):
 *
 * 1. takes `data_key_epoch` FOR SHARE (like every wrap writer);
 * 2. aborts any OPEN session of the offload, state and wrap in one statement
 *    (`sandbox_image_upload_session_disk_key` holds at every statement);
 * 3. nulls any session wrap still present for the offload (defence in depth);
 * 4. nulls the offload's wrap and sets `shreddedAt` (its only writer).
 *
 * Returns the sessions it aborted (their transfers and multipart uploads are
 * the caller's to end after commit), or null when the row does not exist.
 * Throws `not_terminal` for a STORED/EVICTING row. Idempotent.
 */
export async function shredOffloadKeys(
  tx: Prisma.TransactionClient,
  offloadId: string,
): Promise<{ abortedSessions: { id: string; transferId: string }[] } | null> {
  await tx.$queryRaw`SELECT 1 FROM data_key_epoch WHERE id = 1 FOR SHARE`;
  const [row] = await tx.$queryRaw<{ state: string }[]>`SELECT state::text AS state
    FROM sandbox_disk_offload WHERE id = ${offloadId} FOR UPDATE`;
  if (!row) return null;
  if (row.state === "STORED" || row.state === "EVICTING") throw new DiskKeyError("not_terminal");
  const abortedSessions = await tx.$queryRaw<{ id: string; transferId: string }[]>`
    UPDATE sandbox_image_upload_session SET state = 'ABORTED', "liveDiskOffloadId" = NULL,
      "endReason" = COALESCE("endReason", 'shredded'), encryption = NULL, "wrappedKey" = NULL,
      "wrappedKeyNonce" = NULL, "wrapSalt" = NULL, "keyId" = NULL,
      "updatedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
    WHERE "diskOffloadId" = ${offloadId} AND state = 'OPEN'
    RETURNING id, "transferId"`;
  await tx.$executeRaw`UPDATE sandbox_image_upload_session SET encryption = NULL,
      "wrappedKey" = NULL, "wrappedKeyNonce" = NULL, "wrapSalt" = NULL, "keyId" = NULL,
      "updatedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
    WHERE "diskOffloadId" = ${offloadId} AND "wrappedKey" IS NOT NULL`;
  await tx.$executeRaw`UPDATE sandbox_disk_offload SET "wrappedKey" = NULL, "wrapSalt" = NULL,
      "wrapNonce" = NULL, "shreddedAt" = COALESCE("shreddedAt", (clock_timestamp() AT TIME ZONE 'UTC')),
      "updatedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
    WHERE id = ${offloadId}`;
  return { abortedSessions };
}

// --- Data-key status and rewrap sources -------------------------------------

type KidCount = { kid: string; rows: number };
type CountClient = Pick<Prisma.TransactionClient, "$queryRaw">;

/** `data-key-status` source: live offload wraps by root kid (shredded rows hold none). */
export function countDiskOffloadWrapKids(db: CountClient, cap: number) {
  return db.$queryRaw<KidCount[]>`SELECT "rootKid" AS kid, count(*)::int AS rows
    FROM sandbox_disk_offload WHERE "wrappedKey" IS NOT NULL
    GROUP BY 1 ORDER BY 1 LIMIT ${cap}`;
}

/** `data-key-status` source: wraps of OPEN disk sessions (a removal racing an upload). */
export function countDiskSessionWrapKids(db: CountClient, cap: number) {
  return db.$queryRaw<KidCount[]>`SELECT "keyId" AS kid, count(*)::int AS rows
    FROM sandbox_image_upload_session
    WHERE "diskOffloadId" IS NOT NULL AND "wrappedKey" IS NOT NULL
    GROUP BY 1 ORDER BY 1 LIMIT ${cap}`;
}

export type DiskRewrapCursor = { offload: string | null; session: string | null };

/**
 * Rewrap batch (credential maintenance tick, `credentials/rewrap.ts`): every
 * offload and OPEN disk-session wrap under a kid other than `writeKey`'s gets
 * a fresh salt and nonce under `writeKey`, bound to the new kid. The caller
 * holds the epoch FOR SHARE; rows are taken FOR UPDATE SKIP LOCKED in id
 * order. A row no configured root opens is counted and skipped.
 */
export async function rewrapDiskKeyBatch(
  tx: Prisma.TransactionClient,
  writeKey: DiskWrapKey,
  cursor: DiskRewrapCursor,
  limit: number,
  keys: readonly DiskWrapKey[] | undefined = readDiskWrapKeys()?.all,
): Promise<{ rewrapped: number; failed: number; scanned: number; next: DiskRewrapCursor }> {
  type WrapRow = {
    id: string;
    offloadId: string;
    userId: string;
    sandboxId: string;
    seq: number;
    sessionId: string;
    wrappedKey: Uint8Array;
    wrapSalt: Uint8Array;
    wrapNonce: Uint8Array;
    rootKid: string;
  };
  const offloads = await tx.$queryRaw<WrapRow[]>`SELECT o.id, o.id AS "offloadId", o."userId",
      o."sandboxId", o.seq, o."completedSessionId" AS "sessionId", o."wrappedKey", o."wrapSalt",
      o."wrapNonce", o."rootKid"
    FROM sandbox_disk_offload o
    WHERE o."wrappedKey" IS NOT NULL AND o."rootKid" <> ${writeKey.rootKeyId}
      AND o.id > ${cursor.offload ?? ""}
    ORDER BY o.id LIMIT ${limit} FOR UPDATE OF o SKIP LOCKED`;
  const sessions = await tx.$queryRaw<WrapRow[]>`SELECT s.id, o.id AS "offloadId", o."userId",
      o."sandboxId", o.seq, s.id AS "sessionId", s."wrappedKey", s."wrapSalt",
      s."wrappedKeyNonce" AS "wrapNonce", s."keyId" AS "rootKid"
    FROM sandbox_image_upload_session s JOIN sandbox_disk_offload o ON o.id = s."diskOffloadId"
    WHERE s."wrappedKey" IS NOT NULL AND s."keyId" <> ${writeKey.rootKeyId}
      AND s.id > ${cursor.session ?? ""}
    ORDER BY s.id LIMIT ${limit} FOR UPDATE OF s SKIP LOCKED`;
  let rewrapped = 0;
  let failed = 0;
  const rewrap = (row: WrapRow): DiskWrap | null => {
    let dek: Buffer | undefined;
    try {
      const context = {
        userId: row.userId,
        sandboxId: row.sandboxId,
        offloadId: row.offloadId,
        seq: row.seq,
        sessionId: row.sessionId,
      };
      dek = unwrapDiskDek(
        {
          wrappedKey: Buffer.from(row.wrappedKey),
          wrapSalt: Buffer.from(row.wrapSalt),
          wrapNonce: Buffer.from(row.wrapNonce),
          rootKid: row.rootKid,
        },
        context,
        keys,
      );
      return wrapDiskDek(writeKey, { ...context, dek });
    } catch {
      // Unopenable under every configured root: counted, never logged with ids.
      failed++;
      return null;
    } finally {
      dek?.fill(0);
    }
  };
  for (const row of offloads) {
    const next = rewrap(row);
    if (!next) continue;
    const updated = await tx.sandboxDiskOffload.updateMany({
      where: { id: row.id, rootKid: row.rootKid, shreddedAt: null },
      data: {
        wrappedKey: new Uint8Array(next.wrappedKey),
        wrapSalt: new Uint8Array(next.wrapSalt),
        wrapNonce: new Uint8Array(next.wrapNonce),
        rootKid: next.rootKid,
      },
    });
    rewrapped += updated.count;
  }
  for (const row of sessions) {
    const next = rewrap(row);
    if (!next) continue;
    const updated = await tx.sandboxImageUploadSession.updateMany({
      where: { id: row.id, keyId: row.rootKid, state: "OPEN" },
      data: {
        wrappedKey: new Uint8Array(next.wrappedKey),
        wrapSalt: new Uint8Array(next.wrapSalt),
        wrappedKeyNonce: new Uint8Array(next.wrapNonce),
        keyId: next.rootKid,
      },
    });
    rewrapped += updated.count;
  }
  return {
    rewrapped,
    failed,
    scanned: Math.max(offloads.length, sessions.length),
    next: {
      offload: offloads.length < limit ? null : (offloads.at(-1)?.id ?? null),
      session: sessions.length < limit ? null : (sessions.at(-1)?.id ?? null),
    },
  };
}
