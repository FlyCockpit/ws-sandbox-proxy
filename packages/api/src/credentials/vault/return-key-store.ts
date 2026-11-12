import type { Prisma } from "@wssp/db";
import { fenceWriteKey } from "../../crypto/data-key-epoch";
import { openEnvelope, type ParsedEnvelope } from "./envelope";
import { CredentialVaultError } from "./errors";
import { type ReturnKeyWrapKey, readVaultKeys } from "./keys";
import {
  createReturnKeyPair,
  rewrapReturnPrivateKey,
  unwrapReturnPrivateKey,
  type WrappedReturnKey,
  wrapReturnPrivateKey,
} from "./return-key";
import type { ReturnAad } from "./sealed-box";
import { CredentialVaultUnavailable } from "./store";

/**
 * The only module that writes or reads `CredentialReturnKey.wrappedPrivate`
 * (and its salt/nonce). Private keys exist only inside these functions and
 * are zeroed before they return.
 */

type Tx = Prisma.TransactionClient;

const wrappedSelect = {
  kidR: true,
  publicKey: true,
  wrappedPrivate: true,
  rwrapSalt: true,
  wrapNonce: true,
  rootKid: true,
  destroyedAt: true,
} satisfies Prisma.CredentialReturnKeySelect;

/** Creates and stores a fresh return keypair at `epoch`; returns its public half. */
export async function insertReturnKey(
  tx: Tx,
  epoch: bigint,
): Promise<{ kidR: string; publicKey: Buffer }> {
  const keys = readVaultKeys();
  if (!keys) throw new CredentialVaultUnavailable();
  // The data-key epoch fence (§4.6): wrap under the kid the DB names.
  const writeKey = await fenceWriteKey(tx, keys.returnKey.all);
  const pair = createReturnKeyPair();
  try {
    const wrapped = wrapReturnPrivateKey(pair, writeKey);
    await tx.credentialReturnKey.create({
      data: {
        kidR: wrapped.kidR,
        epoch,
        publicKey: new Uint8Array(wrapped.publicKey),
        wrappedPrivate: new Uint8Array(wrapped.wrappedPrivate),
        rwrapSalt: new Uint8Array(wrapped.rwrapSalt),
        wrapNonce: new Uint8Array(wrapped.wrapNonce),
        rootKid: wrapped.rootKid,
      },
      select: { kidR: true },
    });
    return { kidR: pair.kidR, publicKey: Buffer.from(pair.publicKey) };
  } finally {
    pair.privateKey.fill(0);
  }
}

export type OpenCaptureResult =
  | { ok: true; plaintext: Buffer }
  | { ok: false; reason: "unknown_kid" | "context_mismatch" | "decrypt_failed" | "unavailable" };

/**
 * Commit-fence step 9: open an envelope sealed to `kidR` against the AAD the
 * server rebuilt from rows. A missing or destroyed key is `unknown_kid`; a
 * root key this process lacks is `unavailable` (the caller acks DEFERRED).
 * The caller zeroes `plaintext`.
 */
export async function openCaptureEnvelope(
  tx: Tx,
  envelope: ParsedEnvelope,
  expected: ReturnAad,
): Promise<OpenCaptureResult> {
  const keys = readVaultKeys();
  if (!keys) return { ok: false, reason: "unavailable" };
  const row = await tx.credentialReturnKey.findUnique({
    where: { kidR: envelope.header.kidR },
    select: wrappedSelect,
  });
  if (!row || row.destroyedAt) return { ok: false, reason: "unknown_kid" };
  let pair: ReturnType<typeof unwrapReturnPrivateKey>;
  try {
    pair = unwrapReturnPrivateKey(
      {
        kidR: row.kidR,
        publicKey: Buffer.from(row.publicKey),
        wrappedPrivate: Buffer.from(row.wrappedPrivate),
        rwrapSalt: Buffer.from(row.rwrapSalt),
        wrapNonce: Buffer.from(row.wrapNonce),
        rootKid: row.rootKid,
      },
      keys.returnKey.all,
    );
  } catch (error) {
    if (error instanceof CredentialVaultError && error.code === "key_unavailable")
      return { ok: false, reason: "unavailable" };
    throw error;
  }
  try {
    return { ok: true, plaintext: openEnvelope(envelope, expected, pair) };
  } catch (error) {
    if (!(error instanceof CredentialVaultError)) throw error;
    return {
      ok: false,
      reason: error.code === "context_mismatch" ? "context_mismatch" : "decrypt_failed",
    };
  } finally {
    pair.privateKey.fill(0);
  }
}

/** Destruction (gated by the caller): the wrapped private key is overwritten, never recoverable. */
export async function destroyReturnKeyMaterial(tx: Tx, kidR: string): Promise<void> {
  await tx.credentialReturnKey.update({
    where: { kidR },
    data: { destroyedAt: new Date(), wrappedPrivate: new Uint8Array(0) },
    select: { kidR: true },
  });
}

/**
 * Rewrap batch (§4.6): re-encrypt the PRIVATE key of up to `limit` live return
 * keys whose `rootKid` is not `writeKey`'s, each with a fresh `rwrapSalt` and
 * nonce (§4.2); the unwrap re-derives and checks the public key first. A
 * destroyed key is never selected: its `wrappedPrivate` is empty and stays
 * empty (it holds nothing under any root, so it is not counted either). The
 * caller holds the data-key epoch row FOR SHARE and got `writeKey` from it.
 * Rows are taken FOR UPDATE SKIP LOCKED after `afterKidR`; each update
 * re-checks the old kid and that the key is still live.
 */
export async function rewrapReturnKeyBatch(
  tx: Tx,
  writeKey: ReturnKeyWrapKey,
  afterKidR: string | null,
  limit: number,
): Promise<{ rewrapped: number; failed: number; scanned: number; last: string | null }> {
  const keys = readVaultKeys();
  if (!keys) throw new CredentialVaultUnavailable();
  const rows = await tx.$queryRaw<
    {
      kidR: string;
      publicKey: Uint8Array;
      wrappedPrivate: Uint8Array;
      rwrapSalt: Uint8Array;
      wrapNonce: Uint8Array;
      rootKid: string;
    }[]
  >`SELECT "kidR", "publicKey", "wrappedPrivate", "rwrapSalt", "wrapNonce", "rootKid"
    FROM credential_return_key
    WHERE "rootKid" <> ${writeKey.rootKeyId} AND "destroyedAt" IS NULL AND "kidR" > ${afterKidR ?? ""}
    ORDER BY "kidR" LIMIT ${limit} FOR UPDATE SKIP LOCKED`;
  let rewrapped = 0;
  let failed = 0;
  for (const row of rows) {
    let next: WrappedReturnKey;
    try {
      next = rewrapReturnPrivateKey(
        {
          kidR: row.kidR,
          publicKey: Buffer.from(row.publicKey),
          wrappedPrivate: Buffer.from(row.wrappedPrivate),
          rwrapSalt: Buffer.from(row.rwrapSalt),
          wrapNonce: Buffer.from(row.wrapNonce),
          rootKid: row.rootKid,
        },
        keys.returnKey.all,
        writeKey,
      );
    } catch {
      failed++;
      continue;
    }
    const updated = await tx.credentialReturnKey.updateMany({
      where: { kidR: row.kidR, rootKid: row.rootKid, destroyedAt: null },
      data: {
        wrappedPrivate: new Uint8Array(next.wrappedPrivate),
        rwrapSalt: new Uint8Array(next.rwrapSalt),
        wrapNonce: new Uint8Array(next.wrapNonce),
        rootKid: next.rootKid,
      },
    });
    rewrapped += updated.count;
  }
  return { rewrapped, failed, scanned: rows.length, last: rows.at(-1)?.kidR ?? null };
}
