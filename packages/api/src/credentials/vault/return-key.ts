import { randomBytes } from "node:crypto";
import {
  gcmOpen,
  gcmSeal,
  hkdf32,
  KEY_BYTES,
  NONCE_BYTES,
  randomNonce,
  SALT_BYTES,
  TAG_BYTES,
} from "./aead";
import { encodeAad, KID_HEX, returnKeyId, toBase64Url, X25519_KEY_BYTES } from "./codec";
import { CredentialVaultError } from "./errors";
import { keyForKid, type ReturnKeyWrapKey } from "./keys";
import { generateX25519Private, x25519PublicKey } from "./x25519";

/**
 * Return keys: the X25519 keypairs hosts seal captures to
 * (docs/design/credential-vault.md § Return keys).
 *
 *   kidR    = hex(SHA-256(publicKey))[0:16]
 *   K_rrow  = HKDF-SHA256(ikm = K_rwrap, salt = rwrapSalt (32 random),
 *               info = "wssp:cred-return-key-row:v1")
 *   wrapped = AES-256-GCM(K_rrow, wrapNonce, privateKey,
 *               AAD ["wssp:cred-return-key:v1", rootKid, kidR, b64url(publicKey)])
 *
 * Every wrap and rewrap draws a fresh salt and nonce. Every unwrap derives the
 * public key from the decrypted private key and refuses unless it equals the
 * stored public key and kidR (a DB writer cannot substitute either).
 */

const RETURN_KEY_AAD_LABEL = "wssp:cred-return-key:v1";
const RETURN_KEY_ROW_INFO = "wssp:cred-return-key-row:v1";
const WRAPPED_PRIVATE_BYTES = KEY_BYTES + TAG_BYTES;

export type ReturnKeyPair = {
  kidR: string;
  publicKey: Buffer;
  /** Raw 32-byte X25519 scalar; the caller zeroes it. */
  privateKey: Buffer;
};

/** Columns of `CredentialReturnKey` the vault owns. */
export type WrappedReturnKey = {
  kidR: string;
  publicKey: Buffer;
  wrappedPrivate: Buffer;
  rwrapSalt: Buffer;
  wrapNonce: Buffer;
  rootKid: string;
};

export function createReturnKeyPair(): ReturnKeyPair {
  const privateKey = generateX25519Private();
  const publicKey = x25519PublicKey(privateKey);
  return { kidR: returnKeyId(publicKey), publicKey, privateKey };
}

/** Refuses unless `privateKey` derives `publicKey` and `kidR` names it. */
export function verifyReturnKeyPair(pair: ReturnKeyPair): void {
  if (
    pair.privateKey.byteLength !== X25519_KEY_BYTES ||
    pair.publicKey.byteLength !== X25519_KEY_BYTES ||
    !KID_HEX.test(pair.kidR)
  )
    throw new CredentialVaultError("invalid_key");
  const derived = x25519PublicKey(pair.privateKey);
  if (!derived.equals(pair.publicKey) || returnKeyId(derived) !== pair.kidR)
    throw new CredentialVaultError("return_key_mismatch");
}

function aad(rootKid: string, kidR: string, publicKey: Uint8Array): Buffer {
  return encodeAad([RETURN_KEY_AAD_LABEL, rootKid, kidR, toBase64Url(publicKey)]);
}

export function wrapReturnPrivateKey(pair: ReturnKeyPair, key: ReturnKeyWrapKey): WrappedReturnKey {
  verifyReturnKeyPair(pair);
  const rwrapSalt = randomBytes(SALT_BYTES);
  const wrapNonce = randomNonce();
  const rowKey = hkdf32(key.key, rwrapSalt, RETURN_KEY_ROW_INFO);
  try {
    const wrappedPrivate = gcmSeal(
      rowKey,
      wrapNonce,
      pair.privateKey,
      aad(key.rootKeyId, pair.kidR, pair.publicKey),
    );
    return {
      kidR: pair.kidR,
      publicKey: Buffer.from(pair.publicKey),
      wrappedPrivate,
      rwrapSalt,
      wrapNonce,
      rootKid: key.rootKeyId,
    };
  } finally {
    rowKey.fill(0);
  }
}

/** Decrypt and verify a stored return key. The caller zeroes `privateKey`. */
export function unwrapReturnPrivateKey(
  row: WrappedReturnKey,
  keys: readonly ReturnKeyWrapKey[],
): ReturnKeyPair {
  if (
    row.wrappedPrivate.byteLength !== WRAPPED_PRIVATE_BYTES ||
    row.rwrapSalt.byteLength !== SALT_BYTES ||
    row.wrapNonce.byteLength !== NONCE_BYTES ||
    row.publicKey.byteLength !== X25519_KEY_BYTES ||
    !KID_HEX.test(row.kidR)
  )
    throw new CredentialVaultError("malformed");
  const key = keyForKid(keys, row.rootKid);
  const rowKey = hkdf32(key.key, row.rwrapSalt, RETURN_KEY_ROW_INFO);
  let privateKey: Buffer;
  try {
    privateKey = gcmOpen(
      rowKey,
      row.wrapNonce,
      row.wrappedPrivate,
      aad(row.rootKid, row.kidR, row.publicKey),
    );
  } finally {
    rowKey.fill(0);
  }
  const pair = { kidR: row.kidR, publicKey: Buffer.from(row.publicKey), privateKey };
  try {
    verifyReturnKeyPair(pair);
  } catch (error) {
    privateKey.fill(0);
    throw error instanceof CredentialVaultError && error.code === "invalid_key"
      ? new CredentialVaultError("return_key_mismatch")
      : error;
  }
  return pair;
}

/** Re-encrypt a stored private key under `next` with a fresh salt and nonce. */
export function rewrapReturnPrivateKey(
  row: WrappedReturnKey,
  keys: readonly ReturnKeyWrapKey[],
  next: ReturnKeyWrapKey,
): WrappedReturnKey {
  const pair = unwrapReturnPrivateKey(row, keys);
  try {
    return wrapReturnPrivateKey(pair, next);
  } finally {
    pair.privateKey.fill(0);
  }
}
