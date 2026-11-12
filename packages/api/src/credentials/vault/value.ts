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
import { assertAadId, encodeAad, encodeSeq, SHA256_HEX, sha256 } from "./codec";
import { CredentialVaultError } from "./errors";
import { type DekWrapKey, keyForKid } from "./keys";

/**
 * Stored credential values (docs/design/credential-vault.md § Stored value).
 *
 *   value      = AES-256-GCM(DEK, nonce, plaintext,
 *                  AAD ["wssp:cred-value:v1", userId, credentialId, instanceId,
 *                       storageSeq, kind, policyDigest])
 *   K_row      = HKDF-SHA256(ikm = K_wrap, salt = wrapSalt (32 random),
 *                  info = "wssp:cred-wrap-row:v1")
 *   wrappedDek = AES-256-GCM(K_row, wrapNonce, DEK,
 *                  AAD ["wssp:cred-dek:v1", rootKid, userId, credentialId,
 *                       instanceId, storageSeq, policyDigest])
 *
 * Every DEK encrypts exactly one plaintext and every K_row wraps exactly one
 * DEK, so no long-lived key accumulates GCM invocations. DEKs and K_row are
 * zeroed before return; decrypted plaintext is the caller's to zero.
 */

const VALUE_AAD_LABEL = "wssp:cred-value:v1";
const DEK_AAD_LABEL = "wssp:cred-dek:v1";
const DEK_ROW_INFO = "wssp:cred-wrap-row:v1";
const POLICY_DIGEST_DELIVERIES = ["GUEST", "PROXY"] as const;
export type CredentialDelivery = (typeof POLICY_DIGEST_DELIVERIES)[number];
const SECRET_VERSION_KINDS = [
  "UPLOAD",
  "LOGIN",
  "CAPTURE",
  "CHECKPOINT",
  "RECOVERY",
  "PROMOTED",
  "REPIN",
] as const;
export type SecretVersionKind = (typeof SECRET_VERSION_KINDS)[number];
const WRAPPED_DEK_BYTES = KEY_BYTES + TAG_BYTES;

/**
 * policyDigest = hex(SHA-256(canonical JSON {definitionDigest, delivery})):
 * exactly `{"definitionDigest":"<64 hex>","delivery":"GUEST|PROXY"}`.
 */
export function computePolicyDigest(
  definitionDigest: string,
  delivery: CredentialDelivery,
): string {
  if (!SHA256_HEX.test(definitionDigest) || !POLICY_DIGEST_DELIVERIES.includes(delivery))
    throw new CredentialVaultError("malformed");
  const canonical = `{"definitionDigest":"${definitionDigest}","delivery":"${delivery}"}`;
  return sha256(Buffer.from(canonical, "utf8")).toString("hex");
}

/** Authoritative context of one stored value, rebuilt by the caller from rows. */
export type ValueContext = {
  userId: string;
  credentialId: string;
  instanceId: string;
  storageSeq: bigint | number;
  kind: SecretVersionKind;
  /** Recomputed from the verified definition and delivery, never read from the row. */
  policyDigest: string;
};

/** Columns of `CredentialSecretVersion` that the vault owns. */
export type SealedValue = {
  ciphertext: Buffer;
  nonce: Buffer;
  wrappedDek: Buffer;
  wrapSalt: Buffer;
  wrapNonce: Buffer;
  rootKid: string;
  policyDigest: string;
  sizeBytes: number;
};

export type WrappedDek = Pick<SealedValue, "wrappedDek" | "wrapSalt" | "wrapNonce" | "rootKid">;

function checkContext(ctx: ValueContext): { seq: string } {
  assertAadId(ctx.userId);
  assertAadId(ctx.credentialId);
  assertAadId(ctx.instanceId);
  if (!SECRET_VERSION_KINDS.includes(ctx.kind) || !SHA256_HEX.test(ctx.policyDigest))
    throw new CredentialVaultError("malformed");
  return { seq: encodeSeq(ctx.storageSeq) };
}

function valueAad(ctx: ValueContext, seq: string): Buffer {
  return encodeAad([
    VALUE_AAD_LABEL,
    ctx.userId,
    ctx.credentialId,
    ctx.instanceId,
    seq,
    ctx.kind,
    ctx.policyDigest,
  ]);
}

function dekAad(rootKid: string, ctx: ValueContext, seq: string): Buffer {
  return encodeAad([
    DEK_AAD_LABEL,
    rootKid,
    ctx.userId,
    ctx.credentialId,
    ctx.instanceId,
    seq,
    ctx.policyDigest,
  ]);
}

/** A fresh 32-byte DEK. Used for exactly one encryption; the caller zeroes it. */
function generateDek(): Buffer {
  return randomBytes(KEY_BYTES);
}

/** Wrap a DEK under a fresh salted K_row. Never reuses a salt or nonce. */
function wrapDek(dek: Uint8Array, ctx: ValueContext, key: DekWrapKey): WrappedDek {
  const { seq } = checkContext(ctx);
  if (dek.byteLength !== KEY_BYTES) throw new CredentialVaultError("malformed");
  const wrapSalt = randomBytes(SALT_BYTES);
  const wrapNonce = randomNonce();
  const rowKey = hkdf32(key.key, wrapSalt, DEK_ROW_INFO);
  try {
    const wrappedDek = gcmSeal(rowKey, wrapNonce, dek, dekAad(key.rootKeyId, ctx, seq));
    return { wrappedDek, wrapSalt, wrapNonce, rootKid: key.rootKeyId };
  } finally {
    rowKey.fill(0);
  }
}

/** Unwrap under the configured root named by `rootKid`. The caller zeroes the DEK. */
export function unwrapDek(
  wrapped: WrappedDek,
  ctx: ValueContext,
  keys: readonly DekWrapKey[],
): Buffer {
  const { seq } = checkContext(ctx);
  if (
    wrapped.wrappedDek.byteLength !== WRAPPED_DEK_BYTES ||
    wrapped.wrapSalt.byteLength !== SALT_BYTES ||
    wrapped.wrapNonce.byteLength !== NONCE_BYTES
  )
    throw new CredentialVaultError("malformed");
  const key = keyForKid(keys, wrapped.rootKid);
  const rowKey = hkdf32(key.key, wrapped.wrapSalt, DEK_ROW_INFO);
  try {
    return gcmOpen(
      rowKey,
      wrapped.wrapNonce,
      wrapped.wrappedDek,
      dekAad(wrapped.rootKid, ctx, seq),
    );
  } finally {
    rowKey.fill(0);
  }
}

/** Encrypt one value under a fresh DEK, wrapped under the current K_wrap. */
export function encryptValue(
  plaintext: Uint8Array,
  ctx: ValueContext,
  key: DekWrapKey,
): SealedValue {
  const { seq } = checkContext(ctx);
  const dek = generateDek();
  try {
    const nonce = randomNonce();
    const ciphertext = gcmSeal(dek, nonce, plaintext, valueAad(ctx, seq));
    return {
      ciphertext,
      nonce,
      ...wrapDek(dek, ctx, key),
      policyDigest: ctx.policyDigest,
      sizeBytes: plaintext.byteLength,
    };
  } finally {
    dek.fill(0);
  }
}

/**
 * Decrypt a stored value. `ctx` comes from authoritative rows and a policy
 * digest recomputed from the verified definition; a row whose stored digest
 * differs is refused before any key is touched. The returned plaintext is the
 * caller's to zero (`fill(0)` in `finally`).
 */
export function decryptValue(
  sealed: Omit<SealedValue, "sizeBytes"> & { sizeBytes?: number },
  ctx: ValueContext,
  keys: readonly DekWrapKey[],
): Buffer {
  const { seq } = checkContext(ctx);
  if (sealed.policyDigest !== ctx.policyDigest) throw new CredentialVaultError("context_mismatch");
  if (sealed.nonce.byteLength !== NONCE_BYTES) throw new CredentialVaultError("malformed");
  const dek = unwrapDek(sealed, ctx, keys);
  try {
    const plaintext = gcmOpen(dek, sealed.nonce, sealed.ciphertext, valueAad(ctx, seq));
    if (sealed.sizeBytes !== undefined && sealed.sizeBytes !== plaintext.byteLength) {
      plaintext.fill(0);
      throw new CredentialVaultError("context_mismatch");
    }
    return plaintext;
  } finally {
    dek.fill(0);
  }
}

/** Re-wrap a value's DEK under `next` with a new salt and nonce; the value is untouched. */
export function rewrapDek(
  wrapped: WrappedDek,
  ctx: ValueContext,
  keys: readonly DekWrapKey[],
  next: DekWrapKey,
): WrappedDek {
  const dek = unwrapDek(wrapped, ctx, keys);
  try {
    return wrapDek(dek, ctx, next);
  } finally {
    dek.fill(0);
  }
}
