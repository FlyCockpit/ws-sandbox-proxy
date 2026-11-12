import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import { CredentialVaultError } from "./errors";

export const KEY_BYTES = 32;
export const NONCE_BYTES = 12;
export const TAG_BYTES = 16;
export const SALT_BYTES = 32;

/** HKDF-SHA256 to 32 bytes. The caller zeroes the result. */
export function hkdf32(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array | string): Buffer {
  return Buffer.from(hkdfSync("sha256", ikm, salt, info, KEY_BYTES));
}

export function randomNonce(): Buffer {
  return randomBytes(NONCE_BYTES);
}

/** AES-256-GCM: returns `ciphertext ‖ tag`. */
export function gcmSeal(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Buffer {
  if (key.byteLength !== KEY_BYTES || nonce.byteLength !== NONCE_BYTES)
    throw new CredentialVaultError("malformed");
  const cipher = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: TAG_BYTES });
  cipher.setAAD(aad);
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

/**
 * Opens `ciphertext ‖ tag`. Any failure (including a body shorter than the
 * tag) is `authentication_failed`; nothing is returned before the tag verifies.
 */
export function gcmOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  body: Uint8Array,
  aad: Uint8Array,
): Buffer {
  if (key.byteLength !== KEY_BYTES || nonce.byteLength !== NONCE_BYTES)
    throw new CredentialVaultError("malformed");
  if (body.byteLength < TAG_BYTES) throw new CredentialVaultError("authentication_failed");
  const split = body.byteLength - TAG_BYTES;
  const parts: Buffer[] = [];
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, nonce, { authTagLength: TAG_BYTES });
    decipher.setAAD(aad);
    decipher.setAuthTag(body.subarray(split));
    parts.push(decipher.update(body.subarray(0, split)));
    parts.push(decipher.final());
    return Buffer.concat(parts);
  } catch {
    throw new CredentialVaultError("authentication_failed");
  } finally {
    // Unverified (or copied) plaintext chunks never leave this function.
    for (const part of parts) part.fill(0);
  }
}
