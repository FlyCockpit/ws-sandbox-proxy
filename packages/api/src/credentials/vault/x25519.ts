import {
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  type KeyObject,
  randomBytes,
} from "node:crypto";
import { assertCanonicalX25519Public, X25519_KEY_BYTES } from "./codec";
import { CredentialVaultError } from "./errors";

// Fixed DER prefixes for raw 32-byte X25519 keys (RFC 8410).
const PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

/** A fresh 32-byte X25519 private scalar (clamped by the curve operation). */
export function generateX25519Private(): Buffer {
  return randomBytes(X25519_KEY_BYTES);
}

function privateKeyObject(privateKey: Uint8Array): KeyObject {
  if (privateKey.byteLength !== X25519_KEY_BYTES) throw new CredentialVaultError("invalid_key");
  const der = Buffer.concat([PKCS8_PREFIX, privateKey]);
  try {
    return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  } finally {
    der.fill(0);
  }
}

function publicKeyObject(publicKey: Uint8Array): KeyObject {
  assertCanonicalX25519Public(publicKey);
  return createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, publicKey]),
    format: "der",
    type: "spki",
  });
}

/** The raw 32-byte public key of a raw private scalar. */
export function x25519PublicKey(privateKey: Uint8Array): Buffer {
  const spki = createPublicKey(privateKeyObject(privateKey)).export({
    format: "der",
    type: "spki",
  });
  return Buffer.from(spki.subarray(SPKI_PREFIX.byteLength));
}

/**
 * X25519(privateKey, publicKey). Refuses a non-canonical peer key and an
 * all-zero shared secret (RFC 9180 §7.1.4 / RFC 7748 §6.1). The caller zeroes
 * the result.
 */
export function x25519(privateKey: Uint8Array, publicKey: Uint8Array): Buffer {
  let shared: Buffer;
  try {
    shared = diffieHellman({
      privateKey: privateKeyObject(privateKey),
      publicKey: publicKeyObject(publicKey),
    });
  } catch {
    // OpenSSL itself refuses an all-zero result; either way the key is unusable.
    throw new CredentialVaultError("invalid_key");
  }
  if (shared.byteLength !== X25519_KEY_BYTES || shared.every((byte) => byte === 0)) {
    shared.fill(0);
    throw new CredentialVaultError("invalid_key");
  }
  return shared;
}
