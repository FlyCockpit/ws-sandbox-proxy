import { createHash } from "node:crypto";
import { encodeHmacContext } from "../../sandbox/hmac-context";
import { CredentialVaultError } from "./errors";

/**
 * Strict encodings shared by every vault primitive (docs/design/credential-vault.md
 * § Encodings). Every decoder refuses anything that does not round-trip to
 * exactly the same text, so one value has exactly one accepted spelling in TS
 * and in Rust (`apps/cli/src/sandbox_relay/credentials/seal.rs`).
 */

export const X25519_KEY_BYTES = 32;
export const SHA256_HEX = /^[0-9a-f]{64}$/;
export const KID_HEX = /^[0-9a-f]{16}$/;
const B64URL = /^[A-Za-z0-9_-]*$/;

/** Unpadded base64url (RFC 4648 §5), the transport spelling of keys. */
export function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength).toString("base64url");
}

/** Decode unpadded base64url of exactly `length` bytes; non-canonical text is refused. */
export function fromBase64UrlStrict(text: string, length: number): Buffer {
  if (typeof text !== "string" || !B64URL.test(text)) throw new CredentialVaultError("invalid_key");
  const bytes = Buffer.from(text, "base64url");
  if (bytes.byteLength !== length || bytes.toString("base64url") !== text)
    throw new CredentialVaultError("invalid_key");
  return bytes;
}

export function sha256(...parts: Uint8Array[]): Buffer {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest();
}

// p = 2^255 - 19, little-endian.
const P25519 = Buffer.from(
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "hex",
);

/**
 * A canonical X25519 u-coordinate: exactly 32 bytes, high bit clear, value
 * below p. RFC 7748 receivers mask/reduce instead; refusing keeps a single
 * accepted encoding (both libraries would otherwise treat several byte strings
 * as the same point). Low-order points are caught later by the all-zero
 * shared-secret check.
 */
export function assertCanonicalX25519Public(bytes: Uint8Array): void {
  if (bytes.byteLength !== X25519_KEY_BYTES) throw new CredentialVaultError("invalid_key");
  for (let i = X25519_KEY_BYTES - 1; i >= 0; i--) {
    const a = bytes[i]!;
    const p = P25519[i]!;
    if (a < p) return;
    if (a > p) throw new CredentialVaultError("invalid_key");
  }
  // Equal to p.
  throw new CredentialVaultError("invalid_key");
}

/** kidR = hex(SHA-256(publicKey))[0:16]. */
export function returnKeyId(publicKey: Uint8Array): string {
  return sha256(publicKey).toString("hex").slice(0, 16);
}

/**
 * A storage or capture sequence: integer in [1, 2^63 - 1] (Postgres BigInt),
 * encoded as its shortest decimal string.
 */
export function encodeSeq(value: bigint | number): string {
  const big = typeof value === "bigint" ? value : Number.isSafeInteger(value) ? BigInt(value) : -1n;
  if (big < 1n || big > 0x7fff_ffff_ffff_ffffn) throw new CredentialVaultError("malformed");
  return big.toString(10);
}

/** A sequence already in its canonical decimal spelling (see `encodeSeq`). */
export function assertSeqString(value: unknown): asserts value is string {
  if (
    typeof value !== "string" ||
    !/^[1-9][0-9]{0,18}$/.test(value) ||
    BigInt(value) > 0x7fff_ffff_ffff_ffffn
  )
    throw new CredentialVaultError("malformed");
}

/** An identifier inside an AAD list: non-empty, ≤ 256 UTF-8 bytes, well-formed. */
export function assertAadId(value: unknown): asserts value is string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    !value.isWellFormed() ||
    Buffer.byteLength(value, "utf8") > 256
  )
    throw new CredentialVaultError("malformed");
}

/** `encodeHmacContext` over already-validated fields (LP(x) = u32be(len) ‖ UTF-8). */
export function encodeAad(fields: readonly string[]): Buffer {
  return encodeHmacContext(fields);
}
