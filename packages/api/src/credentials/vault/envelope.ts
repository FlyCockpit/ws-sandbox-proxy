import { KID_HEX, SHA256_HEX, sha256 } from "./codec";
import { CredentialVaultError } from "./errors";
import type { ReturnKeyPair } from "./return-key";
import {
  encodeReturnAad,
  openSealed,
  RETURN_AAD_FIELDS,
  type ReturnAad,
  SEAL_OVERHEAD,
} from "./sealed-box";

/**
 * Capture envelope v1 (`<data>/credentials/outbox/<captureId>.wsco`), written
 * by `apps/cli/src/sandbox_relay/credentials/envelope.rs`
 * (docs/design/credential-vault.md § Envelope):
 *
 *   "WSCO" ‖ u8 version = 1 ‖ u32be headerLen ‖ header JSON ‖ seal
 *
 * The header is exactly one canonical JSON spelling (fixed key order, no
 * whitespace, every AAD field a string), ≤ 4 KiB:
 *   {"kidR","recipientPubSha256","aad":{…13 fields…},"sealedLen","sealedSha256","createdAt"}
 *
 * envelopeDigest = SHA-256(every envelope byte) = SHA-256(header bytes ‖ seal)
 * where "header bytes" is the whole prefix before the seal (magic, version,
 * length and JSON). The server ledgers it and matches replays on
 * (captureId, envelopeDigest).
 */

const ENVELOPE_MAGIC = Buffer.from("WSCO", "ascii");
const ENVELOPE_VERSION = 1;
const ENVELOPE_MAX_HEADER_BYTES = 4096;
const PREFIX_BYTES = ENVELOPE_MAGIC.byteLength + 1 + 4;

export type EnvelopeHeader = {
  kidR: string;
  /** hex(SHA-256(recipient public key)); kidR is its first 16 hex. */
  recipientPubSha256: string;
  aad: ReturnAad;
  sealedLen: number;
  sealedSha256: string;
  /** Unix milliseconds at pack time (advisory; never authorizes anything). */
  createdAt: number;
};

export type ParsedEnvelope = {
  header: EnvelopeHeader;
  /** The exact header JSON bytes. */
  headerJson: Buffer;
  seal: Buffer;
  /** SHA-256 of the whole envelope (32 bytes). */
  envelopeDigest: Buffer;
};

/** The single accepted JSON spelling of a header (same order serde emits). */
function canonicalHeaderJson(header: EnvelopeHeader): string {
  const aad = Object.fromEntries(RETURN_AAD_FIELDS.map((field) => [field, header.aad[field]]));
  return JSON.stringify({
    kidR: header.kidR,
    recipientPubSha256: header.recipientPubSha256,
    aad,
    sealedLen: header.sealedLen,
    sealedSha256: header.sealedSha256,
    createdAt: header.createdAt,
  });
}

function validateHeader(value: unknown): EnvelopeHeader {
  const fail = () => new CredentialVaultError("malformed");
  if (typeof value !== "object" || value === null) throw fail();
  const header = value as EnvelopeHeader;
  if (
    typeof header.kidR !== "string" ||
    !KID_HEX.test(header.kidR) ||
    typeof header.recipientPubSha256 !== "string" ||
    !SHA256_HEX.test(header.recipientPubSha256) ||
    !header.recipientPubSha256.startsWith(header.kidR) ||
    typeof header.sealedSha256 !== "string" ||
    !SHA256_HEX.test(header.sealedSha256) ||
    !Number.isSafeInteger(header.sealedLen) ||
    header.sealedLen < SEAL_OVERHEAD ||
    !Number.isSafeInteger(header.createdAt) ||
    header.createdAt < 0 ||
    typeof header.aad !== "object" ||
    header.aad === null
  )
    throw fail();
  // Throws on any field that is missing, mistyped or out of bounds.
  encodeReturnAad(header.kidR, header.aad);
  return header;
}

/** Frame a header and seal. Used by TS fake hosts and vectors. */
export function buildEnvelope(header: EnvelopeHeader, seal: Uint8Array): Buffer {
  validateHeader(header);
  if (header.sealedLen !== seal.byteLength || header.sealedSha256 !== sha256(seal).toString("hex"))
    throw new CredentialVaultError("malformed");
  const json = Buffer.from(canonicalHeaderJson(header), "utf8");
  if (json.byteLength > ENVELOPE_MAX_HEADER_BYTES) throw new CredentialVaultError("malformed");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(json.byteLength);
  return Buffer.concat([ENVELOPE_MAGIC, Buffer.from([ENVELOPE_VERSION]), length, json, seal]);
}

/**
 * Parse and self-verify an envelope: magic, version, header bound, canonical
 * header JSON, exact seal length and `sealedSha256`. Does not decrypt.
 */
export function parseEnvelope(bytes: Uint8Array): ParsedEnvelope {
  const body = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (
    body.byteLength < PREFIX_BYTES ||
    !body.subarray(0, 4).equals(ENVELOPE_MAGIC) ||
    body[4] !== ENVELOPE_VERSION
  )
    throw new CredentialVaultError("malformed");
  const headerLen = body.readUInt32BE(5);
  if (headerLen > ENVELOPE_MAX_HEADER_BYTES || body.byteLength < PREFIX_BYTES + headerLen)
    throw new CredentialVaultError("malformed");
  const headerJson = Buffer.from(body.subarray(PREFIX_BYTES, PREFIX_BYTES + headerLen));
  const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  let header: EnvelopeHeader;
  try {
    header = validateHeader(JSON.parse(text.decode(headerJson)));
  } catch {
    throw new CredentialVaultError("malformed");
  }
  if (canonicalHeaderJson(header) !== headerJson.toString("utf8"))
    throw new CredentialVaultError("malformed");
  const seal = Buffer.from(body.subarray(PREFIX_BYTES + headerLen));
  if (seal.byteLength !== header.sealedLen || sha256(seal).toString("hex") !== header.sealedSha256)
    throw new CredentialVaultError("malformed");
  return { header, headerJson, seal, envelopeDigest: sha256(body) };
}

/**
 * Open a parsed envelope against the AAD the server rebuilt from rows. Every
 * header field must equal the expected value (compared field by field, before
 * any key is used), the header must name `recipient`, and the seal is then
 * opened with the EXPECTED context. The caller zeroes the plaintext.
 */
export function openEnvelope(
  envelope: ParsedEnvelope,
  expected: ReturnAad,
  recipient: ReturnKeyPair,
): Buffer {
  const { header } = envelope;
  if (
    header.kidR !== recipient.kidR ||
    header.recipientPubSha256 !== sha256(recipient.publicKey).toString("hex")
  )
    throw new CredentialVaultError("context_mismatch");
  for (const field of RETURN_AAD_FIELDS)
    if (header.aad[field] !== expected[field]) throw new CredentialVaultError("context_mismatch");
  return openSealed(envelope.seal, recipient, expected);
}
