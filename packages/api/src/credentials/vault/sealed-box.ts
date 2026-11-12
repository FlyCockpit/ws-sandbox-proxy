import { gcmOpen, gcmSeal, hkdf32, NONCE_BYTES, randomNonce, TAG_BYTES } from "./aead";
import {
  assertAadId,
  assertCanonicalX25519Public,
  assertSeqString,
  encodeAad,
  KID_HEX,
  returnKeyId,
  X25519_KEY_BYTES,
} from "./codec";
import { CredentialVaultError } from "./errors";
import type { ReturnKeyPair } from "./return-key";
import { generateX25519Private, x25519, x25519PublicKey } from "./x25519";

/**
 * Sealed captures from hosts to the control plane. Hosts seal in Rust
 * (`apps/cli/src/sandbox_relay/credentials/seal.rs`); the server opens. The TS
 * sealer exists for cross-language vectors and TS fake hosts. Spec:
 * docs/design/credential-vault.md § Sealed box
 *
 *   seal   = eph_pub(32) ‖ nonce(12) ‖ ciphertext ‖ tag(16)
 *   shared = X25519(eph, recipient_pub)          (all-zero refused)
 *   key    = HKDF-SHA256(ikm = shared, salt = eph_pub ‖ recipient_pub,
 *              info = "wssp:cred-return:v1" ‖ kidR)
 *   AAD    = LP list ["wssp:cred-return:v1", kidR, serverOrigin, hostOwnerId,
 *              hostId, sandboxOwnerId, sandboxId, leaseId, bindingId,
 *              instanceId, credentialId, captureSeq, captureId, kind, residueId|""]
 */

const SEAL_LABEL = "wssp:cred-return:v1";
export const SEAL_OVERHEAD = X25519_KEY_BYTES + NONCE_BYTES + TAG_BYTES;
const CAPTURE_KIND = /^[a-z][a-z0-9_-]{0,31}$/;

/** Everything the seal AAD binds besides the label and kidR. */
export type ReturnAad = {
  serverOrigin: string;
  hostOwnerId: string;
  hostId: string;
  sandboxOwnerId: string;
  sandboxId: string;
  leaseId: string;
  bindingId: string;
  instanceId: string;
  credentialId: string;
  /** Decimal string, 1 ≤ seq ≤ 2^63 − 1. */
  captureSeq: string;
  captureId: string;
  /** Capture kind (lowercase token, e.g. `stop`, `checkpoint`, `recovery`, `login`). */
  kind: string;
  /** "" when the capture packs no residue. */
  residueId: string;
};

export const RETURN_AAD_FIELDS = [
  "serverOrigin",
  "hostOwnerId",
  "hostId",
  "sandboxOwnerId",
  "sandboxId",
  "leaseId",
  "bindingId",
  "instanceId",
  "credentialId",
  "captureSeq",
  "captureId",
  "kind",
  "residueId",
] as const satisfies readonly (keyof ReturnAad)[];

/** Validates every field and returns the LP-encoded AAD. */
export function encodeReturnAad(kidR: string, aad: ReturnAad): Buffer {
  if (!KID_HEX.test(kidR)) throw new CredentialVaultError("invalid_key");
  for (const field of RETURN_AAD_FIELDS) {
    if (field === "residueId" && aad.residueId === "") continue;
    assertAadId(aad[field]);
  }
  assertSeqString(aad.captureSeq);
  if (!CAPTURE_KIND.test(aad.kind)) throw new CredentialVaultError("malformed");
  return encodeAad([SEAL_LABEL, kidR, ...RETURN_AAD_FIELDS.map((field) => aad[field])]);
}

function sealKey(
  shared: Buffer,
  ephPub: Uint8Array,
  recipientPub: Uint8Array,
  kidR: string,
): Buffer {
  return hkdf32(
    shared,
    Buffer.concat([ephPub, recipientPub]),
    Buffer.concat([Buffer.from(SEAL_LABEL, "utf8"), Buffer.from(kidR, "ascii")]),
  );
}

/** Test-only determinism: fixed ephemeral scalar and nonce for vectors. Never in production. */
export type SealDeterminism = { ephemeralPrivateKey: Uint8Array; nonce: Uint8Array };

export function sealToReturnKey(
  plaintext: Uint8Array,
  recipientPublicKey: Uint8Array,
  aad: ReturnAad,
  determinism?: SealDeterminism,
): Buffer {
  assertCanonicalX25519Public(recipientPublicKey);
  const kidR = returnKeyId(recipientPublicKey);
  const aadBytes = encodeReturnAad(kidR, aad);
  const eph = determinism ? Buffer.from(determinism.ephemeralPrivateKey) : generateX25519Private();
  const nonce = determinism ? Buffer.from(determinism.nonce) : randomNonce();
  try {
    const ephPub = x25519PublicKey(eph);
    const shared = x25519(eph, recipientPublicKey);
    const key = sealKey(shared, ephPub, recipientPublicKey, kidR);
    shared.fill(0);
    try {
      return Buffer.concat([ephPub, nonce, gcmSeal(key, nonce, plaintext, aadBytes)]);
    } finally {
      key.fill(0);
    }
  } finally {
    eph.fill(0);
  }
}

/**
 * Open a seal addressed to `recipient` (a verified return key). `aad` must be
 * rebuilt from authoritative rows, never read from the envelope header. The
 * caller zeroes the plaintext.
 */
export function openSealed(seal: Uint8Array, recipient: ReturnKeyPair, aad: ReturnAad): Buffer {
  if (seal.byteLength < SEAL_OVERHEAD) throw new CredentialVaultError("malformed");
  const kidR = returnKeyId(recipient.publicKey);
  if (kidR !== recipient.kidR) throw new CredentialVaultError("return_key_mismatch");
  const aadBytes = encodeReturnAad(kidR, aad);
  const body = Buffer.from(seal.buffer, seal.byteOffset, seal.byteLength);
  const ephPub = body.subarray(0, X25519_KEY_BYTES);
  const nonce = body.subarray(X25519_KEY_BYTES, X25519_KEY_BYTES + NONCE_BYTES);
  const shared = x25519(recipient.privateKey, ephPub);
  const key = sealKey(shared, ephPub, recipient.publicKey, kidR);
  shared.fill(0);
  try {
    return gcmOpen(key, nonce, body.subarray(X25519_KEY_BYTES + NONCE_BYTES), aadBytes);
  } finally {
    key.fill(0);
  }
}
