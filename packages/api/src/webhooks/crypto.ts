import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { WEBHOOK_SECRET_PREFIX } from "@wssp/sandbox-contracts";
import { DATA_KEY_HKDF_SALT, type DataKeyPurpose, type DataSubkey } from "../crypto/data-key";
import { encodeHmacContext } from "../sandbox/hmac-context";

/**
 * Endpoint signing secrets at rest: AES-256-GCM under the
 * `webhook-endpoint-secret:v1` HKDF sub-key of `DATA_ENCRYPTION_KEY`
 * (`../crypto/data-key.ts`). The worker must recover the plaintext to sign, so
 * a digest (the credential pattern) cannot work. The nonce is 96 random bits
 * per encryption.
 *
 * AAD binds the ciphertext to (derivation scheme, purpose label, endpoint,
 * owner, secret version): a ciphertext copied onto another row, or sealed for
 * another purpose or under the retired raw-key scheme, fails to authenticate
 * and surfaces as `WebhookSecretUnavailableError` (fail closed, never a crash).
 *
 * `keyId` on a row is the ROOT key id (first 16 hex of SHA-256(root)), not a
 * sub-key id: a root rotation is then found by `secretKeyId <> current root
 * kid` and re-encrypted with `DATA_ENCRYPTION_KEY_PREVIOUS` still set.
 */

export const WEBHOOK_SECRET_PURPOSE = "webhook-endpoint-secret:v1" satisfies DataKeyPurpose;
const TAG_BYTES = 16;
const NONCE_BYTES = 12;
export const SIGNING_SECRET_BYTES = 32;

/** The webhook sub-key: `rootKeyId` is what rows store as `secretKeyId`. */
export type WebhookSecretKey = DataSubkey<typeof WEBHOOK_SECRET_PURPOSE>;

export type SecretBinding = { endpointId: string; userId: string; version: number };

function aad(binding: SecretBinding): Buffer {
  return encodeHmacContext([
    DATA_KEY_HKDF_SALT,
    WEBHOOK_SECRET_PURPOSE,
    binding.endpointId,
    binding.userId,
    String(binding.version),
  ]);
}

export type SealedSecret = { ciphertext: Buffer; nonce: Buffer; keyId: string };

export function sealSecret(
  secret: Buffer,
  binding: SecretBinding,
  subkey: WebhookSecretKey,
): SealedSecret {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", subkey.key, nonce, { authTagLength: TAG_BYTES });
  cipher.setAAD(aad(binding));
  const ciphertext = Buffer.concat([cipher.update(secret), cipher.final(), cipher.getAuthTag()]);
  return { ciphertext, nonce, keyId: subkey.rootKeyId };
}

/** Thrown when no configured key matches or authentication fails. Carries no data. */
export class WebhookSecretUnavailableError extends Error {
  constructor() {
    super("Webhook signing secret is unavailable.");
    this.name = "WebhookSecretUnavailableError";
  }
}

export function openSecret(
  sealed: { ciphertext: Uint8Array; nonce: Uint8Array; keyId: string },
  binding: SecretBinding,
  keys: readonly WebhookSecretKey[],
): Buffer {
  const subkey = keys.find((candidate) => candidate.rootKeyId === sealed.keyId);
  const body = Buffer.from(sealed.ciphertext);
  if (!subkey || body.byteLength <= TAG_BYTES || sealed.nonce.byteLength !== NONCE_BYTES)
    throw new WebhookSecretUnavailableError();
  try {
    const decipher = createDecipheriv("aes-256-gcm", subkey.key, Buffer.from(sealed.nonce), {
      authTagLength: TAG_BYTES,
    });
    decipher.setAAD(aad(binding));
    decipher.setAuthTag(body.subarray(body.byteLength - TAG_BYTES));
    return Buffer.concat([
      decipher.update(body.subarray(0, body.byteLength - TAG_BYTES)),
      decipher.final(),
    ]);
  } catch {
    throw new WebhookSecretUnavailableError();
  }
}

/** A fresh Standard Webhooks signing secret: raw bytes and the `whsec_` text shown once. */
export function generateSigningSecret(): { raw: Buffer; text: string } {
  const raw = randomBytes(SIGNING_SECRET_BYTES);
  return { raw, text: `${WEBHOOK_SECRET_PREFIX}${raw.toString("base64")}` };
}
