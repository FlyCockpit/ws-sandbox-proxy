/**
 * The only error the vault throws. It carries a code and a fixed message, never
 * key material, plaintext, ciphertext, or row values, so it is safe to log.
 *
 * - `key_unavailable`: no configured root matches the row's `rootKid`.
 * - `authentication_failed`: AEAD authentication failed (wrong key, AAD, or a
 *   tampered/truncated ciphertext) — the caller cannot tell which, by design.
 * - `invalid_key`: a key is not in its strict encoding, or the X25519 shared
 *   secret is all-zero.
 * - `return_key_mismatch`: a decrypted return private key does not derive the
 *   stored public key or kidR.
 * - `context_mismatch`: a row or envelope names a different context than the
 *   one the caller rebuilt from authoritative rows.
 * - `malformed`: a structural bound failed (lengths, encodings, envelope framing).
 */
export type CredentialVaultErrorCode =
  | "key_unavailable"
  | "authentication_failed"
  | "invalid_key"
  | "return_key_mismatch"
  | "context_mismatch"
  | "malformed";

export class CredentialVaultError extends Error {
  readonly code: CredentialVaultErrorCode;
  constructor(code: CredentialVaultErrorCode) {
    super(`Credential vault: ${code.replaceAll("_", " ")}.`);
    this.name = "CredentialVaultError";
    this.code = code;
  }
}
