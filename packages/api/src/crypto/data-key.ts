import { createHash, hkdfSync } from "node:crypto";
import { sharedVars } from "@wssp/env/vars/shared";

/**
 * Deployment-wide data-at-rest root key (`DATA_ENCRYPTION_KEY`, plus the
 * decrypt-only `DATA_ENCRYPTION_KEY_PREVIOUS` during a rotation).
 *
 * The root never encrypts anything itself. Each purpose derives its own
 * 32-byte sub-key with HKDF-SHA256 (salt `wssp-data-key-v1`, info = the
 * purpose label), so a ciphertext produced for one purpose can never be
 * opened with another purpose's key. The root is never derived from
 * `BETTER_AUTH_SECRET`: rotating auth must not lose data, and vice versa.
 *
 * Key id ("kid"): the first 16 hex of SHA-256(root bytes). Rows store the kid
 * of the ROOT a value was sealed under, not of the sub-key, so one query per
 * table ("kid <> current root kid") finds every row a rewrap job must touch
 * after a root rotation, whatever the purpose. The purpose is fixed per
 * column and bound into each cipher's AAD instead.
 */

/**
 * Closed set of purpose labels. Adding one is a reviewed change: a label is
 * part of the derivation and can never be renamed once data is sealed under
 * it (bump the `:vN` suffix instead). Only labels with a consumer belong
 * here. The credential vault owns two (`credentials/vault/keys.ts`): K_wrap
 * wraps per-value DEKs and K_rwrap wraps return-key private keys, each under a
 * fresh per-row salt (docs/design/credential-vault.md). Disk offload owns
 * K_diskwrap (`sandbox/disk-offload/keys.ts`), also under a per-row salt.
 */
export const DATA_KEY_PURPOSES = [
  "webhook-endpoint-secret:v1",
  "cred-dek-wrap:v1",
  "cred-return-key-wrap:v1",
  // Disk offload (sandbox/disk-offload/keys.ts): wraps per-upload-session disk DEKs.
  "sandbox-disk-dek-wrap:v1",
  // Preview tunnels (sandbox/tunnels/config.ts): the admin-set service credential.
  "tunnel-service-credential:v1",
] as const;
export type DataKeyPurpose = (typeof DATA_KEY_PURPOSES)[number];

export const DATA_KEY_HKDF_SALT = "wssp-data-key-v1";
const SUBKEY_BYTES = 32;

export type DataRootKey = { readonly id: string; readonly key: Buffer };
export type DataSubkey<P extends DataKeyPurpose = DataKeyPurpose> = {
  /** Kid of the root this sub-key came from (the value stored on rows). */
  readonly rootKeyId: string;
  readonly purpose: P;
  readonly key: Buffer;
};

/** Parse a 64-lowercase-hex root. The message names no value. */
export function dataRootKey(hex: string): DataRootKey {
  if (!/^[0-9a-f]{64}$/.test(hex))
    throw new Error("DATA_ENCRYPTION_KEY must be 64 lowercase hex characters.");
  const key = Buffer.from(hex, "hex");
  return { id: createHash("sha256").update(key).digest("hex").slice(0, 16), key };
}

export function deriveSubkey<P extends DataKeyPurpose>(
  root: DataRootKey,
  purpose: P,
): DataSubkey<P> {
  const key = Buffer.from(hkdfSync("sha256", root.key, DATA_KEY_HKDF_SALT, purpose, SUBKEY_BYTES));
  return { rootKeyId: root.id, purpose, key };
}

/** Current root first (encrypts); the previous one, if distinct, only decrypts. */
export type DataKeyring = { readonly current: DataRootKey; readonly previous: DataRootKey | null };

/** Sub-keys for one purpose, current first; `all` is the decrypt set. */
export function deriveSubkeys<P extends DataKeyPurpose>(
  ring: DataKeyring,
  purpose: P,
): { current: DataSubkey<P>; all: readonly DataSubkey<P>[] } {
  const current = deriveSubkey(ring.current, purpose);
  return {
    current,
    all: ring.previous ? [current, deriveSubkey(ring.previous, purpose)] : [current],
  };
}

const DATA_KEY_VARS = {
  DATA_ENCRYPTION_KEY: sharedVars.DATA_ENCRYPTION_KEY,
  DATA_ENCRYPTION_KEY_PREVIOUS: sharedVars.DATA_ENCRYPTION_KEY_PREVIOUS,
};

/**
 * Read the keyring from the environment with the SAME declarations
 * `@wssp/env/shared` validates at boot, without importing that module (so the
 * router graph stays importable in unit tests). Empty strings are unset. Not
 * cached: callers cache what they derive. Throws (naming the variable, never
 * the value) on an invalid value; returns null when the root is unset.
 */
export function readDataKeyring(): DataKeyring | null {
  const parse = (name: keyof typeof DATA_KEY_VARS) => {
    const raw = process.env[name];
    const parsed = DATA_KEY_VARS[name].safeParse(raw === "" ? undefined : raw);
    if (!parsed.success) throw new Error(`${name} is invalid.`);
    return parsed.data;
  };
  const currentHex = parse("DATA_ENCRYPTION_KEY");
  const previousHex = parse("DATA_ENCRYPTION_KEY_PREVIOUS");
  if (!currentHex) return null;
  const current = dataRootKey(currentHex);
  const previous = previousHex ? dataRootKey(previousHex) : null;
  return { current, previous: previous && previous.id !== current.id ? previous : null };
}
