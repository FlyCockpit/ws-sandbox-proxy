import {
  type DataKeyring,
  type DataSubkey,
  deriveSubkeys,
  readDataKeyring,
} from "../../crypto/data-key";
import { CredentialVaultError } from "./errors";

/** HKDF purpose of K_wrap (wraps per-value DEKs). Part of the derivation: never rename. */
const CRED_DEK_WRAP_PURPOSE = "cred-dek-wrap:v1";
/** HKDF purpose of K_rwrap (wraps return-key private keys). Never rename. */
const CRED_RETURN_KEY_WRAP_PURPOSE = "cred-return-key-wrap:v1";

export type DekWrapKey = DataSubkey<typeof CRED_DEK_WRAP_PURPOSE>;
export type ReturnKeyWrapKey = DataSubkey<typeof CRED_RETURN_KEY_WRAP_PURPOSE>;

/** Vault sub-keys of one keyring: `current` encrypts, `all` (current first) decrypts. */
export type VaultKeys = {
  dek: { current: DekWrapKey; all: readonly DekWrapKey[] };
  returnKey: { current: ReturnKeyWrapKey; all: readonly ReturnKeyWrapKey[] };
};

export function deriveVaultKeys(ring: DataKeyring): VaultKeys {
  return {
    dek: deriveSubkeys(ring, CRED_DEK_WRAP_PURPOSE),
    returnKey: deriveSubkeys(ring, CRED_RETURN_KEY_WRAP_PURPOSE),
  };
}

/** Vault keys from the environment, or null without `DATA_ENCRYPTION_KEY`. */
export function readVaultKeys(): VaultKeys | null {
  const ring = readDataKeyring();
  return ring ? deriveVaultKeys(ring) : null;
}

/** The sub-key for a row's root kid; `key_unavailable` when no configured root matches. */
export function keyForKid<K extends DataSubkey>(keys: readonly K[], rootKid: string): K {
  const key = keys.find((candidate) => candidate.rootKeyId === rootKid);
  if (!key) throw new CredentialVaultError("key_unavailable");
  return key;
}
