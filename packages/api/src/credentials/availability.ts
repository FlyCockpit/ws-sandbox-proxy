import { sharedVars } from "@wssp/env/vars/shared";
import { readDataKeyring } from "../crypto/data-key";

/**
 * Whether CLI logins are available (docs/design/credential-vault.md § Feature
 * gate). Optional features are on by default and turned off explicitly:
 *
 * - `enabled`: `CREDENTIALS_ENABLED` (default true) AND `DATA_ENCRYPTION_KEY`
 *   present. Only then do entry points work and `capabilities.features`
 *   advertise `credentials`.
 * - `keyPresent` false: unavailable, never a boot failure (the operator notice
 *   says to set the key). Captures arriving with data present ack DEFERRED.
 * - `drain`: explicitly off WITH the key present. Entry points refuse, but
 *   capture commit, census, force-release, delete and rewrap keep working so
 *   existing values settle.
 */
export type CredentialsAvailability = {
  flag: boolean;
  keyPresent: boolean;
  enabled: boolean;
  drain: boolean;
};

/**
 * Read with the same declarations `@wssp/env/shared` validates at boot,
 * without importing that module. Empty strings are unset. Throws only on an
 * invalid value (naming the variable, never the value).
 */
export function readCredentialsAvailability(): CredentialsAvailability {
  const raw = process.env.CREDENTIALS_ENABLED;
  const parsed = sharedVars.CREDENTIALS_ENABLED.safeParse(raw === "" ? undefined : raw);
  if (!parsed.success) throw new Error("CREDENTIALS_ENABLED is invalid.");
  const flag = parsed.data;
  const keyPresent = readDataKeyring() !== null;
  return { flag, keyPresent, enabled: flag && keyPresent, drain: !flag && keyPresent };
}
