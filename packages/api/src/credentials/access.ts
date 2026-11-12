import type { Prisma } from "@wssp/db";
import type { Principal } from "../sandbox/contracts";
import { credentialVisibilityOf } from "../sandbox/principal-kinds";
import { readCredentialsAvailability } from "./availability";
import { credentialError } from "./errors";

/**
 * Which logins a principal may see or act on. Sessions: every login of the
 * owner. SDK keys over all owned resources: every login. Allowlist keys: only
 * logins named in `SdkKeyCredentialAllowlist`, read live from the row on every
 * call, so a removed grant takes effect at once. Compose into every login
 * WHERE before cursor/take; a hidden login is indistinguishable from none.
 */
export function credentialAccessFilter(principal: Principal): Prisma.CredentialWhereInput {
  const owned: Prisma.CredentialWhereInput = { userId: principal.ownerId, deletedAt: null };
  const visibility = credentialVisibilityOf(principal);
  if (visibility === "allOwned") return owned;
  if (visibility === "none") return { ...owned, id: { in: [] } };
  return { ...owned, SdkKeyAllowlist: { some: { sdkKeyId: visibility.allowlistKeyId } } };
}

export type CredentialsGate = "read" | "write" | "settle";

/**
 * Feature gate, per docs/design/credential-vault.md § Feature gate
 *
 * Writes need
 * the feature enabled; reads and settling actions (delete) also work in drain
 * mode (explicitly off with the key present). Otherwise `credential.unavailable`.
 */
export function requireCredentials(gate: CredentialsGate): void {
  const availability = readCredentialsAvailability();
  if (availability.enabled) return;
  if (gate !== "write" && availability.drain) return;
  throw credentialError("credential.unavailable");
}
