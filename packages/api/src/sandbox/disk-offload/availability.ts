import { readSandboxOffloadEnv } from "@wssp/env/image-store-config";
import { readDataKeyring } from "../../crypto/data-key";
import { imageStoreSettings } from "../image-store/s3";

/**
 * Availability split for stopped-sandbox disk offload.
 *
 * - Restore needs only the bucket and the data key: an `OFFLOADED` sandbox
 *   stays restorable and destroyable whatever `SANDBOX_OFFLOAD` says, and
 *   whatever `IMAGE_DISTRIBUTION` says (S3 is detected from the bucket and
 *   keys, the same detection the image store uses).
 * - Offload additionally needs `SANDBOX_OFFLOAD=auto` and a host that
 *   reported the offload capability. `off` stops new offloads and evictions
 *   only.
 *
 * Read from the environment on every call (never cached), so tests and a
 * restarted process see the current configuration. An invalid data key
 * throws (naming the variable only), as boot validation would.
 */
export type OffloadBlocker =
  | "s3_not_configured"
  | "data_key_missing"
  | "offload_disabled"
  | "host_unsupported";

function restoreBlocker(): OffloadBlocker | null {
  if (imageStoreSettings() === null) return "s3_not_configured";
  if (readDataKeyring() === null) return "data_key_missing";
  return null;
}

/** Why a new offload cannot start on a host, or null when it can. */
export function offloadBlocker(hostCapable: boolean): OffloadBlocker | null {
  const blocker = restoreBlocker();
  if (blocker) return blocker;
  if (readSandboxOffloadEnv().SANDBOX_OFFLOAD !== "auto") return "offload_disabled";
  if (!hostCapable) return "host_unsupported";
  return null;
}

/** A new offload (or eviction) may start on a host with this capability flag. */
export function canOffload(hostCapable: boolean): boolean {
  return offloadBlocker(hostCapable) === null;
}

/** An offloaded disk may be restored (or its copy read back). */
export function canRestore(): boolean {
  return restoreBlocker() === null;
}
