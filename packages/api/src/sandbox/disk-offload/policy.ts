import type { SandboxOffloadMode as SandboxOffloadModeRow } from "@wssp/db";
import type { SandboxOffloadPolicy } from "@wssp/sandbox-contracts";

/**
 * The per-sandbox offload policy: when a STOPPED disk becomes an export
 * candidate (docs/guide/sandboxes.md#offload-policy).
 *
 * - `ON_STOP` (default): at once, as before policies existed.
 * - `AFTER`: once `lastStoppedAt + offloadAfterMs` has passed.
 * - `ON_PRESSURE`: only while its host needs the space.
 *
 * "Needs the space" (`hostNeedsSpace` in enqueue.ts) overrides AFTER and
 * ON_PRESSURE for every owner: the host is draining with `--offload`, a
 * capacity wait in one of its pools is blocked on disk, or the sandbox's
 * storage pool is at least 90% used (the daemon's own eviction threshold).
 * The policy gates only the start of an export; eviction of a stored copy is
 * unchanged. Type-only imports: the disk view (and so the worker's webhook
 * renderer) reads this module.
 */
export type OffloadPolicyColumns = {
  offloadMode: SandboxOffloadModeRow;
  offloadAfterMs: number | null;
};

/** The row columns of a public policy. */
export function offloadPolicyColumns(policy: SandboxOffloadPolicy): OffloadPolicyColumns {
  switch (policy.mode) {
    case "after":
      return { offloadMode: "AFTER", offloadAfterMs: policy.afterMs };
    case "on_pressure":
      return { offloadMode: "ON_PRESSURE", offloadAfterMs: null };
    default:
      return { offloadMode: "ON_STOP", offloadAfterMs: null };
  }
}

/** The public policy of a row. An AFTER row without a delay (the CHECK forbids it) reads as on_stop. */
export function offloadPolicyOf(row: OffloadPolicyColumns): SandboxOffloadPolicy {
  if (row.offloadMode === "AFTER" && row.offloadAfterMs !== null)
    return { mode: "after", afterMs: row.offloadAfterMs };
  if (row.offloadMode === "ON_PRESSURE") return { mode: "on_pressure" };
  return { mode: "on_stop" };
}

/**
 * When the policy makes a stopped disk due, from its stop time: the stop
 * itself for ON_STOP, stop + delay for AFTER, never for ON_PRESSURE. An
 * unknown stop time counts as due now, as the candidate query treats it.
 */
export function offloadDueAt(
  row: OffloadPolicyColumns & { lastStoppedAt: Date | null },
  now: Date,
): Date | null {
  if (row.offloadMode === "ON_PRESSURE") return null;
  if (row.lastStoppedAt === null) return now;
  if (row.offloadMode === "AFTER" && row.offloadAfterMs !== null)
    return new Date(row.lastStoppedAt.getTime() + row.offloadAfterMs);
  return row.lastStoppedAt;
}
