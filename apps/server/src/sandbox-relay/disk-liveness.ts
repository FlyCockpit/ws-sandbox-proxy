/**
 * A connection's disk upload liveness allowance outside the shared image
 * grant budget (round 1 L2 #1): when the budget refuses an
 * `image.upload.progress`, a disk offload upload's heartbeat may still move
 * its transfer's `lastProgressAt`, so other image traffic or an unavailable
 * budget store never lets the stall rule fail a moving upload. Per
 * connection (`SessionState.diskLiveness`), so another host's traffic never
 * spends it; bounded so a connection cannot turn it into unbounded database
 * work.
 *
 * Keys: `confirmed:<transfer>` (a transfer the server proved to be this
 * host's open disk upload: it granted it on this connection, or a heartbeat
 * matched it; its last try, kept), `nondisk:<transfer>` (proved not to be:
 * never tried again; kept, oldest dropped) and a bare transfer id (a probe:
 * its try, counted against the probe limit until it lapses, whatever it
 * proved).
 */
export type DiskLiveness = Map<string, number>;

/** Heartbeats closer than this are absorbed (the daemon sends every 30 s). */
const INTERVAL_MS = 10_000;
/** Unproven transfer ids one connection may try within an interval. */
export const DISK_LIVENESS_PROBES_MAX = 4;
/** Proven disk upload transfers one connection keeps a slot for. */
const CONFIRMED_MAX = 4;
/** Proven non-disk transfers one connection remembers. */
const NONDISK_MAX = 64;
const CONFIRMED = "confirmed:";
const NONDISK = "nondisk:";

const keysWith = (allowance: DiskLiveness, prefix: string) =>
  [...allowance.keys()].filter((key) => key.startsWith(prefix));

/** Whether this connection may try one disk liveness write for `transferId`
 * now: once per interval per transfer. A proven disk upload always may; a
 * proven non-disk transfer never; any other id takes one of
 * `DISK_LIVENESS_PROBES_MAX` probe slots. */
export function takeDiskLivenessSlot(
  allowance: DiskLiveness,
  transferId: string,
  nowMs: number,
): boolean {
  for (const [key, at] of allowance)
    if (!key.startsWith(CONFIRMED) && !key.startsWith(NONDISK) && nowMs - at >= INTERVAL_MS)
      allowance.delete(key);
  const confirmed = allowance.get(CONFIRMED + transferId);
  if (confirmed !== undefined) {
    if (nowMs - confirmed < INTERVAL_MS) return false;
    allowance.set(CONFIRMED + transferId, nowMs);
    return true;
  }
  if (allowance.has(NONDISK + transferId) || allowance.has(transferId)) return false;
  const probes = [...allowance.keys()].filter(
    (k) => !k.startsWith(CONFIRMED) && !k.startsWith(NONDISK),
  ).length;
  if (probes >= DISK_LIVENESS_PROBES_MAX) return false;
  allowance.set(transferId, nowMs);
  return true;
}

/** The server proved `transferId` this host's open disk upload (`disk`) or
 * not, at `nowMs`: it keeps its own slot, or is never probed again. */
export function confirmDiskLiveness(
  allowance: DiskLiveness,
  transferId: string,
  disk: boolean,
  nowMs: number,
): void {
  const at = allowance.get(transferId) ?? allowance.get(CONFIRMED + transferId) ?? nowMs;
  // The probe's own entry stays until it lapses: it keeps counting against
  // `DISK_LIVENESS_PROBES_MAX` whatever it proved (round 5), so fresh ids
  // never buy more than that many lookups per interval.
  if (!disk) {
    allowance.delete(CONFIRMED + transferId);
    allowance.set(NONDISK + transferId, nowMs);
    const nondisk = keysWith(allowance, NONDISK);
    if (nondisk.length > NONDISK_MAX) allowance.delete(nondisk[0]!);
    return;
  }
  allowance.delete(NONDISK + transferId);
  allowance.set(CONFIRMED + transferId, at);
  const confirmed = keysWith(allowance, CONFIRMED);
  if (confirmed.length > CONFIRMED_MAX) allowance.delete(confirmed[0]!);
}

/** The server granted `transferId` (a disk upload) to this connection: it
 * holds a slot from now on, before its first heartbeat (round 4). */
export function grantDiskLiveness(allowance: DiskLiveness, transferId: string): void {
  if (allowance.has(CONFIRMED + transferId)) return;
  // Never tried yet: its first heartbeat may go at once.
  confirmDiskLiveness(allowance, transferId, true, Number.NEGATIVE_INFINITY);
}
