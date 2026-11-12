/**
 * Post-commit wake hints for the capacity queue (no imports: outbox.ts and
 * host-admission.ts use this without a cycle). A hint carries no data and
 * no authority; the queue re-reads everything under its own locks. Wakes are
 * process-local like operation long-polls; a missed wake costs at most the
 * scheduler's 15 s fallback (`QUEUE_RECHECK_MS`).
 */
export type CapacityHint = { poolIds?: Iterable<string>; hostIds?: Iterable<string> } | "all";
type Wake = (hint: CapacityHint) => void;

let wake: Wake | null = null;

/** Server runtime binds the scheduler (no-op until bound). */
export function bindCapacityQueueWake(next: Wake | null): void {
  wake = next;
}

/** Call only AFTER a commit: the woken placer must read the committed rows. */
export function notifyCapacityChanged(hint: CapacityHint = "all"): void {
  try {
    wake?.(hint);
  } catch {
    console.error("[capacity-queue] wake failed; periodic retry pending");
  }
}

type Pending = { all: boolean; poolIds: Set<string>; hostIds: Set<string> };
const pendingByTransaction = new WeakMap<object, Pending>();

/**
 * Record, inside a transaction, that capacity may have changed. The
 * sandbox outbox/relay transaction delivers it after its commit and drops it
 * on rollback; any other transaction must call `notifyCapacityChanged`
 * itself after committing.
 */
export function noteCapacityChanged(tx: object, hint: CapacityHint = "all"): void {
  let pending = pendingByTransaction.get(tx);
  if (!pending) {
    pending = { all: false, poolIds: new Set(), hostIds: new Set() };
    pendingByTransaction.set(tx, pending);
  }
  if (hint === "all") pending.all = true;
  else {
    for (const id of hint.poolIds ?? []) pending.poolIds.add(id);
    for (const id of hint.hostIds ?? []) pending.hostIds.add(id);
  }
}

/** Take (and clear) the hints recorded on `tx`; null when none. */
export function takeCapacityHints(tx: object): CapacityHint | null {
  const pending = pendingByTransaction.get(tx);
  pendingByTransaction.delete(tx);
  if (!pending) return null;
  if (pending.all) return "all";
  if (pending.poolIds.size === 0 && pending.hostIds.size === 0) return null;
  return { poolIds: pending.poolIds, hostIds: pending.hostIds };
}
