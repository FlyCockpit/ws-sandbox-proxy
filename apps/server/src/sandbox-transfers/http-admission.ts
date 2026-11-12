import { ORPCError } from "@orpc/server";
import type { Principal } from "@wssp/api/sandbox/contracts";
import { env } from "@wssp/env/server";

// Admission for transfer HTTP bodies (upload chunk reads) and download streams.
// Both credential planes share these per-owner and global slots; neither keeps
// a queue of waiting payloads. A refused request never consumes its body.
const holders = new Map<string, number>();
let active = 0;

/** Acquire one slot or throw 429. The returned release is idempotent. */
export function acquireTransferSlot(owner: Principal): () => void {
  const count = holders.get(owner.ownerId) ?? 0;
  if (active >= env.TRANSFER_GLOBAL_ACTIVE || count >= env.TRANSFER_OWNER_ACTIVE)
    throw new ORPCError("TOO_MANY_REQUESTS");
  active++;
  holders.set(owner.ownerId, count + 1);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    active--;
    const remaining = (holders.get(owner.ownerId) ?? 1) - 1;
    if (remaining) holders.set(owner.ownerId, remaining);
    else holders.delete(owner.ownerId);
  };
}

/** Holds a slot for the duration of `work`; the slot always leaves in finally. */
export async function admitted<T>(owner: Principal, work: () => Promise<T>): Promise<T> {
  const release = acquireTransferSlot(owner);
  try {
    return await work();
  } finally {
    release();
  }
}

/** Slots currently held (tests assert that aborted streams return theirs). */
export function transferSlotsInUse(): number {
  return active;
}
