import { env } from "@wssp/env/server";
import { transferError } from "./limits.js";
import { TransferStore } from "./store.js";

let bound: TransferStore | undefined;
export function transferStore(): TransferStore {
  if (!bound) throw transferError("TRANSFER_IO");
  return bound;
}

/** Recovery is part of startup readiness; the lifecycle owns shutdown. */
export async function startTransferStore() {
  const store = new TransferStore(env.TRANSFER_SPOOL_DIR, {
    maxBytes: env.TRANSFER_MAX_BYTES,
    diskBytes: env.TRANSFER_DISK_BYTES,
    ownerActive: env.TRANSFER_OWNER_ACTIVE,
    globalActive: env.TRANSFER_GLOBAL_ACTIVE,
    idleMs: env.TRANSFER_IDLE_SECONDS * 1000,
    absoluteMs: env.TRANSFER_ABSOLUTE_SECONDS * 1000,
  });
  await store.start();
  bound = store;
  return store;
}
