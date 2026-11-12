import { statfs } from "node:fs/promises";
import { templateBuildsConfig } from "@wssp/api/template-builds/config";
import { bindBuildContextPort } from "@wssp/api/template-builds/context-port";
import { env } from "@wssp/env/server";
import { transferError } from "../sandbox-transfers/limits.js";
import type { TransferStore } from "../sandbox-transfers/store.js";
import { BuildContextStore } from "./context-store.js";

let bound: BuildContextStore | undefined;
export function buildContextStore(): BuildContextStore {
  if (!bound) throw transferError("TRANSFER_IO");
  return bound;
}

/**
 * Starts the build-context store. Server startup awaits this BEFORE
 * `startTransferStore`: its recovery unlinks the staged name of every
 * adopted context, so the transfer store's recovery never sees a second name
 *.
 */
export async function startBuildContextStore() {
  const config = templateBuildsConfig();
  const store = new BuildContextStore(env.TRANSFER_SPOOL_DIR, {
    maxBytes: config.contextMaxBytes,
    stagedBytesPerAccount: config.contextStagedBytesPerAccount,
    stagedBytes: config.contextStagedBytes,
    idleMs: env.TRANSFER_IDLE_SECONDS * 1000,
    globalActive: env.TRANSFER_GLOBAL_ACTIVE,
  });
  await store.start();
  // Warning only: both spools' budgets against the free space of each root.
  const budget = config.contextStagedBytes + env.TRANSFER_DISK_BYTES;
  for (const root of [store.root, env.TRANSFER_SPOOL_DIR]) {
    try {
      const fs = await statfs(root);
      if (fs.bavail * fs.bsize < budget)
        console.warn(
          "[template-builds] Free space on a spool root is below TEMPLATE_BUILD_CONTEXT_STAGED_BYTES + TRANSFER_DISK_BYTES.",
        );
    } catch {
      // The transfer root is created by its own store, after this one.
    }
  }
  return store;
}

/** Binds the orchestrator's context port (and the routes' store) once both
 * stores recovered. */
export function bindBuildContextStores(contexts: BuildContextStore, transfers: TransferStore) {
  bound = contexts;
  bindBuildContextPort({
    importContext: (principal, buildId) => contexts.importContext(transfers, principal, buildId),
    commitContext: (principal, buildId, transferId, key) =>
      contexts.commitContext(transfers, principal, buildId, transferId, key),
    abortContext: (principal, buildId) => contexts.abort(principal, buildId),
  });
}
