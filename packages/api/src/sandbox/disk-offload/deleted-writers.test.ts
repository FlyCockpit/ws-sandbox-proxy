import { readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Sweep S2 with the plan's own alternation:
 * `"DELETED"|'DELETED'|sandboxStateForLifecycleResult|finishConvergence`
 * over packages/api/src, apps/server/src and packages/db/src.
 *
 * Every hit that can WRITE a sandbox DELETED (a literal state write, or a
 * computed one through the lifecycle mapping and `finishConvergence`) is
 * listed below with its routing: intent-aware (an OWNER_DESTROY ends the
 * offload through `endOffloadForDestroy` first), offload-aware (it never
 * maps a sandbox with `diskOffloadId` to DELETED), or provably
 * `diskOffloadId IS NULL` (the row it writes cannot hold one). The
 * `sandbox_instance_deleted_offload` CHECK aborts any writer that is wrong.
 * Every other hit is a reviewed read, counted per file. A new writer, a
 * moved one or a new read fails until reviewed.
 */
const ROOT = resolve(import.meta.dirname, "../../../../..");
const SCAN = ["packages/api/src", "apps/server/src", "packages/db/src"];
const SWEEP = /"DELETED"|'DELETED'|sandboxStateForLifecycleResult|finishConvergence/;
const WRITE =
  /SET state = 'DELETED'|data: \{ state: "DELETED"|^state: "DELETED",$|sandboxStateForLifecycleResult\(|finishConvergence\(/;

const INVENTORY = "apps/server/src/sandbox-relay/inventory-reconcile.ts";
const HANDLERS = "apps/server/src/sandbox-relay/operation-handlers.ts";

/** Reviewed writers: `file | trimmed line` → routing. */
const WRITERS: Record<string, string> = {
  // Lifecycle mapping: KILL SUCCEEDED + SYSTEM_DETACH → OFFLOADED (I17).
  "packages/api/src/sandbox/state-transitions.ts | export function sandboxStateForLifecycleResult(":
    "intent-aware: the mapping itself",
  [`${HANDLERS} | let nextSandbox = sandboxStateForLifecycleResult(`]:
    "intent-aware: endOffloadForDestroy before the DELETED write (OWNER_DESTROY)",
  [`${HANDLERS} | data: { state: "DELETED", sandboxHostId: null, storagePoolId: null },`]:
    "diskOffloadId IS NULL: image-missing retire of a create (a restore exits first)",
  [`${HANDLERS} | state: "DELETED",`]: "a `where` of the DELETED detach (already written)",
  [`${HANDLERS} | const next = sandboxStateForLifecycleResult(kind, opState, endState, current, errorCode);`]:
    "read-only prediction (wouldAuthorSandboxState)",
  [`${INVENTORY} | : sandboxStateForLifecycleResult(`]:
    "intent-aware: SYSTEM_DETACH → settleSystemDetachKill; DELETED → finishConvergence",
  [`${INVENTORY} | await finishConvergence(tx, sender, sandbox, {`]:
    "intent-aware: endOffloadForDestroy before DELETED; convergence evidence never DELETED with diskOffloadId",
  [`${INVENTORY} | async function finishConvergence(`]:
    "intent-aware: endOffloadForDestroy for an owner destroy before the state write",
  [`${INVENTORY} | state: "DELETED",`]: "`where` filters of remnant rows (already DELETED)",
  'packages/api/src/sandbox/capacity-queue.ts | data: { state: "DELETED", lastErrorCode: code },':
    "diskOffloadId IS NULL: a WAITING_FOR_CAPACITY create never offloaded",
  'packages/api/src/sandbox/disk-offload/destroy.ts | state: "DELETED",':
    "intent-aware: endOffloadForDestroy itself, for the server-completed OFFLOADED destroy",
  'packages/api/src/sandbox/image-store/jobs.ts | data: { state: "DELETED", objectKey: null },':
    "image artifact row, not a sandbox",
  'packages/api/src/sandbox/disk-offload/destroy.ts | data: { state: "DELETED" },':
    "disk offload row (after the deferred shred), not a sandbox",
  "packages/db/src/account-deletion.ts | UPDATE sandbox_instance s SET state = 'DELETED', \"lastErrorCode\" = 'access_denied',":
    "diskOffloadId IS NULL: only WAITING_FOR_CAPACITY rows",
};

/** Reviewed non-writing occurrences: path → count. */
const READS: Record<string, number> = {
  "apps/server/src/sandbox-relay/execution-config-ack.ts": 1,
  "apps/server/src/sandbox-relay/inventory-reconcile.ts": 11,
  "apps/server/src/sandbox-relay/operation-handlers.ts": 6,
  "apps/server/src/sandbox-relay/outbox-processor.ts": 2,
  "apps/server/src/sandbox-transfers/store.ts": 1,
  "packages/api/src/credentials/captures.ts": 2,
  "packages/api/src/credentials/census.ts": 1,
  "packages/api/src/credentials/service.ts": 2,
  "packages/api/src/credentials/teardown.ts": 3,
  "packages/api/src/routers/admin-observability.ts": 1,
  "packages/api/src/sandbox/disk-offload/destroy.ts": 1,
  "packages/api/src/sandbox/disk-offload/disk-view.ts": 1,
  "packages/api/src/sandbox/disk-offload/maintenance.ts": 2,
  "packages/api/src/sandbox/disk-offload/pin.ts": 1,
  "packages/api/src/sandbox/host-admission.ts": 2,
  // + captureStoreDeadline: a deleted build VM ends its capture's storage.
  "packages/api/src/sandbox/image-store/captures.ts": 2,
  "packages/api/src/sandbox/image-store/jobs.ts": 3,
  "packages/api/src/sandbox/image-store/references.ts": 1,
  "packages/api/src/sandbox/image-store/settings.ts": 1,
  // A key's live-sandbox count excludes destroyed sandboxes; read.
  "packages/api/src/sandbox/key-sandbox-limit.ts": 1,
  "packages/api/src/sandbox/launch-branches.inventory.ts": 2,
  "packages/api/src/sandbox/outbox-retention.ts": 1,
  "packages/api/src/sandbox/relay-fence.ts": 2,
  "packages/api/src/sandbox/sandbox-list.ts": 2,
  "packages/api/src/sandbox/sandbox-names.ts": 1,
  "packages/api/src/sandbox/services/hosts.ts": 1,
  "packages/api/src/sandbox/services/sandboxes.ts": 2,
  "packages/api/src/sandbox/sharing-access.ts": 2,
  "packages/api/src/sandbox/state-transitions.ts": 13,
  "packages/api/src/sandbox/terminal-tickets.ts": 1,
  // CLI shells: a destroyed state ends a connection; read.
  "packages/api/src/sandbox/connect-binding.ts": 1,
  // Preview tunnels: a destroyed sandbox's tunnel is deleted, and port
  // changes skip destroyed sandboxes; reads.
  "packages/api/src/sandbox/tunnels/controller.ts": 2,
  "packages/api/src/sandbox/tunnels/service.ts": 4,
  "packages/api/src/template-builds/cleanup.ts": 1,
  "packages/api/src/template-builds/decide.ts": 1,
  "packages/api/src/template-builds/orchestrator.ts": 1,
  "packages/db/src/account-deletion.ts": 2,
};

function sources(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!["node_modules", "testing", "generated"].includes(entry.name))
        out.push(...sources(path));
    } else if (
      entry.name.endsWith(".ts") &&
      !entry.name.endsWith(".d.ts") &&
      !/\.(test|pg\.test|s3\.test)\.ts$/.test(entry.name) &&
      !entry.name.includes("harness")
    )
      out.push(path);
  }
  return out;
}

describe("S2: every DELETED writer is routed (§8.9)", () => {
  const hits = SCAN.flatMap((dir) => sources(resolve(ROOT, dir))).flatMap((file) =>
    readFileSync(file, "utf8")
      .split("\n")
      .map((line) => ({ file: relative(ROOT, file), line: line.trim() }))
      .filter((hit) => SWEEP.test(hit.line) && !/^(\/\/|\*|\/\*)/.test(hit.line)),
  );

  it("lists every writer with its routing and no stale entry", () => {
    const writers = new Set(
      hits.filter((hit) => WRITE.test(hit.line)).map((hit) => `${hit.file} | ${hit.line}`),
    );
    expect([...writers].sort()).toEqual(Object.keys(WRITERS).sort());
  });

  it("every other occurrence is a reviewed read", () => {
    const counts: Record<string, number> = {};
    for (const hit of hits) {
      if (WRITE.test(hit.line)) continue;
      counts[hit.file] = (counts[hit.file] ?? 0) + 1;
    }
    expect(counts).toEqual(READS);
  });

  it("the owner-destroy writers end the offload through the choke point first", () => {
    for (const file of [HANDLERS, INVENTORY, "packages/api/src/sandbox/services/sandboxes.ts"]) {
      const text = readFileSync(resolve(ROOT, file), "utf8");
      expect(text, file).toContain("endOffloadForDestroy(tx, {");
    }
  });
});
