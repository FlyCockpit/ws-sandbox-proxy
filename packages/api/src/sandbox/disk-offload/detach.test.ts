import { readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Sweep S17 with the plan's own alternation:
 * `"OFFLOADED"|'OFFLOADED'|state: next|state: input.next|state: nextSandbox`
 * over packages/api/src, apps/server/src and packages/db/src. A literal
 * write of the OFFLOADED state appears only in `disk-offload/detach.ts`;
 * every computed generic writer guards `!== "OFFLOADED"` (U7). Read-only
 * literals are listed here, reviewed; a new one fails until reviewed.
 */
const ROOT = resolve(import.meta.dirname, "../../../../..");
const SCAN = ["packages/api/src", "apps/server/src", "packages/db/src"];
const SWEEP = /"OFFLOADED"|'OFFLOADED'|state: next\b|state: input\.next|state: nextSandbox/;
const LITERAL_WRITE = /\bstate:\s*["']OFFLOADED["']/;
const COMPUTED_WRITE = /\bstate: (next|input\.next|nextSandbox),?$/;

/** Reviewed non-writing occurrences: path → count. */
const READS: Record<string, number> = {
  "packages/api/src/routers/admin-observability.ts": 1, // state filter list
  "packages/api/src/sandbox/state-transitions.ts": 6, // transition table + mapping
  "packages/api/src/sandbox/sharing-access.ts": 2, // SQL `<> 'OFFLOADED'`; reconcile skips it (C7)
  "packages/api/src/sandbox/image-store/captures.ts": 1, // capture refused disk_offloaded (C7)
  "packages/api/src/sandbox/terminal-tickets.ts": 1, // a stopped state for bindings (C7)
  "packages/api/src/template-builds/cleanup.ts": 1, // `Exclude<…, "OFFLOADED">` (C7)
  "packages/api/src/sandbox/disk-offload/evict.ts": 1, // `where` (already detached)
  "packages/api/src/sandbox/disk-offload/disk-view.ts": 1, // DTO `disk.location: store`
  "apps/server/src/sandbox-relay/inventory-reconcile.ts": 4, // routing + fences
  "apps/server/src/sandbox-relay/operation-handlers.ts": 3, // OFFLOADED-first routing + the U7 fence
  "packages/api/src/credentials/teardown.ts": 2, // the two OFFLOADED settlement arms (U5)
  "packages/api/src/sandbox/disk-offload/destroy.ts": 1, // the OFFLOADED destroy `where` constant
  "packages/api/src/sandbox/idempotency.ts": 1, // hostless transport test
  "packages/api/src/sandbox/operation-transaction.ts": 1, // restore-intent domain test
  "packages/api/src/sandbox/launch-branches.inventory.ts": 2, // inventory key text
  "packages/api/src/sandbox/disk-offload/restore-admit.ts": 1, // the restorable-state constant
  "packages/api/src/lib/sdk-key-access.ts": 1, // restore-intent target `where`
  "packages/api/src/sandbox/services/sandboxes.ts": 2, // reconnect → restore routing; the OFFLOADED destroy constant
  "packages/api/src/sandbox/sharing-authority.ts": 1, // restore placement principals
  "packages/api/src/sandbox/tunnels/controller.ts": 1, // port changes skip offloaded sandboxes (SQL)
};

function sources(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== "node_modules" && entry.name !== "testing") out.push(...sources(path));
    } else if (entry.name.endsWith(".ts") && !/\.(test|pg\.test|s3\.test)\.ts$/.test(entry.name))
      out.push(path);
  }
  return out;
}

describe("S17: detachToOffloaded is the only OFFLOADED writer", () => {
  const hits = SCAN.flatMap((dir) => sources(resolve(ROOT, dir))).flatMap((file) =>
    readFileSync(file, "utf8")
      .split("\n")
      .map((line, i) => ({ file: relative(ROOT, file), line: line.trim(), at: i + 1 }))
      .filter((hit) => SWEEP.test(hit.line)),
  );

  it("writes the literal state only in disk-offload/detach.ts", () => {
    const writers = hits.filter((hit) => LITERAL_WRITE.test(hit.line) && !/where/.test(hit.line));
    expect([...new Set(writers.map((hit) => hit.file))]).toEqual([
      "packages/api/src/sandbox/disk-offload/detach.ts",
    ]);
    expect(writers).toHaveLength(1);
  });

  it("every computed generic writer guards !== OFFLOADED in the same file", () => {
    const computed = hits.filter((hit) => COMPUTED_WRITE.test(hit.line));
    expect(computed.length).toBeGreaterThan(0);
    for (const hit of computed) {
      const text = readFileSync(resolve(ROOT, hit.file), "utf8");
      const variable = hit.line.match(COMPUTED_WRITE)?.[1] ?? "";
      expect(text, `${hit.file}:${hit.at}`).toContain(
        `requireRelayFence(${variable} !== "OFFLOADED")`,
      );
    }
  });

  it("every other occurrence is a reviewed read", () => {
    const counts: Record<string, number> = {};
    for (const hit of hits) {
      if (hit.file.endsWith("disk-offload/detach.ts") || COMPUTED_WRITE.test(hit.line)) continue;
      counts[hit.file] = (counts[hit.file] ?? 0) + 1;
    }
    expect(counts).toEqual(READS);
  });
});
