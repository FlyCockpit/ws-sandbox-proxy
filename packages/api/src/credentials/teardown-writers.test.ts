import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Writer enumeration: every sandbox
 * generation writer and every DELETED write must settle login leases in the
 * same transaction. This greps the non-test sources of the sandbox services
 * and the relay for
 *   (a) `retireSupersededOperations(tx…` callers,
 *   (b) `advanceGeneration: true`,
 *   (c) raw generation increments (`generation + …`, `generation: { increment`),
 *   (d) `state: "DELETED"` writes,
 *   (e) `HOST_LOST` writes (`state: "HOST_LOST"`, `state = 'HOST_LOST'`), which
 *       must move ACTIVE/RELEASING leases to RECOVERY_REQUIRED (§7.1); none
 *       exists today, and a second scan covers every server-side source so a
 *       future writer anywhere is caught,
 * and requires each hit to appear in the reviewed table below, mapped either to
 * a settlement helper called in the same file (within `near` lines when given)
 * or to an exemption that carries a `credential-settlement: exempt` comment
 * just above it. A new writer, a moved one, or a stale entry fails the test.
 */

const ROOT = join(import.meta.dirname, "../../../..");
const SCANNED = ["packages/api/src/sandbox", "apps/server/src/sandbox-relay"];
const PATTERNS = [
  /retireSupersededOperations\(tx/,
  /advanceGeneration: true/,
  /generation"? \+ /,
  /generation: \{\s*increment/,
  /state: "DELETED"/,
  // Every OFFLOADED write settles credentials.
  /state:\s*"OFFLOADED"/,
  /state:\s*"HOST_LOST"/,
  /state\s*=\s*'HOST_LOST'/,
];
const HOST_LOST_PATTERNS = PATTERNS.slice(-2);
/** HOST_LOST may be written by any server-side module (admin, worker, relay). */
const HOST_LOST_SCANNED = ["packages/api/src", "apps/server/src", "apps/worker/src"];
const HELPERS = [
  "settleCredentialTeardown",
  "settleCredentialConvergence",
  "settleCredentialsOnDeleted",
  "settleCredentialsOnHostLost",
  "settleSupersededLaunchLeases",
  // The OFFLOADED settlement (detach, restore exit).
  "settleCredentialsOnOffloaded",
  // The cold reconnect's own advance: it refuses while anything is left to
  // settle (`supersedeColdLaunch` settles it in its own transaction first).
  "hasSupersededLaunchLeases",
] as const;
type Helper = (typeof HELPERS)[number];
type Entry =
  | { file: string; text: string; helper: Helper; near?: number }
  | { file: string; text: string; exempt: string };

const SANDBOXES = "packages/api/src/sandbox/services/sandboxes.ts";
const LEASE = "packages/api/src/sandbox/lease.ts";
const INVENTORY = "apps/server/src/sandbox-relay/inventory-reconcile.ts";
const HANDLERS = "apps/server/src/sandbox-relay/operation-handlers.ts";
const DETACH = "packages/api/src/sandbox/disk-offload/detach.ts";
const RESTORE = "packages/api/src/sandbox/disk-offload/restore-admit.ts";

/** The reviewed table. `text` is the trimmed source line. */
const WRITERS: readonly Entry[] = [
  // User stop (and cold reconnect) share enqueueOwnedOperation's retirement.
  {
    file: SANDBOXES,
    text: "await retireSupersededOperations(tx, owner.ownerId, sandbox.id, boundGeneration);",
    helper: "settleCredentialTeardown",
    near: 15,
  },
  // stopSandbox's spec; settled in enqueueOwnedOperation.
  { file: SANDBOXES, text: "advanceGeneration: true,", helper: "settleCredentialTeardown" },
  {
    file: SANDBOXES,
    text: "const nextGeneration = options.advanceGeneration ? sandbox.generation + 1 : sandbox.generation;",
    exempt: "casExistingSandboxState helper; callers enumerated",
  },
  // System expiry / access / readiness writer; both it and the failed
  // stop/kill retry (queueFailedTeardownRetry) settle through the shared
  // queueSystemTeardown below them.
  {
    file: LEASE,
    text: "const nextGeneration = sandbox.generation + 1;",
    helper: "settleCredentialTeardown",
    near: 350,
  },
  {
    file: LEASE,
    text: "const nextGeneration = sandbox.generation + 1;",
    helper: "settleCredentialTeardown",
    near: 180,
  },
  // Retry cleanup (offload §8.7, U10) re-queues through queueSystemTeardown.
  {
    file: LEASE,
    text: "const nextGeneration = sandbox.generation + 1;",
    helper: "settleCredentialTeardown",
    near: 90,
  },
  {
    file: LEASE,
    text: "await retireSupersededOperations(tx, sandbox.userId, sandbox.id, nextGeneration, now);",
    helper: "settleCredentialTeardown",
    near: 10,
  },
  {
    file: LEASE,
    text: "generation: sandbox.generation + 1,",
    exempt: "read of the queued expiry",
  },
  {
    file: LEASE,
    text: '{ ...operation, generation: sandbox.generation + advanced, state: "FAILED" },',
    exempt: "operation-row settlement only",
  },
  // the only OFFLOADED writer (evict, census, SYSTEM_DETACH).
  {
    file: DETACH,
    text: "generation: { increment: 1 },",
    helper: "settleCredentialsOnOffloaded",
    near: 25,
  },
  { file: DETACH, text: 'state: "OFFLOADED",', helper: "settleCredentialsOnOffloaded", near: 25 },
  {
    file: "packages/api/src/sandbox/disk-offload/evict.ts",
    text: 'where: { id: m.sandboxId, state: "OFFLOADED", diskOffloadId: m.offloadId },',
    exempt: "read of an eviction already detached",
  },
  // restore admission advances an OFFLOADED sandbox.
  {
    file: RESTORE,
    text: "const generation = sandbox.generation + 1;",
    exempt: "OFFLOADED holds no lease (I6, U5) and a restore claims none",
  },
  {
    file: RESTORE,
    text: "await retireSupersededOperations(tx, ownerId, sandbox.id, generation);",
    exempt: "OFFLOADED holds no lease (I6, U5) and a restore claims none",
  },
  // Inventory convergence.
  {
    file: INVENTORY,
    text: "const generation = sandbox.generation + 1;",
    helper: "settleCredentialConvergence",
    near: 90,
  },
  {
    file: INVENTORY,
    text: "await retireSupersededOperations(tx, sandbox.userId, sandbox.id, generation, now);",
    helper: "settleCredentialConvergence",
    near: 10,
  },
  { file: INVENTORY, text: 'state: "DELETED",', helper: "settleCredentialsOnDeleted", near: 25 },
  // A deleted sandbox's remnant destroy (obligeRemnantDestroy): stays DELETED.
  {
    file: INVENTORY,
    text: "const generation = sandbox.generation + 1;",
    helper: "settleCredentialsOnDeleted",
    near: 35,
  },
  { file: INVENTORY, text: 'state: "DELETED",', helper: "settleCredentialsOnDeleted", near: 30 },
  {
    file: INVENTORY,
    text: "await retireSupersededOperations(tx, sandbox.userId, sandbox.id, generation, now);",
    helper: "settleCredentialsOnDeleted",
    near: 3,
  },
  {
    file: INVENTORY,
    text: '{ state: "DELETED" as const, liveResourcesHeld: true },',
    exempt: "census silence read filter",
  },
  {
    file: INVENTORY,
    text: '...(detachedRemnant ? [{ sandboxHostId: null, state: "DELETED" as const }] : []),',
    exempt: "convergence read filter",
  },
  // Lifecycle results.
  { file: HANDLERS, text: 'state: "DELETED",', helper: "settleCredentialsOnDeleted", near: 50 },
  // E2-A-05: a proven-unissued image-missing create retires to DELETED.
  {
    file: HANDLERS,
    text: 'data: { state: "DELETED", sandboxHostId: null, storagePoolId: null },',
    helper: "settleCredentialsOnDeleted",
    near: 5,
  },
  {
    file: "packages/api/src/sandbox/capacity-queue.ts",
    text: 'data: { state: "DELETED", lastErrorCode: code },',
    exempt: "waiting create: no lease, no residue",
  },
  {
    file: "packages/api/src/sandbox/image-store/jobs.ts",
    text: 'data: { state: "DELETED", objectKey: null },',
    exempt: "image artifact row",
  },
  {
    file: "packages/api/src/sandbox/disk-offload/destroy.ts",
    text: 'data: { state: "DELETED" },',
    exempt: "disk offload row",
  },
  // Offload §8.9: the server-completed destroy of an OFFLOADED sandbox.
  {
    file: SANDBOXES,
    text: "generation: sandbox.generation + 1,",
    helper: "settleCredentialsOnDeleted",
  },
  {
    file: SANDBOXES,
    text: "const generation = sandbox.generation + 1;",
    helper: "settleCredentialsOnDeleted",
    near: 40,
  },
  {
    file: SANDBOXES,
    text: "await retireSupersededOperations(tx, owner.ownerId, sandbox.id, generation);",
    helper: "settleCredentialsOnDeleted",
    near: 15,
  },
  // The choke point's own DELETED write for that destroy (its caller settled).
  {
    file: "packages/api/src/sandbox/disk-offload/destroy.ts",
    text: 'state: "DELETED",',
    exempt: "OFFLOADED destroy: caller ran settleCredentialsOnDeleted",
  },
  {
    file: "packages/api/src/sandbox/disk-offload/destroy.ts",
    text: "generation: input.offloaded.generation + 1,",
    exempt: "OFFLOADED destroy: caller ran settleCredentialsOnDeleted",
  },
];

/** Kill: two hits of the same text in sandboxes.ts are counted separately below. */
const KILL_ENTRIES: readonly Entry[] = [
  {
    file: SANDBOXES,
    text: "await retireSupersededOperations(tx, owner.ownerId, sandbox.id, boundGeneration);",
    helper: "settleCredentialTeardown",
    near: 15,
  },
  {
    file: SANDBOXES,
    text: "advanceGeneration: true,",
    helper: "settleCredentialTeardown",
    near: 30,
  },
  // Cold reconnect: an UNKNOWN predecessor's launch leases settle as superseded
  // in their own transaction first; the reconnect's advance refuses until then.
  {
    file: SANDBOXES,
    text: "advanceGeneration: true,",
    helper: "hasSupersededLaunchLeases",
    near: 5,
  },
  {
    file: SANDBOXES,
    text: "advanceGeneration: true,",
    helper: "settleSupersededLaunchLeases",
    near: 5,
  },
  {
    file: SANDBOXES,
    text: "await retireSupersededOperations(tx, owner.ownerId, sandboxId, superseding);",
    helper: "settleSupersededLaunchLeases",
    near: 3,
  },
];

type Hit = { file: string; line: number; text: string; lines: string[] };

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      if (name === "testing" || name === "__fixtures__") continue;
      out.push(...walk(path));
    } else if (
      name.endsWith(".ts") &&
      !name.endsWith(".test.ts") &&
      !name.endsWith(".d.ts") &&
      !name.includes("harness")
    )
      out.push(path);
  }
  return out;
}

function scan(dirs = SCANNED, patterns = PATTERNS): Hit[] {
  const hits: Hit[] = [];
  for (const dir of dirs)
    for (const path of walk(join(ROOT, dir))) {
      const lines = readFileSync(path, "utf8").split("\n");
      lines.forEach((source, index) => {
        if (!/^\s*(\/\/|\*|\/\*)/.test(source) && patterns.some((p) => p.test(source)))
          hits.push({
            file: relative(ROOT, path),
            line: index + 1,
            text: source.trim(),
            lines,
          });
      });
    }
  return hits;
}

const key = (e: { file: string; text: string }) => `${e.file} | ${e.text}`;

/** Checks one hit against one entry; returns a failure message or null. */
function verify(hit: Hit, entry: Entry): string | null {
  const marked = hit.lines
    .slice(Math.max(0, hit.line - 5), hit.line - 1)
    .join("\n")
    .includes("credential-settlement: exempt");
  if ("exempt" in entry)
    return marked
      ? null
      : `${hit.file}:${hit.line} is exempt in the table but lacks a "credential-settlement: exempt" comment`;
  if (marked) return `${hit.file}:${hit.line} is marked exempt but mapped to ${entry.helper}`;
  const call = new RegExp(`\\b${entry.helper}\\(`);
  const window =
    entry.near === undefined
      ? hit.lines
      : hit.lines.slice(Math.max(0, hit.line - 1 - entry.near), hit.line + entry.near);
  return window.some((line) => call.test(line) && !/^\s*(import|export|\/\/|\*)/.test(line))
    ? null
    : `${hit.file}:${hit.line} must call ${entry.helper}${entry.near === undefined ? "" : ` within ${entry.near} lines`}`;
}

describe("credential teardown writer enumeration (§7.5)", () => {
  it("maps every generation writer and DELETED write to its settlement helper", () => {
    const table = [...WRITERS, ...KILL_ENTRIES];
    const byKey = new Map<string, Entry[]>();
    for (const entry of table) byKey.set(key(entry), [...(byKey.get(key(entry)) ?? []), entry]);
    const hitsByKey = new Map<string, Hit[]>();
    for (const hit of scan()) hitsByKey.set(key(hit), [...(hitsByKey.get(key(hit)) ?? []), hit]);

    const failures: string[] = [];
    for (const [k, hits] of hitsByKey) {
      const entries = byKey.get(k) ?? [];
      if (entries.length !== hits.length) {
        failures.push(
          `${k}: ${hits.length} hit(s) at line(s) ${hits.map((h) => h.line).join(", ")} but ${entries.length} reviewed entr(ies) — map the new writer to settleCredentialTeardown / settleCredentialConvergence / settleCredentialsOnDeleted, or exempt it with a comment`,
        );
        continue;
      }
      // Same-text hits: find an assignment using each entry once.
      const assign = (i: number, unused: Entry[]): boolean =>
        i === hits.length ||
        unused.some(
          (entry, j) =>
            verify(hits[i]!, entry) === null &&
            assign(
              i + 1,
              unused.filter((_, n) => n !== j),
            ),
        );
      if (!assign(0, entries))
        failures.push(
          ...hits.map((hit) =>
            entries.map((entry) => verify(hit, entry)).every((m) => m !== null)
              ? (verify(hit, entries[0]!) ?? "")
              : `${k}: no consistent assignment (line ${hit.line})`,
          ),
        );
    }
    for (const k of byKey.keys())
      if (!hitsByKey.has(k)) failures.push(`stale reviewed entry: ${k}`);
    expect(failures).toEqual([]);
  });

  it("finds no HOST_LOST writer outside the reviewed sources", () => {
    const outside = scan(HOST_LOST_SCANNED, HOST_LOST_PATTERNS).filter(
      (hit) => !SCANNED.some((dir) => hit.file.startsWith(`${dir}/`)),
    );
    expect(outside.map((hit) => `${hit.file}:${hit.line}`)).toEqual([]);
  });

  it("recognizes a HOST_LOST write in TS and SQL form (self-check)", () => {
    for (const source of [
      '      data: { state: "HOST_LOST" },',
      "    SET state = 'HOST_LOST', \"updatedAt\" = now()",
    ])
      expect(HOST_LOST_PATTERNS.some((p) => p.test(source))).toBe(true);
    expect(HOST_LOST_PATTERNS.some((p) => p.test("NOT IN ('STOPPED', 'HOST_LOST')"))).toBe(false);
  });

  it("fails on an unmapped writer (self-check)", () => {
    const hit: Hit = {
      file: SANDBOXES,
      line: 2,
      text: "advanceGeneration: true,",
      lines: ["const x = 1;", "advanceGeneration: true,"],
    };
    expect(
      verify(hit, { file: SANDBOXES, text: hit.text, helper: "settleCredentialTeardown", near: 5 }),
    ).not.toBeNull();
    expect(verify(hit, { file: SANDBOXES, text: hit.text, exempt: "x" })).not.toBeNull();
  });
});
