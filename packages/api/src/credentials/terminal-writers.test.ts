import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Terminal-writer enumeration: every write of
 * a sandbox operation row must settle the operation's credential work in the
 * same transaction when it can make the operation terminal. A never-sent
 * operation (a dispatch refusal, an undelivered dispatch, an allocation the
 * host proved never issued) gets no host result to repair it later, so a
 * missed settlement strands reserved slots and RELEASING leases.
 *
 * This greps every server-side source for operation-row writers
 * (`casActiveOperation(tx…`, `sandboxOperation.update…(`, raw
 * `UPDATE sandbox_mutation_operation`) and requires each hit to appear in the
 * reviewed table below: mapped to `settleOperationCredentials` (the one
 * terminal finalization helper, teardown.ts) or a named settlement helper,
 * called in the same file (within `near` lines when given), or exempt with
 * the reason it cannot strand credential work. A new writer, a moved one, or
 * a stale entry fails. The generation and DELETED writers have their own
 * enumeration (teardown-writers.test.ts).
 *
 * Operation rows CREATED already terminal (a STOPPED-sandbox attach recorded
 * SUCCEEDED, a convergence proof, a waiting create's teardown) are terminal
 * writers too: every create (`sandboxOperation.create(`, `recordedOperation(`,
 * raw `INSERT INTO sandbox_mutation_operation`) is enumerated in `CREATES`.
 * A `queued` entry is checked mechanically (its literal's first `state:` is
 * `"QUEUED"`); any other create maps to a settlement helper or is exempt
 * with the reason it carries no credential work.
 */

const ROOT = join(import.meta.dirname, "../../../..");
const SCANNED = ["apps/server/src", "apps/worker/src", "packages/api/src", "packages/db/src"];
const PATTERNS = [
  /casActiveOperation\(tx/,
  /casActiveOperation\($/,
  /sandboxOperation\.update(Many)?\(/,
  /UPDATE sandbox_mutation_operation/,
];
const CREATE_PATTERNS = [
  /sandboxOperation\.(create|createMany|upsert)\(/,
  /recordedOperation\(/,
  /INSERT INTO sandbox_mutation_operation/,
];
const HELPERS = [
  "settleOperationCredentials",
  "settleCredentialsOnStopped",
  "settleTerminalTeardown",
  "settleCredentialConvergence",
  "detachAttachment",
  // The OFFLOADED settlement of a restore exit.
  "settleCredentialsOnOffloaded",
] as const;
type Helper = (typeof HELPERS)[number];
type Entry =
  | { file: string; text: string; helper: Helper; near?: number }
  | { file: string; text: string; exempt: string }
  | { file: string; text: string; queued: true };

const OUTBOX = "apps/server/src/sandbox-relay/outbox-processor.ts";
const INVENTORY = "apps/server/src/sandbox-relay/inventory-reconcile.ts";
const HANDLERS = "apps/server/src/sandbox-relay/operation-handlers.ts";
const FENCE = "packages/api/src/sandbox/relay-fence.ts";
const RESULTS = "packages/api/src/sandbox/operation-results.ts";
const CAPTURES = "packages/api/src/sandbox/image-store/captures.ts";
const CONTROLS = "packages/api/src/sandbox/process-controls.ts";
const RESTORE = "packages/api/src/sandbox/disk-offload/restore-admit.ts";

const CAS = "await casActiveOperation(tx, fence, {";
const CAS_OPEN = "await casActiveOperation(";
const UPDATE = "await tx.sandboxOperation.updateMany({";
const NON_TERMINAL = "non-terminal write (no credential work can end here)";
const RESULT_STORE = "result storage fields only; the state is written elsewhere";

/** The reviewed table. `text` is the trimmed source line. */
const WRITERS: readonly Entry[] = [
  // Dispatch: obsolete retirement, refusals, claims.
  {
    file: OUTBOX,
    text: "const retired = await tx.sandboxOperation.updateMany({",
    exempt:
      "obsolete retirement: CANCEL_REQUESTED/UNKNOWN_OUTCOME of a superseded attempt; the superseding generation writer settled its leases",
  },
  { file: OUTBOX, text: CAS, helper: "settleOperationCredentials", near: 15 },
  { file: OUTBOX, text: CAS, helper: "settleOperationCredentials", near: 15 },
  { file: OUTBOX, text: CAS, helper: "settleOperationCredentials", near: 15 },
  {
    file: OUTBOX,
    text: "const requested = await tx.sandboxOperation.updateMany({",
    exempt: NON_TERMINAL,
  },
  {
    file: OUTBOX,
    text: "await casActiveOperation(tx, fence, { dispatchAttempt: operation.dispatchAttempt });",
    exempt: NON_TERMINAL,
  },
  {
    file: OUTBOX,
    text: "const claimed = await tx.sandboxOperation.updateMany({",
    exempt: NON_TERMINAL,
  },
  { file: OUTBOX, text: CAS_OPEN, exempt: "stdin control send: dispatchAttempt only" },
  {
    file: OUTBOX,
    text: "const failed = await tx.sandboxOperation.updateMany({",
    helper: "settleOperationCredentials",
    near: 20,
  },
  {
    file: OUTBOX,
    text: "const written = await tx.sandboxOperation.updateMany({",
    helper: "settleOperationCredentials",
    near: 20,
  },
  {
    file: OUTBOX,
    text: "} else await casActiveOperation(tx, fence, data);",
    helper: "settleOperationCredentials",
    near: 5,
  },
  // Inventory reconciliation.
  {
    file: INVENTORY,
    text: UPDATE,
    exempt: "presence witness on an already FAILED allocation's result",
  },
  {
    file: INVENTORY,
    text: "const failed = await tx.sandboxOperation.updateMany({",
    helper: "settleOperationCredentials",
    near: 25,
  },
  // A pending stop/kill proven by inventory: finishConvergence settles STOPPED/DELETED.
  {
    file: INVENTORY,
    text: "const settled = await tx.sandboxOperation.updateMany({",
    helper: "settleCredentialsOnStopped",
  },
  {
    file: INVENTORY,
    text: UPDATE,
    exempt:
      "UNKNOWN launches at or below a host-proven expiry: the expiry's generation writer settled their launch leases (settleCredentialTeardown)",
  },
  // Host results and reconciliation.
  {
    file: HANDLERS,
    text: "const written = await tx.sandboxOperation.updateMany({",
    helper: "settleOperationCredentials",
  },
  {
    file: HANDLERS,
    text: "const written = await tx.sandboxOperation.updateMany({",
    exempt: "progress: ACCEPTED/RUNNING",
  },
  {
    file: HANDLERS,
    text: "const updated = await tx.sandboxOperation.updateMany({",
    exempt: "process birth fields",
  },
  { file: HANDLERS, text: UPDATE, exempt: "lease-from-ready deadline field" },
  {
    file: HANDLERS,
    text: CAS_OPEN,
    exempt: "UNKNOWN_OUTCOME only: no credential change until a result or retry",
  },
  {
    file: HANDLERS,
    text: "const adopted = await tx.sandboxOperation.updateMany({",
    exempt: NON_TERMINAL,
  },
  { file: HANDLERS, text: CAS, helper: "settleOperationCredentials", near: 12 },
  {
    file: HANDLERS,
    text: "const requeued = await tx.sandboxOperation.updateMany({",
    exempt: NON_TERMINAL,
  },
  // Fence primitives.
  {
    file: FENCE,
    text: "const written = await tx.sandboxOperation.updateMany({",
    exempt: "the casActiveOperation primitive; its callers are enumerated",
  },
  {
    file: FENCE,
    text: "const written = await tx.sandboxOperation.updateMany({",
    exempt: "cancelQueuedOperation: CANCELLABLE_OPERATION_KINDS carry no credential work",
  },
  {
    file: FENCE,
    text: UPDATE,
    exempt:
      "settleSupersededOperations: superseded predecessors; the superseding generation writer settled their leases",
  },
  {
    file: FENCE,
    text: UPDATE,
    exempt:
      "settleSupersededOperations: superseded predecessors; the superseding generation writer settled their leases",
  },
  { file: FENCE, text: UPDATE, exempt: "retireSupersededOperations: CANCEL_REQUESTED" },
  // Expiry / readiness failure of a launch.
  {
    file: "packages/api/src/sandbox/lease.ts",
    text: "const finished = await tx.sandboxOperation.updateMany({",
    helper: "settleOperationCredentials",
    near: 25,
  },
  // Template capture operations carry no logins.
  { file: CAPTURES, text: UPDATE, exempt: "template capture operation" },
  {
    file: CAPTURES,
    text: "await tx.sandboxOperation.update({",
    exempt: "template capture operation",
  },
  {
    file: CAPTURES,
    text: "await tx.sandboxOperation.update({",
    exempt: "template capture operation",
  },
  {
    file: "packages/api/src/sandbox/image-store/capture-result.ts",
    text: UPDATE,
    exempt: "template capture operation: RUNNING",
  },
  {
    file: "apps/server/src/sandbox-relay/image-handlers.ts",
    text: "const adopted = await tx.sandboxOperation.updateMany({",
    exempt:
      "recorded-capture adoption: moves only dispatchedConnectionEpoch of an ACCEPTED/RUNNING template capture operation, never its state or result",
  },
  { file: CONTROLS, text: "await tx.sandboxOperation.update({", exempt: "stdin sequence" },
  {
    file: CONTROLS,
    text: "const changed = await tx.sandboxOperation.updateMany({",
    exempt: "CANCEL_REQUESTED",
  },
  // A cancelled never-dispatched access KILL: no new generation, leases settle.
  {
    file: "packages/api/src/sandbox/sharing-access.ts",
    text: UPDATE,
    helper: "settleTerminalTeardown",
    near: 30,
  },
  { file: RESULTS, text: "await tx.sandboxOperation.update({", exempt: RESULT_STORE },
  { file: RESULTS, text: "await tx.sandboxOperation.update({", exempt: RESULT_STORE },
  { file: RESULTS, text: "await tx.sandboxOperation.update({", exempt: RESULT_STORE },
  { file: RESULTS, text: UPDATE, exempt: "process description purge" },
  {
    file: "packages/api/src/sandbox/operation-transaction.ts",
    text: "await tx.sandboxOperation.update({",
    exempt:
      "the acceptance digest snapshot (offload §8.3a): writes digestContext only, never state",
  },
  {
    file: "packages/api/src/sandbox/placement-materialize.ts",
    text: "const updated = await tx.sandboxOperation.updateMany({",
    exempt: "a queued create accepted at placement: QUEUED",
  },
  // restore admission and its wait.
  {
    file: RESTORE,
    text: UPDATE,
    exempt: "a restore placed: the operation's generation, still QUEUED",
  },
  {
    file: RESTORE,
    text: "await tx.sandboxOperation.update({",
    exempt: NON_TERMINAL,
  },
  {
    file: RESTORE,
    text: UPDATE,
    exempt: "a waiting restore ended: QUEUED, never dispatched, it claimed no lease",
  },
  {
    file: "packages/api/src/sandbox/disk-offload/restore-exit.ts",
    text: UPDATE,
    exempt:
      "UNKNOWN → FAILED of a restore attempt before its SYSTEM_DETACH kill: the caller already ran settleOperationCredentials for UNKNOWN; the kill's settleCredentialsOnOffloaded settles the attempt",
  },
  // Waiting creates claim nothing before placement.
  {
    file: "packages/api/src/sandbox/capacity-queue.ts",
    text: UPDATE,
    exempt: "waiting create: no lease before placement",
  },
  {
    file: "packages/db/src/account-deletion.ts",
    text: "UPDATE sandbox_mutation_operation o SET state = 'FAILED', \"errorCode\" = 'access_denied',",
    exempt: "waiting creates: no lease before placement",
  },
];

const LIVE = "packages/api/src/credentials/live.ts";
const LIVE_OP = "const op = await recordedOperation(tx, owner, {";
const OP_CREATE = "const operation = await tx.sandboxOperation.create({";

/** The reviewed creates. Every create of a terminal row says how it settles. */
const CREATES: readonly Entry[] = [
  { file: "apps/server/src/sandbox-transfers/store.ts", text: OP_CREATE, queued: true },
  // A convergence proof recorded SUCCEEDED: its settlement runs right after.
  { file: INVENTORY, text: OP_CREATE, helper: "settleCredentialConvergence", near: 25 },
  // A deleted sandbox's remnant destroy (obligeRemnantDestroy).
  { file: INVENTORY, text: OP_CREATE, queued: true },
  {
    file: "packages/api/src/sandbox/process-signals.ts",
    text: "const control = await tx.sandboxOperation.create({",
    exempt: "SIGNAL_PROCESS: schema default QUEUED; a process control carries no credential work",
  },
  { file: "packages/api/src/sandbox/capacity-queue.ts", text: OP_CREATE, queued: true },
  {
    file: "packages/api/src/sandbox/capacity-queue.ts",
    text: "return tx.sandboxOperation.create({",
    exempt:
      "recordWaitingTeardown: a stop/kill of a create still waiting for capacity, recorded SUCCEEDED; a waiting create holds no lease, spec or residue (claims happen at placement). Also a kill of an already-DELETED sandbox, whose leases its DELETED write settled",
  },
  { file: CAPTURES, text: OP_CREATE, queued: true },
  { file: "packages/api/src/sandbox/lease.ts", text: OP_CREATE, queued: true },
  { file: "packages/api/src/sandbox/lease.ts", text: OP_CREATE, queued: true },
  { file: "packages/api/src/sandbox/placement-materialize.ts", text: OP_CREATE, queued: true },
  { file: RESTORE, text: OP_CREATE, queued: true },
  {
    file: "packages/api/src/sandbox/services/sandboxes.ts",
    text: "const row = await tx.sandboxOperation.create({",
    queued: true,
  },
  { file: "packages/api/src/sandbox/services/sandboxes.ts", text: OP_CREATE, queued: true },
  // Offload §8.9: the server-completed destroy of an OFFLOADED sandbox; its
  // DELETED write settles through settleCredentialsOnDeleted (teardown-writers).
  {
    file: "packages/api/src/sandbox/services/sandboxes.ts",
    text: "const destroyed = await tx.sandboxOperation.create({",
    exempt: "OFFLOADED destroy: settled by its DELETED write's settleCredentialsOnDeleted",
  },
  {
    file: "packages/api/src/credentials/live-ops.ts",
    text: "return tx.sandboxOperation.create({",
    exempt: "the recordedOperation primitive: each caller is enumerated with its state",
  },
  {
    file: "packages/api/src/credentials/login-sessions.ts",
    text: "const op = await recordedOperation(tx, flow, {",
    queued: true,
  },
  // Live attach / free (§10.1).
  {
    file: LIVE,
    text: LIVE_OP,
    exempt:
      "an attach to a STOPPED sandbox, recorded SUCCEEDED: it writes the attachment row only — no lease is claimed and no spec stored, so nothing can strand; the next start claims it under the resume rules",
  },
  { file: LIVE, text: LIVE_OP, queued: true },
  // A free with no live lease, recorded SUCCEEDED: the attachment ends inline.
  { file: LIVE, text: LIVE_OP, helper: "detachAttachment", near: 3 },
  { file: LIVE, text: LIVE_OP, queued: true },
];

type Hit = { file: string; line: number; text: string; lines: string[] };

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      if (name === "testing" || name === "__fixtures__" || name === "node_modules") continue;
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

function scan(patterns: readonly RegExp[] = PATTERNS): Hit[] {
  const hits: Hit[] = [];
  for (const dir of SCANNED)
    for (const path of walk(join(ROOT, dir))) {
      const lines = readFileSync(path, "utf8").split("\n");
      lines.forEach((source, index) => {
        if (/^\s*(\/\/|\*|\/\*)/.test(source) || /^\s*export async function/.test(source)) return;
        if (patterns.some((p) => p.test(source.trim())))
          hits.push({ file: relative(ROOT, path), line: index + 1, text: source.trim(), lines });
      });
    }
  return hits;
}

const key = (e: { file: string; text: string }) => `${e.file} | ${e.text}`;

/** Checks one hit against one entry; returns a failure message or null. */
function verify(hit: Hit, entry: Entry): string | null {
  if ("exempt" in entry) return entry.exempt.trim().length > 0 ? null : "exemption without reason";
  if ("queued" in entry) {
    // The create's literal: its first `state:` within the next 20 lines.
    const state = hit.lines
      .slice(hit.line, hit.line + 20)
      .find((line) => /^\s*state: /.test(line))
      ?.trim();
    return state === 'state: "QUEUED",'
      ? null
      : `${hit.file}:${hit.line} is reviewed as a QUEUED create but its state is ${state ?? "absent"}`;
  }
  const call = new RegExp(`\\b${entry.helper}\\(`);
  const window =
    entry.near === undefined
      ? hit.lines
      : hit.lines.slice(Math.max(0, hit.line - 1 - entry.near), hit.line + entry.near);
  return window.some((line) => call.test(line) && !/^\s*(import|export|\/\/|\*)/.test(line))
    ? null
    : `${hit.file}:${hit.line} must call ${entry.helper}${entry.near === undefined ? "" : ` within ${entry.near} lines`}`;
}

/** Every hit matched to a reviewed entry (each entry used once); the failures. */
function enumerate(table: readonly Entry[], hits: readonly Hit[]): string[] {
  const byKey = new Map<string, Entry[]>();
  for (const entry of table) byKey.set(key(entry), [...(byKey.get(key(entry)) ?? []), entry]);
  const hitsByKey = new Map<string, Hit[]>();
  for (const hit of hits) hitsByKey.set(key(hit), [...(hitsByKey.get(key(hit)) ?? []), hit]);

  const failures: string[] = [];
  for (const [k, found] of hitsByKey) {
    const entries = byKey.get(k) ?? [];
    if (entries.length !== found.length) {
      failures.push(
        `${k}: ${found.length} hit(s) at line(s) ${found.map((h) => h.line).join(", ")} but ${entries.length} reviewed entr(ies) — call settleOperationCredentials after a terminal write, or exempt it with its reason`,
      );
      continue;
    }
    // Same-text hits: find an assignment using each entry once.
    const assign = (i: number, unused: Entry[]): boolean =>
      i === found.length ||
      unused.some(
        (entry, j) =>
          verify(found[i]!, entry) === null &&
          assign(
            i + 1,
            unused.filter((_, n) => n !== j),
          ),
      );
    if (!assign(0, entries))
      failures.push(
        ...found.map(
          (hit) =>
            entries.map((entry) => verify(hit, entry)).find((m) => m !== null) ??
            `${k}: no consistent assignment (line ${hit.line})`,
        ),
      );
  }
  for (const k of byKey.keys()) if (!hitsByKey.has(k)) failures.push(`stale reviewed entry: ${k}`);
  return failures;
}

describe("terminal operation writer enumeration (§7.1)", () => {
  it("maps every operation-row writer to settleOperationCredentials (or a reviewed exemption)", () => {
    expect(enumerate(WRITERS, scan())).toEqual([]);
  });

  it("maps every operation-row create: QUEUED (checked), settled, or exempt with its reason", () => {
    expect(enumerate(CREATES, scan(CREATE_PATTERNS))).toEqual([]);
  });

  it("a create reviewed as QUEUED that is written terminal fails (self-check)", () => {
    const create = "const operation = await tx.sandboxOperation.create({";
    const hit = (state: string): Hit => ({
      file: OUTBOX,
      line: 1,
      text: create,
      lines: [create, "  data: {", `    state: ${state},`, "  },", "});"],
    });
    const entry: Entry = { file: OUTBOX, text: create, queued: true };
    expect(verify(hit('"QUEUED"'), entry)).toBeNull();
    expect(verify(hit('"SUCCEEDED"'), entry)).not.toBeNull();
    expect(enumerate([], [hit('"SUCCEEDED"')])).toHaveLength(1);
  });

  it("fails on an unmapped terminal writer (self-check)", () => {
    const hit: Hit = {
      file: OUTBOX,
      line: 2,
      text: CAS,
      lines: ["const x = 1;", CAS, "});"],
    };
    expect(
      verify(hit, { file: OUTBOX, text: CAS, helper: "settleOperationCredentials", near: 5 }),
    ).not.toBeNull();
    expect(
      verify(
        { ...hit, lines: [...hit.lines, "await settleOperationCredentials(tx, input);"] },
        { file: OUTBOX, text: CAS, helper: "settleOperationCredentials", near: 5 },
      ),
    ).toBeNull();
  });
});
