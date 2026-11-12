import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * RECOVERY_REQUIRED writer enumeration: every
 * move of a lease to RECOVERY_REQUIRED must write a `recovery_required`
 * credential_event in the same transaction, because that row is what fires
 * the `credential.recovery_required` webhook. `requireLeaseRecovery` in
 * `leases.ts` is the one writer that does both. This scans every server-side
 * source (TS and SQL, tests excluded) for anything that writes the state —
 * SQL `state = 'RECOVERY_REQUIRED'` (SET or CASE), a `'RECOVERY_REQUIRED'::`
 * cast, a Prisma `state: "RECOVERY_REQUIRED"` / `{ set: … }`, or the enum
 * member `CredentialLeaseState.RECOVERY_REQUIRED` — and allows exactly the
 * helper's own statement. Reads use `state::text IN (…)` lists or arrays and
 * are not matched; a read written as an equality must use `state::text =`
 * (SQL) or `{ equals: … }` (Prisma).
 */

const ROOT = join(import.meta.dirname, "../../../..");
const SCANNED = ["packages/api/src", "apps/server/src", "apps/worker/src", "packages/db"];
const HELPER_FILE = "packages/api/src/credentials/leases.ts";
const HELPER = "requireLeaseRecovery";

const WRITE_PATTERNS = [
  /\bstate"?\s*=\s*'RECOVERY_REQUIRED'/g,
  /\bTHEN\s+'RECOVERY_REQUIRED'/g,
  /'RECOVERY_REQUIRED'\s*::/g,
  /\bstate"?\s*:\s*(\{\s*set\s*:\s*)?"RECOVERY_REQUIRED"/g,
  /CredentialLeaseState\.RECOVERY_REQUIRED/g,
];

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    if (name === "node_modules" || name === "dist" || name === "generated") continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...walk(path));
    else if (
      (name.endsWith(".ts") || name.endsWith(".sql")) &&
      !name.endsWith(".test.ts") &&
      !name.endsWith(".d.ts")
    )
      out.push(path);
  }
  return out;
}

type Hit = { file: string; line: number; source: string };

function hitsIn(file: string, source: string): Hit[] {
  const hits: Hit[] = [];
  for (const pattern of WRITE_PATTERNS)
    for (const match of source.matchAll(pattern)) {
      const line = source.slice(0, match.index).split("\n").length;
      const text = source.split("\n")[line - 1] ?? "";
      if (/^\s*(\/\/|\*|\/\*|--)/.test(text)) continue;
      // An index predicate in committed migration SQL reads the state; it never writes it.
      if (/^\s*CREATE\s+(UNIQUE\s+)?INDEX\b/i.test(text)) continue;
      hits.push({ file, line, source: text.trim() });
    }
  return hits;
}

function scan(): Hit[] {
  return SCANNED.flatMap((dir) =>
    walk(join(ROOT, dir)).flatMap((path) =>
      hitsIn(relative(ROOT, path), readFileSync(path, "utf8")),
    ),
  );
}

/** The body of `requireLeaseRecovery` (from its declaration to the next top-level `}`). */
function helperBody(): { start: number; end: number; text: string } {
  const lines = readFileSync(join(ROOT, HELPER_FILE), "utf8").split("\n");
  const start = lines.findIndex((l) => l.startsWith(`export async function ${HELPER}(`));
  const end = lines.findIndex((l, i) => i > start && l === "}");
  return { start: start + 1, end: end + 1, text: lines.slice(start, end + 1).join("\n") };
}

describe("RECOVERY_REQUIRED writer enumeration (§7.1, §12)", () => {
  it("has exactly one writer, requireLeaseRecovery, and it writes the recovery_required event", () => {
    const body = helperBody();
    expect(body.start).toBeGreaterThan(0);
    expect(body.text).toContain('type: "recovery_required"');
    expect(body.text).toContain("tx.credentialEvent.create");

    const outside = scan().filter(
      (hit) => !(hit.file === HELPER_FILE && hit.line >= body.start && hit.line <= body.end),
    );
    expect(
      outside.map(
        (hit) =>
          `${hit.file}:${hit.line} writes RECOVERY_REQUIRED without ${HELPER} (its webhook event would be lost): ${hit.source}`,
      ),
    ).toEqual([]);
    const inside = scan().filter((hit) => hit.file === HELPER_FILE);
    expect(inside).toHaveLength(1);
  });

  it("recognizes a raw transition in SQL and Prisma form, and not a read (self-check)", () => {
    for (const source of [
      "UPDATE credential_lease SET state = 'RECOVERY_REQUIRED', \"endReason\" = 'x'",
      "SET state =\n  'RECOVERY_REQUIRED'",
      "SET state = CASE WHEN x THEN 'RECOVERY_REQUIRED' ELSE state END",
      "SET state = $1, x = 'RECOVERY_REQUIRED'::\"CredentialLeaseState\"",
      '  data: { state: "RECOVERY_REQUIRED" },',
      '  data: { state: { set: "RECOVERY_REQUIRED" } },',
      "  data: { state: CredentialLeaseState.RECOVERY_REQUIRED },",
    ])
      expect(hitsIn("x.ts", source)).not.toEqual([]);
    for (const source of [
      "WHERE state::text IN ('ACTIVE', 'RELEASING', 'RECOVERY_REQUIRED')",
      'where: { state: { in: ["ACTIVE", "RECOVERY_REQUIRED"] } },',
      'if (lease.state === "RECOVERY_REQUIRED") return;',
      "  // SET state = 'RECOVERY_REQUIRED' in a comment",
    ])
      expect(hitsIn("x.ts", source)).toEqual([]);
  });
});
