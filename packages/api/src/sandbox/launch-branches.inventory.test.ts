import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";
import {
  LAUNCH_BRANCH_INVENTORY,
  LAUNCH_BRANCH_SWEEP,
  type LaunchBranchClass,
} from "./launch-branches.inventory";

const root = join(__dirname, "../../../..");

/** The S16 sweep's file set: production TypeScript only. */
function inSweep(path: string): boolean {
  return (
    /\.(ts|tsx|mts|cts)$/.test(path) &&
    !/\.d\.ts$/.test(path) &&
    !/\.test\.tsx?$/.test(path) &&
    !/-harness\.ts$/.test(path) &&
    !/-fixtures\.ts$/.test(path) &&
    !/\.inventory\.ts$/.test(path) &&
    !path.split("/").includes("testing")
  );
}

function sources(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (name === "node_modules" || name === "dist") continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) sources(path, out);
    else out.push(path);
  }
  return out;
}

type Hits = Map<string, Set<string>>;

/** Every sweep hit, keyed by repo-relative file and trimmed line text. */
function scanLaunchBranches(files: Iterable<[path: string, text: string]>): Hits {
  const hits: Hits = new Map();
  for (const [path, text] of files) {
    if (!inSweep(path)) continue;
    for (const line of text.split("\n")) {
      if (!LAUNCH_BRANCH_SWEEP.patterns.some((pattern) => line.includes(pattern))) continue;
      const entries = hits.get(path) ?? new Set<string>();
      entries.add(line.trim());
      hits.set(path, entries);
    }
  }
  return hits;
}

function inventoryDrift(
  hits: Hits,
  inventory: Readonly<Record<string, Readonly<Record<string, LaunchBranchClass>>>>,
) {
  const unlisted: string[] = [];
  const stale: string[] = [];
  for (const [file, lines] of hits)
    for (const line of lines)
      if (inventory[file]?.[line] === undefined) unlisted.push(`${file} | ${line}`);
  for (const [file, lines] of Object.entries(inventory))
    for (const line of Object.keys(lines))
      if (!hits.get(file)?.has(line)) stale.push(`${file} | ${line}`);
  return { unlisted, stale };
}

function repoFiles(): [string, string][] {
  return LAUNCH_BRANCH_SWEEP.roots.flatMap((dir) =>
    sources(join(root, dir)).map((path): [string, string] => [
      relative(root, path),
      readFileSync(path, "utf8"),
    ]),
  );
}

describe("S16 launch-branch inventory (offload §12, U4/V4)", () => {
  it("lists every launch-branch hit and no stale entry", () => {
    expect(inventoryDrift(scanLaunchBranches(repoFiles()), LAUNCH_BRANCH_INVENTORY)).toEqual({
      unlisted: [],
      stale: [],
    });
  });

  it("canary: an unrouted CREATE_SANDBOX branch fails the inventory", () => {
    const files = repoFiles();
    files.push([
      "packages/api/src/sandbox/canary-unrouted.ts",
      'export const newRoot = (op: { kind: string }) => op.kind === "CREATE_SANDBOX";\n',
    ]);
    expect(inventoryDrift(scanLaunchBranches(files), LAUNCH_BRANCH_INVENTORY).unlisted).toEqual([
      'packages/api/src/sandbox/canary-unrouted.ts | export const newRoot = (op: { kind: string }) => op.kind === "CREATE_SANDBOX";',
    ]);
  });

  it("canary: an entry whose line is gone is stale; test support is outside the sweep", () => {
    const drift = inventoryDrift(
      scanLaunchBranches([
        ["packages/api/src/sandbox/x.test.ts", 'if (op.kind === "CREATE_SANDBOX") {}'],
        ["packages/api/src/sandbox/testing/x.ts", 'if (op.kind === "CREATE_SANDBOX") {}'],
      ]),
      { "packages/api/src/sandbox/gone.ts": { 'if (kind === "CREATE_SANDBOX")': "create-only" } },
    );
    expect(drift).toEqual({
      unlisted: [],
      stale: ['packages/api/src/sandbox/gone.ts | if (kind === "CREATE_SANDBOX")'],
    });
  });

  it("C6c leftovers stay explicit: route-pending entries are counted", () => {
    const pending = Object.values(LAUNCH_BRANCH_INVENTORY).flatMap((lines) =>
      Object.values(lines).filter((value) => value === "route-pending"),
    );
    // C6c flips each to launch-mode-routed; lower this count as it does.
    expect(pending.length).toBe(LAUNCH_BRANCH_ROUTE_PENDING);
  });
});

// C6c routed the relay fence (U9), the dispatch gates (U9.1), the outbox
// egress/allocation branches and the attestation root release; C6d routed
// the §8.7 exit and result-mapping sites. None is left.
const LAUNCH_BRANCH_ROUTE_PENDING = 0;
