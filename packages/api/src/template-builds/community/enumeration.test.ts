/**
 * Enumeration tests (community-base §8.1, §8.6; guest-sudo-plan review4 U3). A new
 * revision loader, tag writer or COMMUNITY_PREP writer fails here until it is
 * reviewed: it either applies the launchable predicate or is listed with the
 * reason it may read an UPSTREAM pin or a pending revision.
 */
import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const ROOT = new URL("../../../../../", import.meta.url);
const TREES = ["packages/api/src/", "apps/server/src/", "apps/worker/src/"];

function sources(): { path: string; lines: string[] }[] {
  const out: { path: string; lines: string[] }[] = [];
  const walk = (dir: URL, rel: string) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (entry.name === "testing" || entry.name === "node_modules") continue;
        walk(new URL(`${entry.name}/`, dir), `${rel}${entry.name}/`);
      } else if (entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts"))
        out.push({
          path: `${rel}${entry.name}`,
          lines: readFileSync(new URL(entry.name, dir), "utf8").split("\n"),
        });
    }
  };
  for (const tree of TREES) walk(new URL(tree, ROOT), tree);
  return out;
}

const LOADER =
  /sandboxTemplateRevision\.(find\w*|update\w*|count)\(|FROM sandbox_template_revision/;
const GUARDED = /launchableRevisionWhere|resolvableRevisionWhere|pendingVerifyBuildId/;

/** Unguarded loaders per file, each reviewed. */
const REVIEWED_LOADERS: Record<string, { count: number; reason: string }> = {
  "packages/api/src/template-builds/rebuild.ts": {
    count: 2,
    reason: "rebuild source/base by stored id; community templates branch out before",
  },
  "packages/api/src/template-builds/exec-plan.ts": {
    count: 1,
    reason: "a stored build's base identity (by its own baseRevisionId)",
  },
  "packages/api/src/template-builds/community/service.ts": {
    count: 4,
    reason: "the dedicated UPSTREAM writer: revive/number its pins, read latest, supersede",
  },
  "packages/api/src/sandbox/pool-placement.ts": {
    count: 1,
    reason: "startup read of an already-resolved revision",
  },
  "packages/api/src/sandbox/capacity-queue.ts": {
    count: 3,
    reason: "the waiting head by its stored id (resolved at entry), rebuild follow, end code",
  },
  "packages/api/src/sandbox/placement-materialize.ts": {
    count: 1,
    reason: "root-taint facts of the resolved revision",
  },
  "packages/api/src/sandbox/disk-offload/restore-admit.ts": {
    count: 1,
    reason: "the restored sandbox's own revision, for pool ranking only (never a launch selection)",
  },
  "packages/api/src/sandbox/disk-offload/detach.ts": {
    count: 1,
    reason: "base fingerprint of a stale copy's own revision (identity, never a launch)",
  },
  "packages/api/src/sandbox/direct-placement.ts": {
    count: 1,
    reason: "FOR SHARE lock of the resolved revision",
  },
  "packages/api/src/sandbox/template-resolution.ts": {
    count: 2,
    reason: "the resolver itself (its predicate is `launchable`, computed above the query)",
  },
  "packages/api/src/sandbox/image-store/settings.ts": {
    count: 2,
    reason: "prune keep-window subquery (the outer row is guarded); image label read (slug)",
  },
  "packages/api/src/sandbox/services/operation-views.ts": {
    count: 1,
    reason: "display label of a capture's revision (slug, number)",
  },
  "packages/api/src/template-builds/views.ts": {
    count: 1,
    reason: "display label of a build's revisions (number)",
  },
  "packages/api/src/sandbox/image-store/jobs.ts": {
    count: 1,
    reason: "prune keep-window subquery (the outer row is guarded)",
  },
  "packages/api/src/sandbox/image-store/captures.ts": {
    count: 3,
    reason: "retention keep-window subquery; the finalizer's parent and revision number",
  },
  "packages/api/src/sandbox/image-store/references.ts": {
    count: 1,
    reason: "image reference census (metadata)",
  },
  "packages/api/src/sandbox/image-store/access.ts": {
    count: 1,
    reason: "foreign-copy access rule (metadata)",
  },
  "packages/api/src/sandbox/services/templates.ts": {
    count: 10,
    reason:
      "owner metadata views (DTO shows source and pendingVerify), registration numbering, associate in-tx re-read, retire (D-L)",
  },
  "packages/api/src/lib/sdk-key-access.ts": {
    count: 2,
    reason: "ownership checks of an already-resolved revision id",
  },
  "apps/server/src/sandbox-relay/outbox-processor.ts": {
    count: 1,
    reason: "I12 dispatch gate input (sourceKind)",
  },
  "apps/server/src/sandbox-relay/dispatch-gates.ts": {
    count: 1,
    reason: "dispatch read of an already-resolved revision",
  },
  "apps/server/src/sandbox-relay/image-handlers.ts": {
    count: 2,
    reason: "census evidence (marks UPSTREAM split) and upload architecture",
  },
};

describe("revision loaders (§8.1)", () => {
  it("every loader applies the launchable predicate or is reviewed", () => {
    const unguarded: Record<string, number> = {};
    for (const { path, lines } of sources())
      lines.forEach((line, i) => {
        if (!LOADER.test(line)) return;
        if (GUARDED.test(lines.slice(i, i + 14).join("\n"))) return;
        unguarded[path] = (unguarded[path] ?? 0) + 1;
      });
    expect(unguarded).toEqual(
      Object.fromEntries(Object.entries(REVIEWED_LOADERS).map(([path, v]) => [path, v.count])),
    );
  });
});

describe("tag writers (§8.6, I1t)", () => {
  it("only the reviewed writers move a tag, and none can target UPSTREAM or pending", () => {
    const writers: string[] = [];
    for (const { path, lines } of sources())
      lines.forEach((line) => {
        if (/sandboxTemplateTag\.upsert\(/.test(line)) writers.push(path);
      });
    expect(writers.sort()).toEqual(
      [
        // Registration: a MANUAL revision it just created (never used for UPSTREAM, M1).
        "packages/api/src/sandbox/services/templates.ts",
        // setTag: `launchableRevisionWhere` on the target revision.
        "packages/api/src/sandbox/services/templates.ts",
        // Cache hit: a SUCCEEDED build's revision (never pending).
        "packages/api/src/template-builds/service.ts",
        // Capture finalizer: skipped when the build is verifyRequired.
        "packages/api/src/sandbox/image-store/captures.ts",
        // Verify pass: clears pendingVerifyBuildId first, in the same transaction.
        "packages/api/src/template-builds/orchestrator.ts",
      ].sort(),
    );
    const read = (path: string) => readFileSync(new URL(path, ROOT), "utf8");
    const captures = read("packages/api/src/sandbox/image-store/captures.ts");
    expect(captures).toMatch(/if \(!pendingVerify\) \{\s+await tx\.sandboxTemplateTag\.upsert/);
    const templates = read("packages/api/src/sandbox/services/templates.ts");
    expect(templates).toMatch(
      /launchableRevisionWhere\(\),\s+\},\s+select: \{ id: true \},\s+\}\);\s+if \(!revision\) throw templateNotFound\(\);\s+await tx\.sandboxTemplateTag\.upsert/,
    );
    const orchestrator = read("packages/api/src/template-builds/orchestrator.ts");
    expect(orchestrator).toMatch(
      /data: \{ pendingVerifyBuildId: null \},[\s\S]{0,400}sandboxTemplateTag\.upsert/,
    );
    const service = read("packages/api/src/template-builds/community/service.ts");
    expect(service).not.toMatch(/sandboxTemplateTag\.(upsert|create)/);
  });
});

describe("COMMUNITY_PREP writers (guest-sudo-plan review4 U3)", () => {
  it("only the community service writes the origin; the public input has none", () => {
    const writes: string[] = [];
    for (const { path, lines } of sources())
      lines.forEach((line) => {
        if (/origin:\s*"COMMUNITY_PREP"/.test(line)) writes.push(path);
      });
    expect([...new Set(writes)]).toEqual(["packages/api/src/template-builds/community/service.ts"]);
    const service = readFileSync(
      new URL("packages/api/src/template-builds/community/service.ts", ROOT),
      "utf8",
    );
    // The one write is the community build insert; every other mention is a
    // read filter (`where`).
    const insert = service.slice(
      service.indexOf("async function insertCommunityBuild("),
      service.indexOf("export type CommunityTemplateResult"),
    );
    expect(insert.match(/origin: "COMMUNITY_PREP"/g)).toHaveLength(1);
    const outside = service.replace(insert, "");
    for (const match of outside.matchAll(/origin: "COMMUNITY_PREP"/g))
      expect(outside.slice(Math.max(0, (match.index ?? 0) - 200), match.index)).toMatch(/where:/);
    const contracts = readFileSync(
      new URL("packages/sandbox-contracts/src/template-builds.ts", ROOT),
      "utf8",
    );
    expect(contracts).not.toMatch(/COMMUNITY_PREP|origin/);
  });
});

/** §8.2: every build-identity site, each with its role note (§10.1). */
const BUILD_ID_SITES: Record<string, { count: number; note: string }> = {
  "packages/api/src/sandbox/capacity-queue.ts": {
    count: 1,
    note: "the waiting insert: role build only, verify refused (T4)",
  },
  "packages/api/src/sandbox/image-store/captures.ts": {
    count: 1,
    note: "capture: not in the verify table",
  },
  "packages/api/src/sandbox/managed-sandbox.ts": {
    count: 2,
    note: "TEMPLATE_BUILD keyed on buildId, TEMPLATE_VERIFY on verifyBuildId",
  },
  "packages/api/src/sandbox/placement-materialize.ts": {
    count: 5,
    note: "role-keyed fields, queued guard, build binding on the build VM only",
  },
  "packages/api/src/sandbox/services/sandboxes.ts": {
    count: 3,
    note: "create role assert, L3 build command fields, reserved key namespace",
  },
  "packages/api/src/sandbox/template-resolution.ts": {
    count: 1,
    note: "the resolver's own-build exemptions (I1, I12)",
  },
  "packages/api/src/template-builds/community/service.ts": {
    count: 1,
    note: "a build principal never accepts a community build",
  },
  "packages/api/src/template-builds/rebuild.ts": { count: 2, note: "unchanged" },
  "packages/api/src/template-builds/service.ts": { count: 1, note: "unchanged" },
  "packages/api/src/template-builds/visibility.ts": { count: 1, note: "unchanged" },
};

describe("build identity sites (§8.2)", () => {
  it("every buildIdOf / buildSandboxFields call site is reviewed", () => {
    const sites: Record<string, number> = {};
    for (const { path, lines } of sources())
      for (const line of lines)
        if (/buildIdOf\(|buildSandboxFields\(/.test(line) && !/export function/.test(line))
          sites[path] = (sites[path] ?? 0) + 1;
    expect(sites).toEqual(
      Object.fromEntries(Object.entries(BUILD_ID_SITES).map(([path, v]) => [path, v.count])),
    );
  });
});
