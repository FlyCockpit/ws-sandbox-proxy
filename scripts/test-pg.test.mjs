/**
 * `scripts/test-pg.mjs` skip policy: WSSP_SKIP_PG=1 is an explicit,
 * loud local skip, and is refused under CI so no workflow, repository variable
 * or inline env can turn the real-PostgreSQL layer green without running it.
 */
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  pgTestFiles,
  pgWiringViolations,
  prepareTemplateSchema,
  unavailableOutcome,
} from "./test-pg.mjs";

const script = resolve(fileURLToPath(new URL(".", import.meta.url)), "test-pg.mjs");
const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));

test("WSSP_SKIP_PG is refused under CI, honoured loudly outside CI, and never implied", () => {
  for (const CI of ["true", "1", "TRUE", "yes"])
    assert.equal(unavailableOutcome("no daemon", { CI, WSSP_SKIP_PG: "1" }).code, 1, `CI=${CI}`);
  const refused = unavailableOutcome("no daemon", { CI: "true", WSSP_SKIP_PG: "1" });
  assert.match(refused.lines[0], /^FAILED: WSSP_SKIP_PG=1 is refused under CI/);
  for (const CI of [undefined, "", "0", "false"]) {
    const skipped = unavailableOutcome("no daemon", { CI, WSSP_SKIP_PG: "1" });
    assert.equal(skipped.code, 0, `CI=${CI}`);
    assert.match(skipped.lines[0], /^SKIPPED: pnpm test:pg did NOT run/);
  }
  for (const WSSP_SKIP_PG of [undefined, "", "true", "yes", "0"])
    assert.equal(unavailableOutcome("no daemon", { WSSP_SKIP_PG }).code, 1, `skip=${WSSP_SKIP_PG}`);
});

test("the real entry exits 1 under CI with WSSP_SKIP_PG=1, before touching Docker", () => {
  const run = spawnSync(process.execPath, [script], {
    // PATH without docker: the refusal must come first, whatever Docker's state.
    env: { PATH: "/nonexistent", CI: "true", WSSP_SKIP_PG: "1" },
    encoding: "utf8",
    timeout: 30_000,
  });
  assert.equal(run.status, 1, run.stderr);
  assert.match(run.stderr, /FAILED: WSSP_SKIP_PG=1 is refused under CI/);
  assert.doesNotMatch(run.stderr, /SKIPPED/);
});

test("every *.pg.test.ts in the repository is wired into turbo run test:pg", () => {
  // Guard against a silently empty scan: known real-DB files are found.
  const found = pgTestFiles(repoRoot).map((file) => file.slice(repoRoot.length + 1));
  assert.ok(found.includes("packages/db/src/account-deletion.pg.test.ts"), found.join("\n"));
  assert.ok(found.includes("apps/server/src/sandbox-relay/host-tombstone.pg.test.ts"));
  assert.deepEqual(pgWiringViolations(repoRoot), []);
});

test("an unwired *.pg.test.ts fails the wiring check, naming the file", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "pg-wiring-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const put = (path, text) => {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), text);
  };
  put("vitest.pg.config.ts", 'export default { test: { include: ["src/**/*.pg.test.ts"] } };\n');
  put("turbo.json", '{ "tasks": { "test:pg": { "cache": false } } }\n');
  const wired = { scripts: { "test:pg": "vitest run --config ../../vitest.pg.config.ts" } };
  put("packages/good/package.json", JSON.stringify(wired));
  put("packages/good/src/a.pg.test.ts", "");
  put("packages/unwired/package.json", JSON.stringify({ scripts: { test: "vitest run" } }));
  put("packages/unwired/src/b.pg.test.ts", "");
  put("packages/good/test/c.pg.test.ts", "");
  put("scripts/d.pg.test.ts", "");
  put("packages/good/node_modules/x/e.pg.test.ts", "");
  assert.deepEqual(pgWiringViolations(dir), [
    'packages/good/test/c.pg.test.ts: outside packages/good/src, so "src/**/*.pg.test.ts" never collects it',
    "packages/unwired/src/b.pg.test.ts: packages/unwired/package.json has no test:pg script running vitest.pg.config.ts",
    "scripts/d.pg.test.ts: not inside a workspace package (apps/* or packages/*), so no test:pg task runs it",
  ]);
  put("turbo.json", '{ "tasks": { "test": {} } }\n');
  put("vitest.pg.config.ts", 'export default { test: { include: ["test/**/*.pg.test.ts"] } };\n');
  const broken = pgWiringViolations(dir);
  assert.ok(
    broken.includes('vitest.pg.config.ts: must include "src/**/*.pg.test.ts"'),
    broken.join("\n"),
  );
  assert.ok(
    broken.includes('turbo.json: no "test:pg" task, so turbo run test:pg runs nothing'),
    broken.join("\n"),
  );
});

// A real failing child proves runner diagnostics survive without an outer retry.
function fakeRunner(t, stderr) {
  const dir = mkdtempSync(join(tmpdir(), "wssp-fake-runner-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const counter = join(dir, "attempts");
  writeFileSync(counter, "0");
  const file = join(dir, "runner.mjs");
  writeFileSync(
    file,
    [
      'import { readFileSync, writeFileSync } from "node:fs";',
      `const counter = ${JSON.stringify(counter)};`,
      'writeFileSync(counter, String(Number(readFileSync(counter, "utf8")) + 1));',
      `process.stderr.write(${JSON.stringify(stderr)}); process.exit(1);`,
    ].join("\n"),
  );
  return {
    apply: () => execFileSync(process.execPath, [file], { stdio: "pipe", timeout: 30_000 }),
    attempts: () => Number(readFileSync(counter, "utf8")),
  };
}

test("template preparation invokes the runner exactly once on success", () => {
  let attempts = 0;
  assert.equal(
    prepareTemplateSchema(() => {
      attempts++;
      return "applied";
    }),
    "applied",
  );
  assert.equal(attempts, 1);
});

test("template preparation preserves refusal and engine diagnostics without replaying a migration", (t) => {
  for (const diagnostic of [
    "Refusing edited migration checksum.",
    "owned engine #0 did not drain cleanly; exit=101; task was cancelled",
  ]) {
    const runner = fakeRunner(t, diagnostic);
    assert.throws(
      () => prepareTemplateSchema(runner.apply),
      (error) => {
        assert.match(
          error.message,
          /committed migration preparation failed \(exit 1\); no harness retry/,
        );
        assert.ok(error.message.includes(diagnostic));
        assert.ok(error.cause instanceof Error);
        return true;
      },
    );
    assert.equal(runner.attempts(), 1);
  }
});
