import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { localDatabaseNames } from "./lib/local-db-name.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

test("--adopt refuses EXPECTED_DB before it connects: it marks only what db:reset:local resets", () => {
  const other = `${localDatabaseNames({ cwd: ROOT, env: {} }).main}_other`;
  const result = spawnSync(
    process.execPath,
    [path.join(ROOT, "scripts/db/worktree.mjs"), "--adopt"],
    {
      cwd: ROOT,
      // No DATABASE_URL and no terminal: even a regression could not mark anything
      // (adopt itself needs an interactive TTY and the typed name).
      env: { PATH: process.env.PATH, EXPECTED_DB: other },
      encoding: "utf8",
      timeout: 20_000,
      killSignal: "SIGKILL",
    },
  );
  assert.equal(result.status, 1, `${result.stdout}${result.stderr}`);
  assert.match(result.stderr, /--adopt refuses EXPECTED_DB/);
  assert.doesNotMatch(`${result.stdout}${result.stderr}`, /marked|Type .* to confirm/);
});
