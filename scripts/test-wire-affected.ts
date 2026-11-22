/**
 * `pnpm test:wire:affected`, in `pnpm verify:fast`: runs `test:cancel-wire`
 * and `test:relay-chaos` when this branch or the work tree changed something
 * they read (scripts/lib/wire-affected.ts; it fails open). `pnpm verify` and
 * CI always run both.
 */
import { spawnSync } from "node:child_process";
import process from "node:process";
import { parseArgs } from "node:util";
import {
  buildSelector,
  changedFiles,
  type Git,
  ROOT,
  SUITE_SCRIPTS,
  SUITES,
  selectSuites,
} from "./lib/wire-affected.ts";

const git: Git = (args) => {
  const result = spawnSync("git", args, { cwd: ROOT, encoding: "utf8" });
  return result.status === 0 ? result.stdout : undefined;
};

try {
  parseArgs({ args: process.argv.slice(2), strict: true, options: {} });
} catch (error) {
  process.stderr.write(
    `test-wire-affected: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exit(1);
}
const selected = selectSuites(buildSelector(), changedFiles(git));
for (const suite of SUITES) {
  const script = SUITE_SCRIPTS[suite];
  const reason = selected.get(suite);
  if (reason === undefined) {
    process.stdout.write(
      `${script} skipped: nothing it reads changed (\`pnpm verify\` and CI run it).\n`,
    );
    continue;
  }
  process.stdout.write(`${script} runs: ${reason}.\n`);
  const result = spawnSync("pnpm", ["run", script], { cwd: ROOT, stdio: "inherit" });
  if (result.status !== 0) process.exit(result.status ?? 1);
}
