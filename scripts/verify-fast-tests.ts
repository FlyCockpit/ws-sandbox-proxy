/**
 * The test step of `pnpm verify:fast`:
 *
 *   node scripts/verify-fast-tests.ts [extra turbo args, e.g. --dry=json]
 *
 * 1. `turbo run test --affected`, unchanged.
 * 2. When the same diff touches files outside every workspace package that
 *    drift tests read (crates/, apps/cli/, docs/, scripts/, .github/), a second
 *    `turbo run test --filter=<pkg>...` for those packages. Turbo maps such a
 *    file to the root package only, so step 1 never selects them. Tasks step 1
 *    already ran are cache hits here.
 *
 * The diff mirrors Turbo's `--affected`: `TURBO_SCM_BASE` (default `main`) to `TURBO_SCM_HEAD` (default `HEAD`), plus uncommitted and
 * untracked files, which Turbo also counts.
 */
import { spawnSync } from "node:child_process";
import process from "node:process";
import { driftTestPackages } from "./lib/drift-test-packages.ts";

function git(args: string[]): string | null {
  const result = spawnSync("git", args, { encoding: "utf8" });
  return result.status === 0 ? result.stdout : null;
}

function lines(text: string): string[] {
  return text.split("\n").filter((line) => line.length > 0);
}

function changedPaths(): string[] | null {
  const base =
    process.env.TURBO_SCM_BASE ||
    ["main"].find((ref) => git(["rev-parse", "--verify", "-q", `${ref}^{commit}`]));
  if (!base) return null;
  const head = process.env.TURBO_SCM_HEAD || "HEAD";
  const committed = git(["diff", "--name-only", "--no-renames", `${base}...${head}`]);
  const uncommitted = git(["diff", "--name-only", "--no-renames", "HEAD"]);
  const untracked = git(["ls-files", "--others", "--exclude-standard"]);
  if (committed === null || uncommitted === null || untracked === null) return null;
  return [...lines(committed), ...lines(uncommitted), ...lines(untracked)];
}

function turbo(args: string[]): void {
  const result = spawnSync("pnpm", ["turbo", "run", "test", "--output-logs=errors-only", ...args], {
    stdio: "inherit",
  });
  if (result.status !== 0) process.exit(result.status ?? 1);
}

const extra = process.argv.slice(2);
turbo(["--affected", ...extra]);

const paths = changedPaths();
const packages = driftTestPackages(paths);
// The env package exercises setup's pure port/URL configuration. Those imports
// live outside its workspace, so root-script edits must select that suite too.
if (paths === null || paths.some((path) => path.startsWith("scripts/"))) {
  packages.push("@wssp/env");
}
if (packages.length > 0) {
  console.error(
    `verify:fast: ${paths === null ? "diff unknown" : "out-of-package changes"}; drift tests in ${packages.join(", ")}`,
  );
  turbo([...packages.map((name) => `--filter=${name}`), ...extra]);
}
