/**
 * `pnpm test:pg`: the real-PostgreSQL test layer (`*.pg.test.ts`).
 *
 * Owns exactly one disposable PostgreSQL container for the whole run, applies
 * committed migrations through the production runner,
 * freezes that database as the template every test file clones, then runs the
 * per-package `test:pg` Turbo task serially (each Vitest capped at 2 workers).
 * The container is removed on success, failure, SIGINT, SIGTERM and SIGHUP,
 * and only after the whole Turbo → pnpm → Vitest process tree is gone (it runs
 * as an owned process group; a signal is forwarded to it first).
 *
 * No silent skip: without Docker this FAILS unless WSSP_SKIP_PG=1 is set
 * explicitly, which prints a loud SKIPPED banner and exits 0. Under CI (any
 * `CI` value other than empty, "0" or "false"; GitHub Actions sets CI=true)
 * WSSP_SKIP_PG is refused and the run fails, so no workflow, repository
 * variable or inline env can turn the real-DB layer green without running it.
 *
 * No unwired file either: `pgWiringViolations` refuses a
 * `*.pg.test.ts` that `turbo run test:pg` would never collect. It runs before
 * Docker is touched here, and as a policy test in `pnpm policy:pg-image-ci`
 * (scripts/test-pg.test.mjs, part of `pnpm verify:fast` and `pnpm verify`).
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import {
  canonicalApplyFixture,
  disposableDirectory,
  dockerAvailability,
  spawnOwnedProcessGroup,
  startDisposablePostgres,
} from "./lib/disposable-postgres.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
const TEMPLATE_DATABASE = "wssp_pg_template";

function banner(lines) {
  const bar = "=".repeat(72);
  console.error(`\n${bar}\n${lines.map((line) => ` ${line}`).join("\n")}\n${bar}\n`);
}

/** The one include every package's `test:pg` runs (vitest.pg.config.ts). */
const PG_TEST_INCLUDE = "src/**/*.pg.test.ts";
const PG_TEST_SUFFIX = ".pg.test.ts";
const SKIPPED_DIRECTORIES = new Set([
  ".git",
  "node_modules",
  "target",
  "dist",
  ".turbo",
  "coverage",
]);

export function pgTestFiles(dir, found = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIPPED_DIRECTORIES.has(entry.name)) pgTestFiles(join(dir, entry.name), found);
    } else if (entry.isFile() && entry.name.endsWith(PG_TEST_SUFFIX))
      found.push(join(dir, entry.name));
  }
  return found;
}

/**
 * Every way a `*.pg.test.ts` could silently never run, as messages naming the
 * file. A file is wired only when it lives under `src/` of a workspace package
 * (apps/* or packages/*) whose `test:pg` script runs the shared
 * vitest.pg.config.ts, that config still includes PG_TEST_INCLUDE, and
 * turbo.json declares the `test:pg` task the harness runs.
 */
export function pgWiringViolations(repoRoot) {
  const violations = [];
  const config = join(repoRoot, "vitest.pg.config.ts");
  if (!existsSync(config) || !readFileSync(config, "utf8").includes(`"${PG_TEST_INCLUDE}"`))
    violations.push(`vitest.pg.config.ts: must include "${PG_TEST_INCLUDE}"`);
  const turbo = join(repoRoot, "turbo.json");
  if (!existsSync(turbo) || !/"test:pg"\s*:\s*\{/.test(readFileSync(turbo, "utf8")))
    violations.push('turbo.json: no "test:pg" task, so turbo run test:pg runs nothing');
  for (const file of pgTestFiles(repoRoot).sort()) {
    const shown = relative(repoRoot, file).split(sep).join("/");
    let packageDir = dirname(file);
    while (
      packageDir.startsWith(repoRoot) &&
      packageDir !== repoRoot &&
      !existsSync(join(packageDir, "package.json"))
    )
      packageDir = dirname(packageDir);
    const packagePath = relative(repoRoot, packageDir).split(sep).join("/");
    if (!/^(?:apps|packages)\/[^/]+$/.test(packagePath)) {
      violations.push(
        `${shown}: not inside a workspace package (apps/* or packages/*), so no test:pg task runs it`,
      );
      continue;
    }
    const script = JSON.parse(readFileSync(join(packageDir, "package.json"), "utf8")).scripts?.[
      "test:pg"
    ];
    if (typeof script !== "string" || !script.includes("vitest.pg.config.ts"))
      violations.push(
        `${shown}: ${packagePath}/package.json has no test:pg script running vitest.pg.config.ts`,
      );
    if (!relative(packageDir, file).split(sep).join("/").startsWith("src/"))
      violations.push(
        `${shown}: outside ${packagePath}/src, so "${PG_TEST_INCLUDE}" never collects it`,
      );
  }
  return violations;
}

/** Prepare once: transactional recovery and native-child drain belong to the runner. */
export function prepareTemplateSchema(apply) {
  try {
    return apply();
  } catch (error) {
    const stderr = error?.stderr;
    const tail = (typeof stderr === "string" ? stderr : Buffer.from(stderr ?? "").toString("utf8"))
      .trim()
      .split("\n")
      .slice(-8)
      .join("\n");
    const status = error?.signal ? `signal ${error.signal}` : `exit ${error?.status ?? "unknown"}`;
    throw new Error(
      `test:pg: committed migration preparation failed (${status}); no harness retry.${tail ? `\n${tail}` : ""}`,
      { cause: error },
    );
  }
}

const isCi = (env) => Boolean(env.CI) && !["0", "false"].includes(env.CI.toLowerCase());

/**
 * What an unavailable Docker means: `{ code, lines }` for the banner. The
 * explicit skip is honoured only outside CI.
 */
export function unavailableOutcome(reason, env) {
  if (env.WSSP_SKIP_PG === "1" && isCi(env))
    return {
      code: 1,
      lines: [
        "FAILED: WSSP_SKIP_PG=1 is refused under CI; the real-PostgreSQL layer must run.",
        `Docker is unavailable: ${reason}`,
        "Run `pnpm test:pg:pull-image` in this job and make Docker available.",
      ],
    };
  if (env.WSSP_SKIP_PG === "1")
    return {
      code: 0,
      lines: [
        "SKIPPED: pnpm test:pg did NOT run any real-PostgreSQL test.",
        `Docker is unavailable: ${reason}`,
        "WSSP_SKIP_PG=1 was set explicitly. DB race and lock claims are UNVERIFIED.",
      ],
    };
  return {
    code: 1,
    lines: [
      "FAILED: pnpm test:pg needs Docker for its disposable PostgreSQL.",
      `Docker is unavailable: ${reason}`,
      "Start Docker, or set WSSP_SKIP_PG=1 to skip explicitly (refused under CI).",
    ],
  };
}

async function main() {
  const unwired = pgWiringViolations(root.replace(/[\\/]$/, ""));
  if (unwired.length > 0) {
    banner(["FAILED: real-PostgreSQL tests that pnpm test:pg would never run:", ...unwired]);
    return 1;
  }
  // Refuse a CI skip even when Docker is up: the setting itself is the defect.
  if (process.env.WSSP_SKIP_PG === "1" && isCi(process.env)) {
    const outcome = unavailableOutcome("not checked", process.env);
    banner(outcome.lines);
    return outcome.code;
  }
  const availability = dockerAvailability();
  if (!availability.ok) {
    const outcome = unavailableOutcome(availability.reason, process.env);
    banner(outcome.lines);
    return outcome.code;
  }

  // Owned by the shared lifecycle: removed by `finally` and by the signal path.
  const fixture = disposableDirectory("wssp-test-pg-");
  const temporary = fixture.path;
  const postgres = await startDisposablePostgres({
    owner: "test-pg",
    // Each test file drops its clone (and its `<clone>_<suffix>` upgrade
    // targets) when it finishes (packages/db/src/testing/pg.ts), so the
    // data directory holds the template plus at most two running files'
    // databases (two Vitest workers) and the WAL, not one clone per file.
    // Measured on the full run (116 files): tmpfs peak 118 MiB
    // and cgroup memory.peak 300 MiB, against about 1.7 GiB of tmpfs when
    // every clone was kept. 512m/1024m leaves 4x and 3x headroom; a new test
    // file adds nothing, only a bigger schema or a heavier single file does.
    // tmpfs pages count against the container's memory limit, so memory is
    // the tmpfs plus room for the server and its backends.
    memory: "1024m",
    tmpfsSize: "512m",
    durabilityOff: true,
  });
  try {
    const require = createRequire(new URL("../packages/db/package.json", import.meta.url));
    const { Client } = require("pg");
    const admin = new Client({ connectionString: postgres.url(), connectionTimeoutMillis: 5_000 });
    await admin.connect();
    try {
      await admin.query(`CREATE DATABASE ${TEMPLATE_DATABASE}`);
    } finally {
      await admin.end();
    }
    const migration = canonicalApplyFixture(root, temporary, postgres.url(TEMPLATE_DATABASE));
    const preparationStarted = performance.now();
    prepareTemplateSchema(() => migration.apply());
    const preparationMs = Math.round(performance.now() - preparationStarted);
    // The runner has exited, so nothing is connected. Freeze the template:
    // clones are byte copies, and no test can open (and thereby block) it.
    const freeze = new Client({ connectionString: postgres.url(), connectionTimeoutMillis: 5_000 });
    await freeze.connect();
    try {
      await freeze.query(
        `ALTER DATABASE ${TEMPLATE_DATABASE} WITH IS_TEMPLATE true ALLOW_CONNECTIONS false`,
      );
    } finally {
      await freeze.end();
    }
    console.log(
      `test:pg: committed migrations applied via migrate-runtime into template ${TEMPLATE_DATABASE} (${preparationMs}ms).`,
    );

    const turbo = resolve(root, "node_modules/.bin/turbo");
    // An owned process group: `exited` resolves only once every process in
    // the tree is gone, and a signal to this process is forwarded to the group
    // and waited for BEFORE the container is removed. `--ui=stream`: the group
    // is detached from the terminal, so Turbo's TUI has no terminal to drive.
    const { exited } = spawnOwnedProcessGroup(
      turbo,
      [
        "run",
        "test:pg",
        "--concurrency=1",
        "--output-logs=full",
        "--ui=stream",
        ...process.argv.slice(2),
      ],
      {
        cwd: root,
        stdio: "inherit",
        env: {
          ...process.env,
          WSSP_PG_ADMIN_URL: postgres.url(),
          WSSP_PG_TEMPLATE_DB: TEMPLATE_DATABASE,
          // `<name>:<port>`: the only server a test file may drop its clone on.
          WSSP_PG_CONTAINER: `${postgres.name}:${postgres.port}`,
        },
      },
    );
    return await exited;
  } finally {
    postgres.stop();
    fixture.remove();
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    process.exitCode = await main();
  } catch (error) {
    console.error(error instanceof Error ? (error.stack ?? error.message) : error);
    process.exitCode = 1;
  }
}
