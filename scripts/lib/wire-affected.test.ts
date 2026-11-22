import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import process from "node:process";
import { describe, test } from "node:test";
import {
  buildSelector,
  changedFiles,
  closureOf,
  GENERATED_DIRS,
  packageOf,
  ROOT,
  ROOT_SKIP_PATHS,
  reachedPackages,
  readWorkspace,
  reasonFor,
  SUITE_SCRIPTS,
  SUITES,
  selectSuites,
  suiteEntries,
} from "./wire-affected.ts";

const { scripts } = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as {
  scripts: Record<string, string>;
};
const selector = buildSelector();
const selected = (changed: readonly string[] | undefined) =>
  [...selectSuites(selector, changed).keys()].sort();
const BOTH = [...SUITES].sort();

function repoFiles(): string[] {
  // Untracked (non-ignored) files too: a new file is checked before its commit.
  const result = spawnSync(
    "git",
    ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
    { cwd: ROOT, encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.split("\0").filter(Boolean);
}

describe("the tier", () => {
  test("verify:fast selects the wire suites; verify and CI run both", () => {
    assert.equal(scripts["test:wire:affected"], "node scripts/test-wire-affected.ts");
    assert.match(scripts["verify:fast"] ?? "", / && pnpm test:wire:affected && /);
    for (const suite of SUITES) {
      const step = `pnpm ${SUITE_SCRIPTS[suite]}`;
      assert.ok(!(scripts["verify:fast"] ?? "").includes(`${step} `), `verify:fast runs ${step}`);
      assert.ok((scripts.verify ?? "").includes(`&& ${step} &&`), `verify must run ${step}`);
    }
    const ci = readFileSync(join(ROOT, ".github/workflows/pr-checks.yml"), "utf8");
    for (const suite of SUITES) assert.ok(ci.includes(`pnpm ${SUITE_SCRIPTS[suite]}`), suite);
    assert.match(scripts["test:setup"] ?? "", / scripts\/lib\/wire-affected\.test\.ts( |$)/);
  });
});

describe("the closure", () => {
  test("resolves completely and contains every test file its config includes", () => {
    for (const suite of SUITES) {
      const closure = selector.closures[suite];
      assert.deepEqual(closure.unresolved, [], `${suite}: unresolved imports`);
      // A computed import makes its whole directory an input; none exists
      // today. If one is added, check that the directory rule is wanted.
      assert.deepEqual([...closure.computedDirs], [], `${suite}: computed imports`);
      const { entries, failOpen } = suiteEntries(suite);
      assert.equal(failOpen, undefined, `${suite}: test files not listed exactly`);
      const [config, ...tests] = entries;
      assert.ok(tests.length > 0, `${suite}: no test files found in ${config}`);
      for (const file of [config!, ...tests]) {
        assert.ok(existsSync(join(ROOT, file)), `${suite}: ${file} is missing`);
        assert.ok(closure.files.has(file), `${suite}: ${file}`);
      }
    }
  });

  test("every file a suite imports or names selects it", () => {
    for (const suite of SUITES)
      for (const file of selector.closures[suite].files)
        assert.notEqual(reasonFor(selector, suite, file), undefined, `${file} → ${suite}`);
  });

  test("every file Cargo can build the daemon from selects both suites", (t) => {
    const manifest = readFileSync(join(ROOT, "Cargo.toml"), "utf8");
    const members = [
      ...(manifest.match(/members\s*=\s*\[([^\]]*)\]/)?.[1] ?? "").matchAll(/"([^"]+)"/g),
    ].map((match) => `${match[1]}/`);
    assert.ok(members.includes("apps/cli/"), "apps/cli is a workspace member");
    const paths = [...manifest.matchAll(/path\s*=\s*"([^"]+)"/g)].map((match) => `${match[1]}/`);
    const files = repoFiles();
    for (const dir of [...members, ...paths]) {
      const inside = files.filter((file) => file.startsWith(dir));
      assert.ok(inside.length > 0, `${dir} holds no files`);
      for (const file of inside) assert.deepEqual(selected([file]), BOTH, file);
    }
    // Cargo's own record of what it compiled into the daemon, when a build
    // left one (pnpm verify builds it before this test runs).
    const targetDir = resolve(ROOT, process.env.CARGO_TARGET_DIR ?? "target");
    const depInfo = join(targetDir, "debug", "wssp.d");
    if (existsSync(depInfo)) {
      const listed = readFileSync(depInfo, "utf8")
        .split(/(?<!\\)\s+/)
        .map((entry) => entry.replaceAll("\\ ", " "))
        .filter((entry) => entry.startsWith(ROOT) && !entry.endsWith(":"))
        .map((entry) => relative(ROOT, entry))
        .filter((entry) => !entry.startsWith("..") && !entry.startsWith("target/"));
      if (listed.length === 0) t.diagnostic(`${depInfo} names no file of this checkout`);
      else {
        assert.ok(
          listed.some((entry) => entry.startsWith("apps/cli/")),
          "dep-info names apps/cli",
        );
        for (const entry of listed) assert.deepEqual(selected([entry]), BOTH, entry);
      }
    } else t.diagnostic(`no ${depInfo}: build the daemon to check Cargo's own input list`);
  });

  test("no closure file names a package it does not reach or a skipped root path", () => {
    const workspace = readWorkspace();
    for (const suite of SUITES) {
      const reached = reachedPackages(selector, suite);
      const unreached = [...workspace.packages.keys()]
        .filter((dir) => !reached.has(dir))
        .map((dir) => dir.slice(0, -1));
      assert.ok(unreached.includes("apps/web"), `${suite} reaches apps/web`);
      const offenders: string[] = [];
      for (const [file, strings] of selector.closures[suite].strings)
        for (const literal of strings) {
          for (const dir of unreached)
            if (literal.includes(dir)) offenders.push(`${file}: "${literal}" names ${dir}`);
          for (const rule of ROOT_SKIP_PATHS)
            if (rule.endsWith("/") ? literal.includes(rule) : literal.split("/").includes(rule))
              offenders.push(`${file}: "${literal}" names ${rule}`);
        }
      assert.deepEqual(offenders, [], `${suite}: classify these paths in wire-affected.ts`);
    }
  });

  test("the generated client is git-ignored, and its schema selects both suites", () => {
    for (const dir of GENERATED_DIRS) {
      const ignored = spawnSync("git", ["check-ignore", "-q", `${dir}x.ts`], { cwd: ROOT });
      assert.equal(ignored.status, 0, `${dir} must be git-ignored`);
    }
    const schema = repoFiles().filter((file) => file.startsWith("packages/db/prisma/schema/"));
    assert.ok(schema.length > 0);
    for (const file of schema) assert.deepEqual(selected([file]), BOTH, file);
  });

  test("every file in the repository is classified", () => {
    const unclassified = repoFiles().filter((path) =>
      SUITES.some((suite) => reasonFor(selector, suite, path)?.startsWith("no rule")),
    );
    assert.deepEqual(
      unclassified,
      [],
      "classify these in scripts/lib/wire-affected.ts (RUST_PATHS, SHARED_PATHS or ROOT_SKIP_PATHS)",
    );
  });
});

describe("selection", () => {
  test("fails open: Rust, shared and unclassified paths and an unknown base run both", () => {
    for (const path of [
      "Cargo.lock",
      "Cargo.toml",
      "crates/sandbox-runtime/src/lib.rs",
      "apps/cli/src/main.rs",
      "third_party/russh-0.65.2.patch",
      ".cargo/config.toml",
      "rust-toolchain.toml",
      "package.json",
      "pnpm-lock.yaml",
      "pnpm-workspace.yaml",
      ".nvmrc",
      "tsconfig.json",
      "scripts/lib/wire-affected.ts",
      "scripts/test-wire-affected.ts",
      "new-root-file.json",
    ]) {
      assert.deepEqual(selected(["apps/web/src/a.tsx", path]), BOTH, path);
    }
    assert.deepEqual(selected(undefined), BOTH);
    assert.match(
      selectSuites(selector, ["new-root-file.json"]).get("cancel-wire") ?? "",
      /no rule in scripts\/lib\/wire-affected\.ts classifies it/,
    );
  });

  test("the wire fixture, the relay server and their package data select the suites", () => {
    for (const [path, suites] of [
      ["apps/server/src/sandbox-relay/cancel-wire-fixtures.ts", BOTH],
      ["apps/server/src/sandbox-relay/session-manager.ts", BOTH],
      ["apps/server/src/sandbox-relay/cancel-wire.contract.test.ts", ["cancel-wire"]],
      // cancel-wire-fixtures.ts names the chaos suite, so cancel-wire runs too.
      ["apps/server/src/sandbox-relay/relay-chaos.contract.test.ts", BOTH],
      ["apps/server/src/sandbox-relay/relay-chaos-matrix.ts", ["relay-chaos"]],
      ["scripts/vitest-cancel-wire.config.ts", ["cancel-wire"]],
      ["scripts/test-io-guard-loopback.ts", ["relay-chaos"]],
      ["packages/api/src/sandbox/services/sandboxes.ts", BOTH],
      ["packages/sandbox-contracts/src/index.ts", BOTH],
      ["crates/sandbox-protocol/fixtures/lifecycle_fault_matrix.json", BOTH],
      ["packages/db/package.json", BOTH],
      ["apps/server/package.json", BOTH],
      ["packages/sdk/src/commands.ts", ["cancel-wire"]],
    ] as const) {
      assert.deepEqual(selected([path]), [...suites].sort(), path);
    }
  });

  test("the web app, docs, CI and unread modules skip both", () => {
    // A module of a reached package that nothing in the closure imports or names.
    const unread = repoFiles().find(
      (file) =>
        file.startsWith("packages/api/src/routers/") &&
        file.endsWith(".ts") &&
        SUITES.every((suite) => reasonFor(selector, suite, file) === undefined),
    );
    assert.ok(unread, "some packages/api router is outside both closures");
    for (const path of [
      unread,
      "apps/web/src/routes/__root.tsx",
      "apps/web/package.json",
      "packages/ui/src/globals.css",
      "packages/locales/src/en-US/common.json",
      "docs/testing.md",
      ".github/workflows/pr-checks.yml",
      "AGENTS.md",
      "Dockerfile",
      "scripts/check-doc-citations.ts",
      "scripts/backup/host.sh",
    ]) {
      assert.deepEqual(selected([path]), [], path);
    }
    assert.deepEqual(selected([]), []);
  });

  test("a module of a reached package that a closure file names by its stem runs", () => {
    // Spawned scripts and computed paths are named, not imported.
    const pkg = packageOf(selector.workspace, "apps/server/src/index.ts");
    assert.equal(pkg, "apps/server/");
    const reason = selectSuites(selector, ["apps/server/src/sandbox-relay/fake-tool.ts"]);
    assert.deepEqual([...reason.keys()], []);
    const twin = "apps/server/src/elsewhere/cancel-wire-fixtures.ts";
    assert.match(
      selectSuites(selector, [twin]).get("cancel-wire") ?? "",
      / names "cancel-wire-fixtures"/,
    );
  });
});

describe("closureOf", () => {
  test("follows relative, package-export, require, asset and directory references", (t) => {
    const dir = mkdtempSync(join(tmpdir(), "wire-affected-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const write = (path: string, text: string) => {
      mkdirSync(dirname(join(dir, path)), { recursive: true });
      writeFileSync(join(dir, path), text);
    };
    write(
      "packages/lib/package.json",
      JSON.stringify({
        name: "@x/lib",
        exports: {
          "./a": "./src/a.ts",
          // Every condition's target joins the closure, whatever vite picks.
          "./cond": { import: "./src/cond.node.ts", default: "./src/cond.ts" },
          // Broad first: the more specific pattern still wins, as in Node.
          "./*": { default: "./src/*.ts" },
          "./feature/*": "./special/*.ts",
        },
      }),
    );
    write("packages/lib/src/a.ts", 'export * from "./b.js";\n');
    write("packages/lib/src/b.ts", "export const b = 1;\n");
    write("packages/lib/src/c.ts", 'const d = require("./d");\n');
    write("packages/lib/src/d.js", "module.exports = 1;\n");
    write("packages/lib/src/unused.ts", "export {};\n");
    write("packages/lib/src/cond.ts", "export {};\n");
    write("packages/lib/src/cond.node.ts", "export {};\n");
    write("packages/lib/src/actual.ts", "export {};\n");
    write("packages/lib/src/typed.ts", "export type T = 1;\n");
    write("packages/lib/src/feature/entry.ts", "export {};\n");
    write("packages/lib/special/entry.ts", 'import "./only-here.js";\n');
    write("packages/lib/special/only-here.ts", "export {};\n");
    write("packages/lib/src/aliased.ts", "export {};\n");
    write("packages/lib/src/bracketed.ts", "export {};\n");
    write("apps/app/package.json", JSON.stringify({ name: "app" }));
    write(
      "apps/app/src/entry.test.ts",
      [
        'import { b } from "@x/lib/a";',
        "import type {",
        "  C,",
        '} from "@x/lib/c";',
        'import "vitest";',
        'const helper = new URL("./helper.py", import.meta.url);',
        'const cwd = new URL("..", import.meta.url);',
        'const data = await import("./data.json?raw");',
        'import "@x/lib/cond";',
        // A regex literal that reads like a comment opener hides nothing.
        "const special = /[/*]/;",
        'const real = await vi.importActual("../../../packages/lib/src/actual.ts");',
        'type T = import("@x/lib/typed").T;',
        'import "@x/lib/feature/entry";',
        'import { vi as v } from "vitest";',
        'const aliased = await v.importActual("@x/lib/aliased");',
        'const bracketed = await v["importActual"]("@x/lib/bracketed");',
        "",
      ].join("\n"),
    );
    write("apps/app/src/helper.py", "print(1)\n");
    write("apps/app/src/data.json", "{}\n");
    write(
      "apps/app/src/lazy.ts",
      'export const load = (name: string) => import("./" + name + ".js");\n',
    );
    write("apps/app/src/broken.ts", 'import "./missing.js";\n');
    write("apps/app/src/garbled/x.ts", "import { from;\n");
    write(
      "apps/app/src/indirect/x.ts",
      'import { vi as v } from "vitest";\nconst name = "importActual";\nawait v[name]("./y");\n',
    );
    const closure = closureOf(["apps/app/src/entry.test.ts"], dir);
    assert.deepEqual([...closure.files].sort(), [
      "apps/app/src/data.json",
      "apps/app/src/entry.test.ts",
      "apps/app/src/helper.py",
      "packages/lib/special/entry.ts",
      "packages/lib/special/only-here.ts",
      "packages/lib/src/a.ts",
      "packages/lib/src/actual.ts",
      "packages/lib/src/aliased.ts",
      "packages/lib/src/b.ts",
      "packages/lib/src/bracketed.ts",
      "packages/lib/src/c.ts",
      "packages/lib/src/cond.node.ts",
      "packages/lib/src/cond.ts",
      "packages/lib/src/d.js",
      "packages/lib/src/typed.ts",
    ]);
    assert.deepEqual([...closure.namedDirs], ["apps/app/"]);
    assert.ok(closure.strings.get("apps/app/src/entry.test.ts")?.includes("./helper.py"));
    assert.deepEqual(closure.unresolved, []);
    const lazy = closureOf(
      [
        "apps/app/src/lazy.ts",
        "apps/app/src/broken.ts",
        "apps/app/src/garbled/x.ts",
        "apps/app/src/indirect/x.ts",
      ],
      dir,
    );
    // A computed load (a specifier, or a vitest loader's name), and a file the
    // parser cannot read, make their directory an input.
    assert.deepEqual([...lazy.computedDirs].sort(), [
      "apps/app/src/",
      "apps/app/src/garbled/",
      "apps/app/src/indirect/",
    ]);
    assert.deepEqual(lazy.unresolved, [["apps/app/src/broken.ts", "./missing.js"]]);
  });
});

describe("suiteEntries", () => {
  test("only a provably literal test.include lists the files; anything else fails open", (t) => {
    const dir = mkdtempSync(join(tmpdir(), "wire-affected-config-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    mkdirSync(join(dir, "scripts"));
    const config = (text: string) => {
      writeFileSync(join(dir, "scripts/vitest-cancel-wire.config.ts"), `${text}\n`);
      return suiteEntries("cancel-wire", dir);
    };
    const listed = {
      entries: ["scripts/vitest-cancel-wire.config.ts", "a/x.contract.test.ts"],
    };
    const plain = 'include: ["a/x.contract.test.ts"]';
    assert.deepEqual(config(`export default defineConfig({ test: { ${plain} } });`), listed);
    // The relay-chaos shape: an arrow function returning the options.
    assert.deepEqual(
      config(`export default defineConfig(({ mode }) => ({ test: { ${plain}, env: { mode } } }));`),
      listed,
    );
    for (const text of [
      'export default defineConfig({ test: { include: ["a/x.contract.test.ts", "a/**/*.test.ts"] } });',
      "export default defineConfig({ test: { include: [name] } });",
      "export default defineConfig({ test: { include: [] } });",
      'export default defineConfig({ test: { environment: "node" } });',
      // A spread or merge could replace the literal list.
      `export default defineConfig({ test: { ${plain}, ...extra } });`,
      `export default defineConfig({ ...base, test: { ${plain} } });`,
      `export default mergeConfig(base, defineConfig({ test: { ${plain} } }));`,
      `export default { test: { ${plain} } };`,
      `export default defineConfig({ test: { ${plain}, include: ["b.test.ts"] } });`,
    ])
      assert.match(config(text).failOpen ?? "", /scripts\/vitest-cancel-wire\.config\.ts: /, text);
  });

  test("each suite's package script runs exactly its config, with no extra filters", () => {
    for (const suite of SUITES)
      assert.equal(
        scripts[SUITE_SCRIPTS[suite]],
        `cargo build -p wssp --bin wssp --locked && vitest run --config scripts/vitest-${suite}.config.ts`,
      );
  });
});

describe("changedFiles", () => {
  test("commits, edits, untracked files, and both sides of a rename since the merge base", (t) => {
    const dir = mkdtempSync(join(tmpdir(), "wire-affected-git-"));
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    // A git hook (or any caller) may export GIT_DIR, GIT_INDEX_FILE and the
    // like; inherited, they would point this scratch repo's writes at the
    // caller's repository. Drop every GIT_* variable.
    const env = Object.fromEntries(
      Object.entries(process.env).filter(([name]) => !name.startsWith("GIT_")),
    );
    const git = (...args: string[]) => {
      // No hooks either: a global core.hooksPath must not judge this repo. And
      // quotePath pinned on: a global core.quotePath=false would hide the
      // quoting the non-ASCII case below guards against.
      const config = [
        ...["-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null"],
        ...["-c", "core.quotePath=true"],
      ];
      const result = spawnSync("git", [...config, ...args], {
        cwd: dir,
        encoding: "utf8",
        env: {
          ...env,
          GIT_CEILING_DIRECTORIES: tmpdir(),
          GIT_AUTHOR_NAME: "t",
          GIT_AUTHOR_EMAIL: "t@example.com",
          GIT_COMMITTER_NAME: "t",
          GIT_COMMITTER_EMAIL: "t@example.com",
        },
      });
      return result.status === 0 ? result.stdout : undefined;
    };
    git("init", "-q", "-b", "main");
    mkdirSync(join(dir, "crates/x"), { recursive: true });
    mkdirSync(join(dir, "apps/web"), { recursive: true });
    writeFileSync(join(dir, "crates/x/lib.rs"), "fn body_that_stays_the_same() {}\n");
    writeFileSync(join(dir, "apps/web/a.ts"), "1");
    writeFileSync(join(dir, "README.md"), "1");
    git("add", ".");
    git("commit", "-q", "-m", "base");
    git("update-ref", "refs/remotes/origin/main", "HEAD");
    git("checkout", "-q", "-b", "feature");
    writeFileSync(join(dir, "apps/web/a.ts"), "2");
    git("mv", "crates/x/lib.rs", "apps/web/lib.rs");
    // A committed non-ASCII name exercises the diff side; the untracked one below, ls-files.
    writeFileSync(join(dir, "apps/web/naïve.ts"), "1");
    git("add", "apps/web/naïve.ts");
    git("commit", "-q", "-am", "edit");
    writeFileSync(join(dir, "README.md"), "2");
    writeFileSync(join(dir, "new.ts"), "1");
    mkdirSync(join(dir, "docs"));
    writeFileSync(join(dir, "docs/café.md"), "1");
    const run = (args: readonly string[]) => git(...args);
    assert.deepEqual(changedFiles(run)?.sort(), [
      "README.md",
      "apps/web/a.ts",
      "apps/web/lib.rs",
      "apps/web/naïve.ts",
      "crates/x/lib.rs",
      "docs/café.md",
      "new.ts",
    ]);
    // A commit on a local main that origin/main lacks still counts.
    git("checkout", "-q", "main");
    writeFileSync(join(dir, "crates/x/lib.rs"), "fn changed() {}\n");
    git("commit", "-q", "-am", "local only");
    assert.deepEqual(changedFiles(run)?.sort(), [
      "README.md",
      "crates/x/lib.rs",
      "docs/café.md",
      "new.ts",
    ]);
    // Without origin/main the unpushed commits are unknown, so everything
    // runs: on main itself, and on a branch of a main with unpushed commits.
    git("update-ref", "-d", "refs/remotes/origin/main");
    assert.equal(changedFiles(run), undefined);
    git("checkout", "-q", "-b", "web-only");
    writeFileSync(join(dir, "apps/web/a.ts"), "3");
    git("commit", "-q", "-am", "web");
    assert.equal(changedFiles(run), undefined);
  });
});
