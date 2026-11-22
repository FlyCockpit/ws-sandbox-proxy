/**
 * Which wire suites a change can affect, for `pnpm verify:fast`
 * (`scripts/test-wire-affected.ts`). `pnpm verify` and CI always run both.
 *
 * `test:cancel-wire` and `test:relay-chaos` build the `wssp` daemon and drive
 * it from vitest. A suite reads:
 *   - every file Cargo builds the daemon from (RUST_PATHS),
 *   - the module closure of its vitest config (read with vite's parser): the
 *     config, the test files it includes and every repo file they import,
 *     re-export, `import()`, `require()`, load with a `vi` loader or name with
 *     `new URL("…", import.meta.url)`, followed
 *     transitively through relative paths and workspace package exports
 *     (computed from the tree on every run, so it cannot go stale),
 *   - any other file of a workspace package that closure reaches into (data,
 *     fixtures, package.json, tsconfig), and
 *   - node_modules (the lockfile and workspace manifests, SHARED_PATHS).
 *
 * Fails open. A changed path selects a suite when any of these hold: it is a
 * Rust or shared input; it is in the suite's closure; its file name (or, for a
 * module, its stem) occurs anywhere in a closure file (a spawned script, a
 * computed path); it is a non-module file of a package the closure reaches;
 * it lies under a directory whose closure file loads a computed specifier
 * (or cannot be parsed); the config's include list is not provably literal;
 * or it is outside every workspace package and ROOT_SKIP_PATHS does not list
 * it. Only what is left is skipped: modules nothing in the closure imports or
 * names, packages the closure never reaches, and the root paths
 * ROOT_SKIP_PATHS lists as unread. The self-test
 * (`scripts/lib/wire-affected.test.ts`, in `pnpm test:setup`) checks that the
 * closure resolves completely, that every file Cargo builds the daemon from is
 * a Rust input, and that no closure file names a skipped package or root path.
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { parseAst } from "vitest/node";

export const ROOT = resolve(import.meta.dirname!, "../..");

export const SUITES = ["cancel-wire", "relay-chaos"] as const;
export type Suite = (typeof SUITES)[number];

/** The package.json script and vitest config of each suite. */
export const SUITE_SCRIPTS: Record<Suite, string> = {
  "cancel-wire": "test:cancel-wire",
  "relay-chaos": "test:relay-chaos",
};
const SUITE_CONFIGS: Record<Suite, string> = {
  "cancel-wire": "scripts/vitest-cancel-wire.config.ts",
  "relay-chaos": "scripts/vitest-relay-chaos.config.ts",
};

/** A rule path matches exactly, or as a prefix when it ends in "/". */
const matches = (rulePath: string, path: string) =>
  rulePath.endsWith("/") ? path.startsWith(rulePath) : path === rulePath;

/** Everything Cargo may read to build `wssp` (workspace members, vendored
 * crates, toolchain and config). The self-test checks the members. */
const RUST_PATHS = [
  "Cargo.toml",
  "Cargo.lock",
  "apps/cli/",
  "crates/",
  "third_party/",
  ".cargo/",
  ".config/nextest.toml",
  "rust-toolchain",
  "rust-toolchain.toml",
] as const;

/** Inputs of both suites that no closure reflects: dependencies, the Node
 * version, the selector itself. */
const SHARED_PATHS = [
  "package.json",
  "pnpm-lock.yaml",
  "pnpm-workspace.yaml",
  ".nvmrc",
  ".npmrc",
  "tsconfig.json",
  "scripts/lib/wire-affected.ts",
  "scripts/lib/wire-affected.test.ts",
  "scripts/test-wire-affected.ts",
] as const;

/** Paths that select a suite although its closure does not read them. */
const EXTRA_PATHS: readonly { path: string; suites: readonly Suite[]; why: string }[] = [
  {
    // The selection brief names the SDK's cancel path; neither suite imports
    // the SDK today, so this costs a run and never hides one.
    path: "packages/sdk/src/commands.ts",
    suites: ["cancel-wire"],
    why: "the SDK's cancel path",
  },
];

/**
 * Paths outside every workspace package that neither suite reads. Every other
 * root path runs both suites (fail open); the self-test lists unclassified
 * files so a new one is classified deliberately.
 */
export const ROOT_SKIP_PATHS = [
  ".github/",
  "docs/",
  "licenses/",
  ".cursorrules",
  ".dockerignore",
  ".editorconfig",
  ".env.docker.defaults",
  ".env.example",
  ".gitattributes",
  ".gitignore",
  ".oxlintrc.json",
  "AGENTS.md",
  "CHANGELOG.md",
  "CLAUDE.md",
  "CODE_OF_CONDUCT.md",
  "CONTRIBUTING.md",
  "Dockerfile",
  "Dockerfile.dev",
  "Dockerfile.worker",
  "LICENSE",
  "README.md",
  "SECURITY.md",
  "THIRD-PARTY-LICENSES.md",
  "_typos.toml",
  "biome.json",
  "docker-compose.agent.yml",
  "docker-compose.dev.yml",
  "docker-compose.podman-rootless.yml",
  "doctor.config.jsonc",
  "knip.jsonc",
  "lefthook.yml",
  "portless.json",
  "tsconfig.scripts.json",
  "tsconfig.sdk-dts.json",
  "turbo.json",
  "vitest.config.ts",
  "vitest.pg.config.ts",
  "vitest.s3.config.ts",
] as const;

const MODULE_RE = /\.(?:[cm]?[jt]s|tsx|jsx)$/;

/**
 * Prisma's generated client: git-ignored (never in a diff), generated from
 * packages/db/prisma/schema/ (data files of a package the suites reach, so a
 * schema change runs them) and importing only itself and @prisma/*. Its files
 * join the closure without being scanned (1.8 MB modules; the scan would
 * dominate the selector's run time).
 */
export const GENERATED_DIRS = ["packages/db/prisma/generated/"] as const;

export interface Workspace {
  /** Package directory (repo-relative, trailing "/") → package.json. */
  packages: Map<string, { name: string; exports: unknown }>;
  byName: Map<string, string>;
}

export function readWorkspace(root = ROOT): Workspace {
  const packages = new Map<string, { name: string; exports: unknown }>();
  const byName = new Map<string, string>();
  for (const group of ["apps", "packages"]) {
    const groupDir = join(root, group);
    if (!existsSync(groupDir)) continue;
    for (const entry of readdirSync(groupDir)) {
      const manifest = join(groupDir, entry, "package.json");
      if (!existsSync(manifest)) continue;
      const { name, exports } = JSON.parse(readFileSync(manifest, "utf8")) as {
        name: string;
        exports?: unknown;
      };
      const dir = `${group}/${entry}/`;
      packages.set(dir, { name, exports });
      byName.set(name, dir);
    }
  }
  return { packages, byName };
}

/** The workspace package directory holding `path`, if any. */
export function packageOf(workspace: Workspace, path: string): string | undefined {
  for (const dir of workspace.packages.keys()) if (path.startsWith(dir)) return dir;
  return undefined;
}

const isFile = (path: string) => existsSync(path) && statSync(path).isFile();

/** Vite/Node-style file candidates for an import target. */
function fileFor(base: string): string | undefined {
  const candidates = [base];
  const js = base.match(/^(.*)\.([cm]?)js$/);
  if (js) candidates.push(`${js[1]}.${js[2]}ts`, `${js[1]}.tsx`);
  for (const ext of [".ts", ".tsx", ".mts", ".js", ".mjs", ".cjs", ".json"])
    candidates.push(base + ext);
  for (const index of ["index.ts", "index.tsx", "index.js"]) candidates.push(join(base, index));
  return candidates.find(isFile);
}

/** Every target an `exports` value can select, under any condition. */
function exportTargets(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(exportTargets);
  if (value && typeof value === "object") return Object.values(value).flatMap(exportTargets);
  return [];
}

/**
 * The repo files a specifier can load: [] when it resolves to nothing,
 * "external" for a non-workspace package (node_modules: the lockfile). A
 * conditional export yields every condition's target, so the closure holds
 * whichever one vite picks.
 */
function resolveSpecifier(
  workspace: Workspace,
  root: string,
  spec: string,
  from: string,
): string[] | "external" {
  const bare = spec.replace(/[?#].*$/, "");
  if (bare.startsWith(".") || bare.startsWith("/")) {
    const file = fileFor(resolve(dirname(from), bare));
    return file === undefined ? [] : [file];
  }
  const parts = bare.match(/^(@[^/]+\/[^/]+|[^@/][^/]*)(\/.*)?$/);
  if (!parts) return [];
  const dir = workspace.byName.get(parts[1]!);
  if (!dir) return "external";
  const sub = `.${parts[2] ?? ""}`;
  const exports = workspace.packages.get(dir)!.exports;
  let targets: string[] = [];
  if (typeof exports === "string" || Array.isArray(exports))
    targets = sub === "." ? exportTargets(exports) : [];
  else if (exports && typeof exports === "object") {
    const map = exports as Record<string, unknown>;
    const conditional = !Object.keys(map).some((key) => key.startsWith("."));
    if (conditional) targets = sub === "." ? exportTargets(map) : [];
    else {
      // An exact key wins; otherwise the most specific matching pattern, as
      // Node orders them (longest prefix before "*", then the longer key).
      if (sub in map) targets = exportTargets(map[sub]);
      else {
        const best = Object.keys(map)
          .filter((key) => {
            const [head, tail, more] = key.split("*");
            return (
              tail !== undefined &&
              more === undefined &&
              sub.startsWith(head!) &&
              sub.endsWith(tail) &&
              sub.length >= head!.length + tail.length
            );
          })
          .sort((a, b) => b.indexOf("*") - a.indexOf("*") || b.length - a.length)[0];
        if (best !== undefined) {
          const [head, tail] = best.split("*") as [string, string];
          const star = sub.slice(head.length, sub.length - tail.length);
          targets = exportTargets(map[best]).map((target) => target.replaceAll("*", star));
        }
      }
    }
  }
  const files = targets.map((target) => fileFor(resolve(root, dir, target)));
  // One target that resolves to nothing makes the whole specifier unresolved.
  return files.every((file) => file !== undefined) ? (files as string[]) : [];
}

type Node = { type: string; [key: string]: unknown };
const isNode = (value: unknown): value is Node =>
  typeof value === "object" && value !== null && typeof (value as Node).type === "string";

/** A string literal, or a template literal without expressions. */
function staticString(node: unknown): string | undefined {
  if (!isNode(node)) return undefined;
  if (node.type === "Literal" && typeof node.value === "string") return node.value;
  if (node.type === "TemplateLiteral" && (node.expressions as unknown[]).length === 0)
    return ((node.quasis as Node[])[0]!.value as { cooked: string }).cooked;
  return undefined;
}

function walk(node: unknown, visit: (node: Node) => void) {
  if (Array.isArray(node)) for (const item of node) walk(item, visit);
  else if (isNode(node)) {
    visit(node);
    for (const [key, value] of Object.entries(node))
      if (key !== "parent" && typeof value === "object") walk(value, visit);
  }
}

const isImportMetaUrl = (node: unknown) =>
  isNode(node) &&
  node.type === "MemberExpression" &&
  isNode(node.object) &&
  node.object.type === "MetaProperty" &&
  isNode(node.property) &&
  node.property.name === "url";

/** The names a module binds to vitest's `vi` (`vi`, `vitest`, an alias). */
function vitestNames(ast: unknown): Set<string> {
  const names = new Set(["vi", "vitest"]);
  for (const node of (isNode(ast) ? (ast.body as unknown[]) : []).filter(isNode))
    if (node.type === "ImportDeclaration" && staticString(node.source) === "vitest")
      for (const spec of (node.specifiers as unknown[]).filter(isNode))
        if (isNode(spec.local) && typeof spec.local.name === "string") names.add(spec.local.name);
  return names;
}

/** Module-loading calls besides `import()`: `require`, `require.resolve` and
 * vitest's module loaders (`vi.importActual` loads the real module). */
function loaderCall(node: Node): boolean {
  const callee = node.callee;
  if (!isNode(callee)) return false;
  if (callee.type === "Identifier") return callee.name === "require";
  if (callee.type !== "MemberExpression" || !isNode(callee.property)) return false;
  // `v.importActual(…)` and `v["importActual"](…)` alike.
  const property = callee.computed ? staticString(callee.property) : callee.property.name;
  if (isNode(callee.object) && callee.object.name === "require") return property === "resolve";
  // vitest's loaders on any object (`vi`, `vitest`, an alias): over-inclusion
  // of a look-alike only adds files.
  return ["mock", "doMock", "unmock", "importActual", "importMock"].includes(property as string);
}

interface ModuleScan {
  /** `[specifier, kind]`: an import/export/loader edge, or a `new URL` path. */
  edges: [string, "module" | "url"][];
  /** A load whose specifier is computed (not one static string). */
  computed: boolean;
  /** Every static string of the module (comments are not strings). */
  strings: string[];
}

/** The static edges and strings of a module, from its syntax tree (vite's
 * parser). A file it cannot parse is reported as computed (fail open). */
function scanModule(text: string, file: string): ModuleScan {
  const scan: ModuleScan = { edges: [], computed: false, strings: [] };
  let ast: unknown;
  try {
    ast = parseAst(text, { lang: /\.tsx?$|\.[cm]ts$/.test(file) ? "ts" : "js" });
  } catch {
    scan.computed = true;
    return scan;
  }
  const vitest = vitestNames(ast);
  const source = (value: unknown) => {
    const spec = staticString(value);
    if (spec === undefined) scan.computed = true;
    else scan.edges.push([spec, "module"]);
  };
  walk(ast, (node) => {
    if (node.type === "Literal" && typeof node.value === "string") scan.strings.push(node.value);
    if (node.type === "TemplateElement")
      scan.strings.push((node.value as { cooked: string | null; raw: string }).cooked ?? "");
    switch (node.type) {
      case "ImportDeclaration":
      case "ExportAllDeclaration":
        source(node.source);
        break;
      case "ExportNamedDeclaration":
        if (node.source) source(node.source);
        break;
      case "ImportExpression":
        source(node.source);
        break;
      case "TSExternalModuleReference":
        source(node.expression);
        break;
      case "TSImportType":
        source(
          isNode(node.argument) && node.argument.type === "TSLiteralType"
            ? node.argument.literal
            : (node.source ?? node.argument),
        );
        break;
      case "CallExpression": {
        if (loaderCall(node)) source((node.arguments as unknown[])[0]);
        // `v[name](…)` on vitest's object: a loader whose name is computed.
        const callee = node.callee;
        if (
          isNode(callee) &&
          callee.type === "MemberExpression" &&
          callee.computed &&
          staticString(callee.property) === undefined &&
          isNode(callee.object) &&
          vitest.has(callee.object.name as string)
        )
          scan.computed = true;
        break;
      }
      case "NewExpression": {
        const args = node.arguments as unknown[];
        if (isNode(node.callee) && node.callee.name === "URL" && isImportMetaUrl(args[1])) {
          const spec = staticString(args[0]);
          if (spec === undefined) scan.computed = true;
          else scan.edges.push([spec, "url"]);
        }
        break;
      }
    }
  });
  return scan;
}

interface Closure {
  /** Repo-relative files the suite loads or names. */
  files: Set<string>;
  /** Repo-relative contents of the closure's modules. */
  texts: Map<string, string>;
  /** Every static string of the closure's modules, by file. */
  strings: Map<string, string[]>;
  /** Directories whose every file the suite may read: those of closure files
   * that load a computed specifier, and non-package directories named with
   * `new URL("dir/", import.meta.url)`. */
  computedDirs: Set<string>;
  /** Package directories named by `new URL(…)` (e.g. a child's cwd). */
  namedDirs: Set<string>;
  /** Specifiers that resolved to nothing: `[file, specifier]`. */
  unresolved: [string, string][];
  /** Set when the suite's test files cannot be listed exactly: every change runs it. */
  failOpen?: string;
}

export function closureOf(
  entries: readonly string[],
  root = ROOT,
  workspace = readWorkspace(root),
) {
  const closure: Closure = {
    files: new Set(),
    texts: new Map(),
    strings: new Map(),
    computedDirs: new Set(),
    namedDirs: new Set(),
    unresolved: [],
  };
  const queue = entries.map((entry) => resolve(root, entry));
  while (queue.length > 0) {
    const file = queue.pop()!;
    const path = relative(root, file).split(sep).join("/");
    if (closure.files.has(path)) continue;
    closure.files.add(path);
    if (!MODULE_RE.test(file) || !isFile(file)) continue;
    if (GENERATED_DIRS.some((dir) => path.startsWith(dir))) continue;
    const text = readFileSync(file, "utf8");
    closure.texts.set(path, text);
    const scan = scanModule(text, file);
    closure.strings.set(path, scan.strings);
    if (scan.computed) closure.computedDirs.add(`${dirname(path)}/`);
    for (const [spec, kind] of scan.edges) {
      if (spec.startsWith("node:")) continue;
      if (kind === "url") {
        const target = resolve(dirname(file), spec);
        if (existsSync(target) && statSync(target).isDirectory()) {
          const rel = `${relative(root, target).split(sep).join("/")}/`;
          const pkg = packageOf(workspace, rel);
          if (pkg !== undefined) closure.namedDirs.add(pkg);
          else closure.computedDirs.add(rel);
          continue;
        }
        if (existsSync(target)) {
          queue.push(target);
          continue;
        }
      }
      const targets = resolveSpecifier(workspace, root, spec, file);
      if (targets === "external") continue;
      if (targets.length === 0) closure.unresolved.push([path, spec]);
      else queue.push(...targets);
    }
  }
  return closure;
}

/**
 * A suite's vitest config and the test files its `include` lists. The list
 * must be literal file paths: a glob, a computed entry or a missing list
 * returns `failOpen` (the suite then runs on every change, and the self-test
 * fails until the selector learns to expand it).
 */
export function suiteEntries(suite: Suite, root = ROOT): { entries: string[]; failOpen?: string } {
  const config = SUITE_CONFIGS[suite];
  const fail = (why: string) => ({ entries: [config], failOpen: `${config}: ${why}` });
  // Only `export default defineConfig({ test: { include: [...] } })`, or the
  // same returned by an arrow function, proves the effective list: a spread,
  // a merge or any other shape could replace it.
  const program = parseAst(readFileSync(join(root, config), "utf8"), {
    lang: "ts",
  }) as unknown as Node;
  const exported = (program.body as Node[]).find(
    (node) => node.type === "ExportDefaultDeclaration",
  );
  const call = exported?.declaration;
  if (
    !isNode(call) ||
    call.type !== "CallExpression" ||
    !isNode(call.callee) ||
    call.callee.name !== "defineConfig"
  )
    return fail("the default export is not defineConfig(…)");
  let options = (call.arguments as unknown[])[0];
  if (isNode(options) && options.type === "ArrowFunctionExpression") options = options.body;
  const property = (object: unknown, name: string): Node | undefined | null => {
    if (!isNode(object) || object.type !== "ObjectExpression") return null;
    const props = object.properties as Node[];
    if (props.some((prop) => prop.type !== "Property" || prop.computed)) return null;
    const found = props.filter(
      (prop) => isNode(prop.key) && (prop.key.name ?? prop.key.value) === name,
    );
    return found.length > 1 ? null : (found[0]?.value as Node | undefined);
  };
  const test = property(options, "test");
  const include = test ? property(test, "include") : test;
  if (!isNode(include) || include.type !== "ArrayExpression")
    return fail(
      "no single literal test.include in a plain object (spreads and merges are not followed)",
    );
  const tests = (include.elements as unknown[]).map(staticString);
  const odd = tests.findIndex((entry) => entry === undefined || /[*?{}[\]!]/.test(entry));
  if (odd >= 0) return fail(`include entry ${tests[odd] ?? "(computed)"} is not a file path`);
  if (tests.length === 0) return fail("include is empty");
  return { entries: [config, ...(tests as string[])] };
}

export interface Selector {
  closures: Record<Suite, Closure>;
  workspace: Workspace;
}

export function buildSelector(root = ROOT): Selector {
  const workspace = readWorkspace(root);
  const closures = Object.fromEntries(
    SUITES.map((suite) => {
      const { entries, failOpen } = suiteEntries(suite, root);
      return [suite, { ...closureOf(entries, root, workspace), failOpen }];
    }),
  ) as Record<Suite, Closure>;
  return { closures, workspace };
}

/** The workspace packages a closure reaches into (trailing "/"). */
export function reachedPackages(selector: Selector, suite: Suite): Set<string> {
  const reached = new Set<string>();
  for (const file of selector.closures[suite].files) {
    const pkg = packageOf(selector.workspace, file);
    if (pkg !== undefined) reached.add(pkg);
  }
  for (const dir of selector.closures[suite].namedDirs) reached.add(dir);
  return reached;
}

const joined = new WeakMap<Closure, string>();

/** The closure file whose text contains `needle`, if any. */
function namedBy(closure: Closure, needle: string): string | undefined {
  if (needle.length === 0) return undefined;
  let all = joined.get(closure);
  if (all === undefined) {
    all = [...closure.texts.values()].join("\0");
    joined.set(closure, all);
  }
  if (!all.includes(needle)) return undefined;
  for (const [file, text] of closure.texts) if (text.includes(needle)) return file;
  return undefined;
}

/**
 * Why `path` selects `suite`, or undefined when the suite cannot read it.
 * Unreached packages and ROOT_SKIP_PATHS are skipped without a name search:
 * the self-test proves no closure file names them in a string.
 */
export function reasonFor(selector: Selector, suite: Suite, path: string): string | undefined {
  if (RUST_PATHS.some((rule) => matches(rule, path))) return "a Rust input of the wssp daemon";
  if (SHARED_PATHS.some((rule) => matches(rule, path))) return "a shared input";
  const extra = EXTRA_PATHS.find((rule) => rule.path === path && rule.suites.includes(suite));
  if (extra) return extra.why;
  const closure = selector.closures[suite];
  if (closure.failOpen !== undefined) return closure.failOpen;
  if (closure.files.has(path)) return "the suite loads it";
  for (const dir of closure.computedDirs)
    if (path.startsWith(dir)) return `${dir} loads a computed specifier`;
  const name = path.slice(path.lastIndexOf("/") + 1);
  const module = MODULE_RE.test(name);
  const pkg = packageOf(selector.workspace, path);
  if (pkg !== undefined && !reachedPackages(selector, suite).has(pkg)) return undefined;
  if (pkg === undefined && ROOT_SKIP_PATHS.some((rule) => matches(rule, path))) return undefined;
  if (pkg === undefined && !path.startsWith("scripts/"))
    return "no rule in scripts/lib/wire-affected.ts classifies it";
  // A reached package or scripts/: a module runs when a closure file names it
  // (a spawned or read path; an import would have put it in the closure).
  const stem = module ? name.replace(MODULE_RE, "") : name;
  const named = namedBy(closure, stem);
  if (named !== undefined) return `${named} names "${stem}"`;
  if (pkg !== undefined && !module) return `a data file of ${pkg}, which the suite loads`;
  return undefined;
}

/** Each suite to run, with the first path that selects it and why. */
export function selectSuites(
  selector: Selector,
  changed: readonly string[] | undefined,
): Map<Suite, string> {
  if (changed === undefined)
    return new Map(SUITES.map((suite) => [suite, "the changed paths are unknown"]));
  const selected = new Map<Suite, string>();
  for (const suite of SUITES)
    for (const path of changed) {
      const reason = reasonFor(selector, suite, path);
      if (reason !== undefined) {
        selected.set(suite, `${path} changed (${reason})`);
        break;
      }
    }
  return selected;
}

/** The only trusted base: a local `main` may hold unpushed commits itself. */
const BASE_REF = "origin/main";

export type Git = (args: readonly string[]) => string | undefined;

/**
 * Files changed since the merge base with the default branch: commits, staged
 * and unstaged edits, and untracked files; a rename lists both of its paths.
 * undefined when unknown.
 */
export function changedFiles(git: Git): string[] | undefined {
  // Without origin/main the unpushed commits are unknown, so everything runs.
  const base = git(["merge-base", "HEAD", BASE_REF])?.trim();
  if (!base) return undefined;
  // -z: paths verbatim (no core.quotePath quoting of non-ASCII names).
  const diff = git(["diff", "-z", "--name-only", "--no-renames", base]);
  const untracked = git(["ls-files", "-z", "--others", "--exclude-standard"]);
  if (diff === undefined || untracked === undefined) return undefined;
  return [...diff.split("\0"), ...untracked.split("\0")].filter(Boolean);
}
