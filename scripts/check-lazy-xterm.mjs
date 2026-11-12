#!/usr/bin/env node
/**
 * Build check (C54): xterm ships only in a lazy chunk.
 *
 *   pnpm -F web build && pnpm check:lazy-xterm
 *
 * Reads the client Vite manifest (`apps/web/dist/client/.vite/manifest.json`)
 * and the emitted assets, then asserts:
 *   1. `src/lib/xterm-view.ts` is a dynamic entry (reached only by `import()`).
 *   2. Every JS chunk that contains xterm code and every CSS file with
 *      xterm's styles belongs to that entry's static closure.
 *   3. No other entry's static closure contains xterm: not the initial
 *      `isEntry` chunk, not any route chunk (the sandbox detail route
 *      included), not any other dynamic entry.
 *   4. The xterm-view entry does contain xterm (the markers are not stale).
 *
 * Usage: node scripts/check-lazy-xterm.mjs [path/to/dist/client]
 */
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const CLIENT = resolve(process.argv[2] ?? join(ROOT, "apps/web/dist/client"));
const MANIFEST = join(CLIENT, ".vite/manifest.json");
const VIEW_ENTRY = "src/lib/xterm-view.ts";
/** Strings present in xterm's code and stylesheet, absent from ours. */
const JS_MARKER = "xterm-helper-textarea";
const CSS_MARKER = ".xterm-viewport";

function fail(message) {
  console.error(`check-lazy-xterm: ${message}`);
  process.exit(1);
}

if (!existsSync(MANIFEST)) fail(`no client manifest at ${MANIFEST}; run \`pnpm -F web build\``);
const manifest = JSON.parse(readFileSync(MANIFEST, "utf8"));

/** Static closure of one manifest key: its chunk, its static imports, recursively. */
function closure(key) {
  const seen = new Set();
  const stack = [key];
  while (stack.length > 0) {
    const next = stack.pop();
    if (seen.has(next)) continue;
    const chunk = manifest[next];
    if (!chunk) fail(`manifest references a missing chunk: ${next}`);
    seen.add(next);
    for (const imported of chunk.imports ?? []) stack.push(imported);
  }
  return seen;
}

function files(keys) {
  const js = new Set();
  const css = new Set();
  for (const key of keys) {
    js.add(manifest[key].file);
    for (const sheet of manifest[key].css ?? []) css.add(sheet);
  }
  return { js, css };
}

const contents = new Map();
function contains(file, marker) {
  if (!contents.has(file)) contents.set(file, readFileSync(join(CLIENT, file), "utf8"));
  return contents.get(file).includes(marker);
}

const view = manifest[VIEW_ENTRY];
if (!view) fail(`${VIEW_ENTRY} is not in the manifest (renamed? update this check)`);
if (!view.isDynamicEntry) fail(`${VIEW_ENTRY} is not a dynamic entry`);
if (view.isEntry) fail(`${VIEW_ENTRY} is an initial entry`);

const viewFiles = files(closure(VIEW_ENTRY));
const viewHasJs = [...viewFiles.js].some((file) => contains(file, JS_MARKER));
const viewHasCss = [...viewFiles.css].some((file) => contains(file, CSS_MARKER));
if (!viewHasJs) fail(`no chunk of ${VIEW_ENTRY} contains xterm (marker "${JS_MARKER}" is stale?)`);
if (!viewHasCss) fail(`no stylesheet of ${VIEW_ENTRY} contains xterm's CSS ("${CSS_MARKER}")`);

const roots = Object.entries(manifest)
  .filter(([key, chunk]) => key !== VIEW_ENTRY && (chunk.isEntry || chunk.isDynamicEntry))
  .map(([key]) => key);
if (!roots.some((key) => manifest[key].isEntry)) fail("the manifest has no initial entry");

const problems = [];
for (const root of roots) {
  const { js, css } = files(closure(root));
  for (const file of js) {
    if (!viewFiles.js.has(file) && contains(file, JS_MARKER))
      problems.push(`${root} statically loads xterm code (${file})`);
    if (viewFiles.js.has(file) && contains(file, JS_MARKER))
      problems.push(`${root} statically loads the xterm chunk (${file})`);
  }
  for (const file of css) {
    if (contains(file, CSS_MARKER)) problems.push(`${root} statically loads xterm CSS (${file})`);
  }
}
if (problems.length > 0) fail(`xterm is not lazy:\n  ${problems.join("\n  ")}`);

const initial = roots.filter((key) => manifest[key].isEntry);
const xtermJs = [...viewFiles.js].filter((file) => contains(file, JS_MARKER));
const xtermCss = [...viewFiles.css].filter((file) => contains(file, CSS_MARKER));
console.log(
  `check-lazy-xterm: ok — xterm only in ${xtermJs.join(", ")} (+ ${xtermCss.join(", ")}); ` +
    `absent from ${initial.length} initial entr${initial.length === 1 ? "y" : "ies"} and ${roots.length - initial.length} other lazy chunks`,
);
