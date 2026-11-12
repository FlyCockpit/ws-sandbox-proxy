import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

/**
 * Publishability proof: `pnpm pack` the SDK (never publish), unpack the tarball
 * into a temp project OUTSIDE the monorepo with only its declared runtime
 * dependency copied in, then type-check and run a consumer program against it.
 * Any leaked workspace reference (source path, `workspace:` specifier,
 * unresolved type) fails here instead of at a user's `npm install`.
 */

const sdkDir = fileURLToPath(new URL("..", import.meta.url));
const require = createRequire(import.meta.url);

const roots: string[] = [];
function workspace(): string {
  const dir = mkdtempSync(join(tmpdir(), "wssp-sdk-consumer-"));
  roots.push(dir);
  return dir;
}

afterAll(() => {
  for (const dir of roots.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function pack(): { dir: string; tarball: string } {
  const dir = workspace();
  execFileSync("pnpm", ["pack", "--pack-destination", dir], { cwd: sdkDir, stdio: "pipe" });
  const tarball = readdirSync(dir).find((name) => name.endsWith(".tgz"));
  if (!tarball) throw new Error("pnpm pack produced no tarball");
  return { dir, tarball: join(dir, tarball) };
}

/** Copy an installed dependency (and nothing else) into the consumer. */
function stageDependency(dir: string, name: string, fromPaths: string[]): void {
  const manifest = require.resolve(`${name}/package.json`, { paths: fromPaths });
  const target = join(dir, "node_modules", name);
  mkdirSync(dirname(target), { recursive: true });
  cpSync(dirname(manifest), target, { recursive: true });
}

function stageConsumer(dir: string, tarball: string): void {
  const moduleDir = join(dir, "node_modules", "@wssp", "sdk");
  mkdirSync(moduleDir, { recursive: true });
  execFileSync("tar", ["-xzf", tarball, "-C", moduleDir, "--strip-components=1"]);
  stageDependency(dir, "zod", [sdkDir]);
  // A realistic Node consumer's types; proves the declarations need nothing
  // from this monorepo (no @wssp/* or server packages are staged at all).
  stageDependency(dir, "@types/node", [sdkDir]);
  const typesDir = join(dir, "node_modules", "@types", "node");
  stageDependency(dir, "undici-types", [typesDir]);
  const fixture = fileURLToPath(new URL("fixture", import.meta.url));
  for (const file of ["package.json", "tsconfig.json", "main.mts"]) {
    cpSync(join(fixture, file), join(dir, file));
  }
}

describe("packed consumer fixture", () => {
  it("packs, type-checks and runs outside the monorepo", { timeout: 180_000 }, () => {
    const { dir, tarball } = pack();

    const entries = execFileSync("tar", ["-tzf", tarball], { encoding: "utf8" });
    for (const entry of [
      "package/LICENSE",
      "package/README.md",
      "package/dist/index.mjs",
      "package/dist/index.d.mts",
    ]) {
      expect(entries).toContain(entry);
    }

    stageConsumer(dir, tarball);

    const manifest = JSON.parse(
      execFileSync("cat", [join(dir, "node_modules", "@wssp", "sdk", "package.json")], {
        encoding: "utf8",
      }),
    ) as { dependencies?: Record<string, string>; devDependencies?: unknown };
    expect(Object.keys(manifest.dependencies ?? {})).toEqual(["zod"]);
    expect(manifest.dependencies?.zod).not.toContain("workspace:");

    const tsc = join(
      dirname(require.resolve("typescript/package.json")),
      // Not in the package's exports map; resolve it relative to the manifest.
      "bin",
      "tsc",
    );
    execFileSync(process.execPath, [tsc, "-p", "tsconfig.json"], { cwd: dir, stdio: "pipe" });

    const output = execFileSync(process.execPath, ["main.mts"], {
      cwd: dir,
      encoding: "utf8",
    });
    expect(output).toContain("consumer ok true true true true true");
  });
});
