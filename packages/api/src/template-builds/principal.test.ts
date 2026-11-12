/**
 * The build principal cannot be minted outside its module: the
 * brand is type-only, only template-build code and the stored-principal
 * resolver may import the loader, and no file outside the helpers casts to a
 * principal type. (`kind: "build"` literals are covered by the principal-kinds
 * lint, whose kind set includes `build`.)
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import type { BuildPrincipal } from "./principal";

const REPO = resolve(import.meta.dirname, "../../../..");

function sources(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry === "dist" || entry === "generated") continue;
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) out.push(...sources(path));
    else if (/\.(ts|tsx)$/.test(entry) && !/\.test\.tsx?$/.test(entry)) out.push(path);
  }
  return out;
}

const roots = ["apps/server/src", "apps/web/src", "apps/worker/src"];
for (const name of readdirSync(resolve(REPO, "packages"))) {
  const src = resolve(REPO, "packages", name, "src");
  try {
    if (statSync(src).isDirectory()) roots.push(relative(REPO, src));
  } catch {
    // A package without `src/` has no TypeScript sources.
  }
}
const files = roots
  .flatMap((root) => sources(resolve(REPO, root)))
  .map((path) => ({
    path: relative(REPO, path).replaceAll("\\", "/"),
    text: readFileSync(path, "utf8"),
  }));

describe("build principal brand", () => {
  it("is not constructible from a plain object (type-level)", () => {
    // Compile-time twin: `BuildBrandIsPrivate` in principal.ts (check-types skips tests).
    // @ts-expect-error the brand symbol is module-private: a literal lacks it.
    const forged: BuildPrincipal = {
      kind: "build",
      ownerId: "owner",
      buildId: "build",
      keyId: null,
      key: null,
    };
    expect(forged.kind).toBe("build");
  });

  it("is imported for loading only by template-build code and the stored-principal resolver", () => {
    const importers = files
      .filter((file) => /\bloadBuildPrincipal\b/.test(file.text))
      .map((file) => file.path)
      .filter((path) => path !== "packages/api/src/template-builds/principal.ts");
    expect(importers.length).toBeGreaterThan(0);
    for (const path of importers)
      expect(
        path.startsWith("packages/api/src/template-builds/") ||
          path === "packages/api/src/sandbox/stored-principal.ts",
        path,
      ).toBe(true);
    // Never a router, a /v1 adapter or any apps/server file.
    expect(importers.filter((path) => /routers\/|^apps\//.test(path))).toEqual([]);
  });

  it("is never produced by a cast outside its module", () => {
    const casts = files.filter(
      (file) =>
        file.path !== "packages/api/src/template-builds/principal.ts" &&
        /\bas\s+(?:BuildPrincipal|Principal)\b/.test(file.text),
    );
    expect(casts.map((file) => file.path)).toEqual([]);
  });
});
