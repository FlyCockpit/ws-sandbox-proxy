/**
 * Apply a preset's theme/font tokens with an ephemeral, exactly pinned CLI.
 * Component regeneration is deliberately excluded: it would overwrite product
 * customizations and can restore the removed shadcn/tailwind.css import.
 */
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = resolve(import.meta.dirname, "..");
const SHADCN_VERSION = "4.18.0";
const CSS_PATH = "packages/ui/src/styles/globals.css";
const CONFIG_PATHS = ["apps/web/components.json", "packages/ui/components.json"];
const PACKAGE_PATHS = ["package.json", "apps/web/package.json", "packages/ui/package.json"];

type Run = (command: string, args: string[], root: string) => void;
const runCommand: Run = (command, args, root) => {
  execFileSync(command, args, { cwd: root, stdio: "inherit" });
};

export function validatePreset(preset: string | undefined): asserts preset is string {
  if (!preset || !/^[A-Za-z0-9]+$/.test(preset)) {
    throw new Error("Expected one base62 preset code from https://ui.shadcn.com/create.");
  }
}

function imports(css: string): string[] {
  // Font imports may change; every other import must remain byte-for-byte stable.
  return (css.match(/@import\s+[^;]+;/g) ?? []).filter(
    (statement) => !statement.includes("@fontsource"),
  );
}

export function applyTheme(preset: string, root = ROOT, run: Run = runCommand) {
  validatePreset(preset);
  const snapshot = (file: string) => ({
    path: resolve(root, file),
    content: readFileSync(resolve(root, file), "utf8"),
  });
  const configs = CONFIG_PATHS.map(snapshot);
  const packages = PACKAGE_PATHS.map(snapshot);
  const css = snapshot(CSS_PATH);
  const restore = (files: typeof configs) => {
    for (const file of files) writeFileSync(file.path, file.content);
  };

  console.log(`Applying preset ${preset} (theme + font only, shadcn ${SHADCN_VERSION}).`);
  try {
    run(
      "pnpm",
      [
        "dlx",
        `shadcn@${SHADCN_VERSION}`,
        "apply",
        "--preset",
        preset,
        "--only",
        "theme,font",
        "-c",
        "apps/web",
        "-y",
      ],
      root,
    );
    const nextCss = readFileSync(css.path, "utf8");
    if (
      nextCss.includes("shadcn/tailwind.css") ||
      JSON.stringify(imports(nextCss)) !== JSON.stringify(imports(css.content))
    ) {
      throw new Error(
        "The preset changed a protected CSS import. Keep the vendored ./shadcn-tailwind.css import; shadcn/tailwind.css is unavailable. Apply theme/font tokens only.",
      );
    }
    for (const file of packages) {
      const pkg = JSON.parse(readFileSync(file.path, "utf8")) as {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
      };
      if (pkg.dependencies?.shadcn || pkg.devDependencies?.shadcn) {
        throw new Error(
          "The preset added the removed shadcn dependency. Use theme/font tokens only.",
        );
      }
    }
  } catch (error) {
    restore([css, ...packages]);
    throw new Error(
      "Theme apply refused or failed. Restored the stylesheet and package manifests; review the remaining diff before retrying.",
      { cause: error },
    );
  } finally {
    restore(configs);
  }

  // Font dependency changes are intentional; only pnpm may reconcile the lockfile.
  run("pnpm", ["install"], root);
  run("pnpm", ["check-types"], root);
  console.log(
    "Theme applied. Review the diff, contrast, color ramps and PWA theme colors before shipping.",
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 1) throw new Error("Usage: pnpm theme:apply <preset-code>");
    validatePreset(args[0]);
    applyTheme(args[0]);
  } catch (error) {
    console.error(error);
    process.exitCode = 1;
  }
}
