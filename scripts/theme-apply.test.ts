import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { applyTheme, validatePreset } from "./theme-apply";

const stylesheet = '@import "./shadcn-tailwind.css";\n:root { --primary: blue; }\n';

function fixture() {
  const root = mkdtempSync(resolve(tmpdir(), "wssp-theme-test-"));
  const files = {
    "packages/ui/src/styles/globals.css": stylesheet,
    "apps/web/components.json": '{"style":"base-lyra"}',
    "packages/ui/components.json": '{"style":"base-lyra"}',
    "package.json": "{}",
    "apps/web/package.json": "{}",
    "packages/ui/package.json": "{}",
  };
  for (const [file, content] of Object.entries(files)) {
    const path = resolve(root, file);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content);
  }
  return { root, files, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}

test("applies only theme/font with an exact ephemeral pin and restores component config", () => {
  const f = fixture();
  const calls: string[][] = [];
  try {
    applyTheme("b2CPjyJD0", f.root, (command, args) => {
      calls.push([command, ...args]);
      if (args[0] !== "dlx") return;
      writeFileSync(
        resolve(f.root, "packages/ui/src/styles/globals.css"),
        stylesheet.replace("blue", "green"),
      );
      writeFileSync(resolve(f.root, "packages/ui/components.json"), "{}");
    });
    assert.deepEqual(calls, [
      [
        "pnpm",
        "dlx",
        "shadcn@4.18.0",
        "apply",
        "--preset",
        "b2CPjyJD0",
        "--only",
        "theme,font",
        "-c",
        "apps/web",
        "-y",
      ],
      ["pnpm", "install"],
      ["pnpm", "check-types"],
    ]);
    assert.equal(
      readFileSync(resolve(f.root, "packages/ui/components.json"), "utf8"),
      f.files["packages/ui/components.json"],
    );
    assert.match(
      readFileSync(resolve(f.root, "packages/ui/src/styles/globals.css"), "utf8"),
      /green/,
    );
  } finally {
    f.cleanup();
  }
});

for (const change of ["import", "dependency", "failure"] as const) {
  test(`rejects a CLI ${change} and restores protected files without proceeding`, () => {
    const f = fixture();
    const calls: string[][] = [];
    try {
      assert.throws(
        () =>
          applyTheme("b2CPjyJD0", f.root, (_command, args) => {
            calls.push(args);
            writeFileSync(resolve(f.root, "packages/ui/components.json"), "{}");
            if (change === "import") {
              writeFileSync(
                resolve(f.root, "packages/ui/src/styles/globals.css"),
                '@import "shadcn/tailwind.css";',
              );
            } else if (change === "dependency") {
              writeFileSync(
                resolve(f.root, "packages/ui/package.json"),
                '{"dependencies":{"shadcn":"4.18.0"}}',
              );
            } else {
              throw new Error("CLI failed");
            }
          }),
        /Restored the stylesheet and package manifests/,
      );
      assert.equal(calls.length, 1);
      for (const [file, content] of Object.entries(f.files)) {
        assert.equal(readFileSync(resolve(f.root, file), "utf8"), content);
      }
    } finally {
      f.cleanup();
    }
  });
}

test("rejects flags and malformed preset codes before invoking the CLI", () => {
  for (const preset of [undefined, "", "--only", "a/b", "a b"]) {
    assert.throws(() => validatePreset(preset), /base62/);
  }
});
