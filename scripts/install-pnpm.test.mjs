import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const installer = new URL("./install-pnpm.mjs", import.meta.url).href;

function runInstaller(root, packageManager, tarball = Buffer.alloc(0)) {
  const manifest = join(root, "package.json");
  writeFileSync(manifest, JSON.stringify({ packageManager }));
  return spawnSync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `
        globalThis.fetch = async () => ({
          ok: true,
          arrayBuffer: async () => Buffer.from(${JSON.stringify(tarball.toString("base64"))}, "base64"),
        });
        process.argv = [process.execPath, "install-pnpm.mjs", ${JSON.stringify(manifest)}, ${JSON.stringify(join(root, "bin"))}, ${JSON.stringify(join(root, "prefix"))}];
        await import(${JSON.stringify(installer)});
      `,
    ],
    { encoding: "utf8" },
  );
}

test("rejects a mismatched wrapper digest before replacing an installed pnpm", () => {
  const root = mkdtempSync(join(tmpdir(), "wssp-pnpm-integrity-"));
  try {
    const target = join(root, "prefix", "lib", "pnpm");
    mkdirSync(target, { recursive: true });
    writeFileSync(join(target, "pnpm"), "existing verified installation");
    const result = runInstaller(
      root,
      `pnpm@12.18.0+sha512.${"0".repeat(128)}`,
      Buffer.from("test wrapper"),
    );
    assert.equal(result.status, 1);
    assert.match(result.stderr, /SHA-512 mismatch/);
    assert.equal(readFileSync(join(target, "pnpm"), "utf8"), "existing verified installation");
    assert.equal(existsSync(join(root, "bin", "pnpm")), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("rejects a verified tarball that has no bin/pnpm.mjs without creating a pnpm link", () => {
  const root = mkdtempSync(join(tmpdir(), "wssp-pnpm-layout-"));
  try {
    const contents = join(root, "contents");
    mkdirSync(join(contents, "package"), { recursive: true });
    writeFileSync(
      join(contents, "package", "package.json"),
      JSON.stringify({ version: "12.18.0" }),
    );
    const archive = join(root, "pnpm.tgz");
    execFileSync("tar", ["-czf", archive, "-C", contents, "package/package.json"]);
    const tarball = readFileSync(archive);
    const expected = createHash("sha512").update(tarball).digest("hex");
    const result = runInstaller(root, `pnpm@12.18.0+sha512.${expected}`, tarball);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /has no bin\/pnpm\.mjs/);
    assert.equal(existsSync(join(root, "bin", "pnpm")), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("rejects packageManager values outside pnpm@x.y.z+sha512.<128 hex> form", () => {
  const root = mkdtempSync(join(tmpdir(), "wssp-pnpm-manifest-"));
  try {
    for (const packageManager of [
      undefined,
      "pnpm@12.18.0",
      `npm@12.18.0+sha512.${"0".repeat(128)}`,
      `pnpm@12.18+sha512.${"0".repeat(128)}`,
      `pnpm@12.18.0+sha256.${"0".repeat(128)}`,
      `pnpm@12.18.0+sha512.${"0".repeat(127)}`,
      `pnpm@12.18.0+sha512.${"0".repeat(129)}`,
      `pnpm@12.18.0+sha512.${"g".repeat(128)}`,
    ]) {
      const result = runInstaller(root, packageManager);
      assert.equal(result.status, 1, String(packageManager));
      assert.match(result.stderr, /packageManager must be/);
      assert.equal(existsSync(join(root, "bin", "pnpm")), false);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("rejects an unreviewed native tarball before executing it or linking pnpm", () => {
  const root = mkdtempSync(join(tmpdir(), "wssp-pnpm-native-"));
  try {
    const contents = join(root, "contents");
    mkdirSync(join(contents, "package", "bin"), { recursive: true });
    writeFileSync(
      join(contents, "package", "bin", "pnpm.mjs"),
      "throw new Error('must not execute');",
    );
    const archive = join(root, "pnpm.tgz");
    execFileSync("tar", ["-czf", archive, "-C", contents, "package"]);
    const tarball = readFileSync(archive);
    const expected = createHash("sha512").update(tarball).digest("hex");
    const result = runInstaller(root, `pnpm@12.18.0+sha512.${expected}`, tarball);
    assert.equal(result.status, 1);
    const reviewedHost =
      process.platform === "linux" &&
      ["x64", "arm64"].includes(process.arch) &&
      Boolean(process.report.getReport().header.glibcVersionRuntime);
    assert.match(
      result.stderr,
      reviewedHost ? /SHA-512 mismatch.*native package/ : /no reviewed native package pin/,
    );
    assert.doesNotMatch(result.stderr, /must not execute/);
    assert.equal(existsSync(join(root, "bin", "pnpm")), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
