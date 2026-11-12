#!/usr/bin/env node
// Install the pnpm pinned by package.json `packageManager` into a Docker image.
//
// Node 25+ no longer bundles corepack, and `npm install -g pnpm@<x>` trusts
// whatever the registry serves with no pinned checksum. This script instead:
//
//   1. reads `pnpm@<version>+sha512.<hex>` from package.json `packageManager`;
//   2. downloads exactly that registry tarball and refuses it unless its SHA-512
//      matches the pinned digest (the same digest Corepack checks locally);
//   3. unpacks it under <prefix>/lib/pnpm;
//   4. verifies the native package tarball against the reviewed platform pin,
//      then uses the verified wrapper's downloader with npm signature checks;
//      compares the downloaded executable with the pinned tarball before running;
//   5. links `pnpm` in <bin-dir> to that native binary and checks the version.
//
// pnpm 12 tarball layout (verified on 12.18.0): bin/pnpm.mjs + bin/pnpx.mjs
// (Corepack entries), a `pnpm` sh placeholder, native-binary.mjs, and dist/
// (bundled node-gyp + the get-pnpm downloader). There is no bin/pnpm.cjs.
//
// Usage: node install-pnpm.mjs <package.json> [bin-dir=/usr/local/bin] [prefix=/usr/local]
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const [manifestPath, binDir = "/usr/local/bin", prefix = "/usr/local"] = process.argv.slice(2);
if (!manifestPath) {
  console.error("usage: install-pnpm.mjs <package.json> [bin-dir] [prefix]");
  process.exit(2);
}

function fail(message) {
  console.error(`install-pnpm: ${message}`);
  process.exit(1);
}

const { packageManager } = JSON.parse(readFileSync(manifestPath, "utf8"));
const match = /^pnpm@(\d+\.\d+\.\d+)\+sha512\.([0-9a-f]{128})$/.exec(packageManager ?? "");
if (!match) {
  fail(`packageManager must be pnpm@<x.y.z>+sha512.<hex>, got ${packageManager}`);
}
const [, version, expected] = match;

const url = `https://registry.npmjs.org/pnpm/-/pnpm-${version}.tgz`;
const response = await fetch(url, { signal: AbortSignal.timeout(120_000) });
if (!response.ok) {
  fail(`${url} returned HTTP ${response.status}`);
}
const tarball = Buffer.from(await response.arrayBuffer());
const actual = createHash("sha512").update(tarball).digest("hex");
if (actual !== expected) {
  fail(`SHA-512 mismatch for pnpm ${version}; refusing to install`);
}

const target = join(prefix, "lib", "pnpm");
const work = mkdtempSync(join(tmpdir(), "pnpm-"));
try {
  const archive = join(work, "pnpm.tgz");
  writeFileSync(archive, tarball);
  rmSync(target, { recursive: true, force: true });
  mkdirSync(target, { recursive: true });
  execFileSync("tar", ["-xzf", archive, "-C", target, "--strip-components=1", "--no-same-owner"], {
    stdio: "inherit",
  });
} finally {
  rmSync(work, { recursive: true, force: true });
}

const wrapper = join(target, "bin", "pnpm.mjs");
if (!existsSync(wrapper)) {
  fail(`pnpm ${version} has no bin/pnpm.mjs; the tarball layout changed — update this script`);
}

// Reviewed npm tarball hashes, independently verified from the registry.
// Bump these together with packageManager; unsupported versions/platforms fail closed.
const nativePins = {
  "12.18.0": {
    "linux-x64":
      "sha512-OJ+X2wcraldCwj75pCIerWARQSRpdfj0eBTs/2ODyhfeW46ylOnjTIE/GKra6Mn6E72/gBmXS8igrUioa+F9fQ==",
    "linux-arm64":
      "sha512-2dpyVBCHT+FfpuQh9i+7MXAqNWYLCvD5vYr5p6Eimxoga8USLnjbUgyj72AOrO0hjc5ri3TEFP3jiyBHjkSZpQ==",
  },
};
const platform = `${process.platform}-${process.arch}`;
const nativePin = nativePins[version]?.[platform];
if (!nativePin || !process.report.getReport().header.glibcVersionRuntime) {
  fail(`no reviewed native package pin for pnpm ${version} on ${platform}`);
}
const nativeUrl = `https://registry.npmjs.org/@pnpm/exe.${platform}/-/exe.${platform}-${version}.tgz`;
const nativeResponse = await fetch(nativeUrl, { signal: AbortSignal.timeout(120_000) });
if (!nativeResponse.ok) fail(`native package returned HTTP ${nativeResponse.status}`);
const nativeTarball = Buffer.from(await nativeResponse.arrayBuffer());
if (`sha512-${createHash("sha512").update(nativeTarball).digest("base64")}` !== nativePin) {
  fail(`SHA-512 mismatch for the pnpm ${version} native package; refusing to install`);
}
let expectedBinary;
const nativeWork = mkdtempSync(join(tmpdir(), "pnpm-native-"));
try {
  const archive = join(nativeWork, "native.tgz");
  writeFileSync(archive, nativeTarball);
  const binary = execFileSync("tar", ["-xOf", archive, "package/pnpm"], {
    maxBuffer: 256 * 1024 * 1024,
  });
  expectedBinary = createHash("sha512").update(binary).digest("hex");
} finally {
  rmSync(nativeWork, { recursive: true, force: true });
}

// Use the signature-verifying downloader from the already pinned wrapper;
// do not execute its result until it also matches the reviewed native bytes.
const env = { ...process.env };
for (const name of Object.keys(env)) {
  if (name.startsWith("COREPACK_")) delete env[name];
}
const native = join(target, "pnpm-native");
execFileSync(
  process.execPath,
  [
    "--input-type=module",
    "-e",
    `
  import { pathToFileURL } from "node:url";
  import { join } from "node:path";
  const [target, version, destPath] = process.argv.slice(1);
  const downloader = await import(pathToFileURL(join(target, "dist/node_modules/get-pnpm/lib/index.js")));
  await downloader.downloadPnpmExecutable({ version, destPath, ...downloader.corepackDownloadOptions() });
`,
    target,
    version,
    native,
  ],
  { cwd: target, env, stdio: "inherit" },
);
if (!lstatSync(native, { throwIfNoEntry: false })?.isFile()) {
  fail(`the native binary was not placed at ${native}`);
}
if (createHash("sha512").update(readFileSync(native)).digest("hex") !== expectedBinary) {
  fail(`the signature-verified pnpm binary differs from the reviewed native package`);
}
const reported = execFileSync(native, ["--version"], {
  cwd: target,
  env,
  encoding: "utf8",
}).trim();
if (reported !== version) fail(`expected pnpm ${version}, the binary reported ${reported}`);

mkdirSync(binDir, { recursive: true });
const link = join(binDir, "pnpm");
rmSync(link, { force: true });
symlinkSync(native, link);

const linked = execFileSync(link, ["--version"], { encoding: "utf8" }).trim();
if (linked !== version) {
  fail(`${link} reports ${linked}, expected ${version}`);
}
console.log(
  `install-pnpm: pnpm ${version} installed (wrapper/native sha512 + npm signature verified)`,
);
