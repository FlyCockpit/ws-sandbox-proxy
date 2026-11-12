import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * sweep S9 (login-grant writers), with a real regex
 * alternation (V4): every non-test source under packages/api/src that grants
 * a login to a sandbox — a binding insert, a path-history append or a proxy
 * enable — also sets `Sandbox.credentialFilesEver` through
 * `markCredentialFilesEver` (§4 safeguard 2: own-host-only resume).
 */
const ROOT = join(import.meta.dirname, "../../../..");
const SCANNED = "packages/api/src";
const WRITER =
  /recordCredentialPathHistory\(|credentialBinding\.create\(|credentialProxyEnabled: true/;
/** Reads and the helper's own definition are not writers. */
const NOT_A_WRITE = /select:|export async function recordCredentialPathHistory/;
const MARK = /markCredentialFilesEver\(tx/;

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    if (name === "node_modules" || name === "testing") continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...walk(path));
    else if (name.endsWith(".ts") && !name.endsWith(".test.ts")) out.push(path);
  }
  return out;
}

function writerLines(source: string): string[] {
  return source
    .split("\n")
    .filter((line) => !/^\s*(\/\/|\*|\/\*)/.test(line))
    .filter((line) => WRITER.test(line) && !NOT_A_WRITE.test(line));
}

describe("credentialFilesEver is set by every login grant writer (S9)", () => {
  const files = walk(join(ROOT, SCANNED)).flatMap((path) => {
    const source = readFileSync(path, "utf8");
    const lines = writerLines(source);
    return lines.length > 0 ? [{ file: relative(ROOT, path), source, lines }] : [];
  });

  it("finds the known writers (the sweep is live)", () => {
    expect(files.map((f) => f.file).sort()).toEqual([
      "packages/api/src/credentials/grants.ts",
      "packages/api/src/credentials/launch.ts",
      "packages/api/src/credentials/login-relay.ts",
      "packages/api/src/credentials/resume.ts",
    ]);
  });

  it("every writer file sets the flag in its grant transaction", () => {
    expect(files.filter((f) => !MARK.test(f.source)).map((f) => f.file)).toEqual([]);
  });

  it("matches each alternative, and not reads (self-check)", () => {
    expect(writerLines("  await recordCredentialPathHistory(tx, id, paths);")).toHaveLength(1);
    expect(writerLines("  const b = await tx.credentialBinding.create({")).toHaveLength(1);
    expect(writerLines("      data: { credentialProxyEnabled: true },")).toHaveLength(1);
    expect(writerLines("      select: { credentialProxyEnabled: true },")).toHaveLength(0);
    expect(writerLines("// recordCredentialPathHistory(tx)")).toHaveLength(0);
  });
});
