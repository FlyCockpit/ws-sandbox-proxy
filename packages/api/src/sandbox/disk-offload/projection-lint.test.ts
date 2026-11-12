import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Disk offload keys are write-only ( "Admin disclosure: none",
 * I7): the wrap columns are selected and written only in
 * `disk-offload/keys.ts`. This scans every server-side TS source (tests
 * excluded) and fails on:
 *
 * - `wrapSalt` / `wrapNonce` anywhere but keys.ts and the credential vault
 *   (which owns same-named columns and has its own lint);
 * - `wrappedKey` / `wrappedKeyNonce` in any file that names a disk offload
 *   (template image code keeps its own `wrappedKey` columns);
 * - a write of `shreddedAt`: `shredOffloadKeys` is its only writer.
 */

const ROOT = join(import.meta.dirname, "../../../../..");
const KEYS = "packages/api/src/sandbox/disk-offload/keys.ts";
const VAULT = "packages/api/src/credentials/vault/";
const SCANNED = ["packages/api/src", "apps/server/src", "apps/worker/src", "packages/db/src"];

const SALT_OR_NONCE = /\b(wrapSalt|wrapNonce)\b/;
const WRAPPED = /\b(wrappedKey|wrappedKeyNonce)\b/;
const NAMES_DISK = /sandboxDiskOffload|sandbox_disk_offload|diskOffloadId|DiskOffload\b/;
const SHRED_WRITE = [/"shreddedAt"\s*=\s/, /\bshreddedAt\s*:\s*(new Date|null\b|\$\{)/];

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    if (name === "node_modules" || name === "dist" || name === "generated") continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) out.push(...walk(path));
    else if (name.endsWith(".ts") && !name.endsWith(".test.ts") && !name.endsWith(".d.ts"))
      out.push(path);
  }
  return out;
}

const isComment = (line: string) => /^\s*(\/\/|\*|\/\*)/.test(line);

function hitsIn(file: string, source: string): string[] {
  const namesDisk = NAMES_DISK.test(source);
  const inVault = file.startsWith(VAULT);
  return source.split("\n").flatMap((line, index) => {
    if (isComment(line)) return [];
    const hit =
      (!inVault && SALT_OR_NONCE.test(line)) ||
      (namesDisk && WRAPPED.test(line)) ||
      SHRED_WRITE.some((pattern) => pattern.test(line));
    return hit ? [`${file}:${index + 1}: ${line.trim()}`] : [];
  });
}

describe("disk offload key projection lint (§3, I7)", () => {
  it("touches disk wrap columns and shreddedAt writes only inside disk-offload/keys.ts", () => {
    const hits = SCANNED.flatMap((dir) =>
      walk(join(ROOT, dir)).flatMap((path) => {
        const file = relative(ROOT, path);
        return file === KEYS ? [] : hitsIn(file, readFileSync(path, "utf8"));
      }),
    );
    expect(hits).toEqual([]);
  });

  it("finds keys.ts's own uses (the scan is live)", () => {
    const keys = readFileSync(join(ROOT, KEYS), "utf8");
    expect(hitsIn("x.ts", keys).length).toBeGreaterThan(0);
  });

  it("matches selections and writes, not comments or template-only files (self-check)", () => {
    expect(hitsIn("x.ts", "  select: { wrapSalt: true },")).not.toEqual([]);
    expect(hitsIn("x.ts", "// the wrapNonce column")).toEqual([]);
    expect(
      hitsIn("x.ts", "tx.sandboxDiskOffload.findFirst();\n  select: { wrappedKey: true },"),
    ).not.toEqual([]);
    expect(hitsIn("x.ts", "  select: { wrappedKey: true, wrappedKeyNonce: true },")).toEqual([]);
    expect(hitsIn("x.ts", '  SET "shreddedAt" = now()')).not.toEqual([]);
    expect(hitsIn("x.ts", "  data: { shreddedAt: new Date() },")).not.toEqual([]);
    expect(hitsIn("x.ts", '  WHERE "shreddedAt" IS NULL')).toEqual([]);
    expect(hitsIn("x.ts", "  where: { shreddedAt: { lt: cutoff } },")).toEqual([]);
    expect(hitsIn(`${VAULT}store.ts`, "  select: { wrapSalt: true },")).toEqual([]);
  });
});
