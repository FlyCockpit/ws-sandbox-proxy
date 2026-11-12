import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Write-only vault, projection half:
 * the encrypted columns of `CredentialSecretVersion` and `CredentialReturnKey`
 * are read and written only inside `packages/api/src/credentials/vault/`.
 * Everything else goes through the vault's functions, so no other module can
 * select a ciphertext or wrapped key into a DTO, log, outbox row or webhook.
 * This scans every server-side TS source (tests excluded) for the column
 * names and fails on a hit outside the vault directory. The webhook secret
 * columns (`secretCiphertext`, …) are a different store and not matched.
 */

const ROOT = join(import.meta.dirname, "../../../../..");
const VAULT = "packages/api/src/credentials/vault/";
/**
 * Disk offload wraps share the `wrapSalt`/`wrapNonce` column names; their one
 * owner is governed by its own lint (sandbox/disk-offload/projection-lint.test.ts).
 */
const DISK_KEYS = "packages/api/src/sandbox/disk-offload/keys.ts";
const SCANNED = ["packages/api/src", "apps/server/src", "apps/worker/src", "packages/db/src"];

/** Vault-owned columns; `ciphertext` only in a Prisma select/data or SQL column position. */
const COLUMN_PATTERNS = [
  /\b(wrappedDek|wrapSalt|wrapNonce|wrappedPrivate|rwrapSalt)\b/,
  /(?<![A-Za-z])ciphertext\s*:\s*true\b/,
  /"ciphertext"/,
];

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

function hitsIn(file: string, source: string): string[] {
  return source
    .split("\n")
    .flatMap((line, index) =>
      !/^\s*(\/\/|\*|\/\*)/.test(line) && COLUMN_PATTERNS.some((p) => p.test(line))
        ? [`${file}:${index + 1}: ${line.trim()}`]
        : [],
    );
}

describe("credential vault projection lint (§1, §4.7)", () => {
  it("touches the vault's encrypted columns only inside credentials/vault/", () => {
    const hits = SCANNED.flatMap((dir) =>
      walk(join(ROOT, dir)).flatMap((path) => {
        const file = relative(ROOT, path);
        return file.startsWith(VAULT) || file === DISK_KEYS
          ? []
          : hitsIn(file, readFileSync(path, "utf8"));
      }),
    );
    expect(hits).toEqual([]);
  });

  it("finds the vault's own uses (the scan is live)", () => {
    const store = readFileSync(join(ROOT, VAULT, "store.ts"), "utf8");
    expect(hitsIn(`${VAULT}store.ts`, store).length).toBeGreaterThan(0);
  });

  it("matches a selection and not a comment or the webhook columns (self-check)", () => {
    expect(hitsIn("x.ts", "  select: { ciphertext: true, nonce: true },")).not.toEqual([]);
    expect(hitsIn("x.ts", "  select: { wrappedDek: true },")).not.toEqual([]);
    expect(hitsIn("x.ts", 'SELECT "wrappedPrivate" FROM credential_return_key')).not.toEqual([]);
    expect(hitsIn("x.ts", "// the wrappedDek column")).toEqual([]);
    expect(hitsIn("x.ts", "  select: { secretCiphertext: true },")).toEqual([]);
  });
});
