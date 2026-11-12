import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  ensureGeneratedClient,
  SCHEMA_STAMP,
  schemaInputsHash,
  staleReason,
} from "./generate-client.mjs";

let dir;
let generateCalls;

function fakeGenerate(packageDir) {
  generateCalls += 1;
  mkdirSync(join(packageDir, "prisma", "generated"), { recursive: true });
  writeFileSync(join(packageDir, "prisma", "generated", "client.ts"), "export {};\n");
}

function ensure(options = {}) {
  return ensureGeneratedClient(dir, { generate: fakeGenerate, log: () => {}, ...options });
}

function setPrismaVersion(name, version) {
  mkdirSync(join(dir, "node_modules", name), { recursive: true });
  writeFileSync(join(dir, "node_modules", name, "package.json"), JSON.stringify({ version }));
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "wssp-db-generate-"));
  generateCalls = 0;
  mkdirSync(join(dir, "prisma", "schema"), { recursive: true });
  writeFileSync(join(dir, "prisma", "schema", "schema.prisma"), "model A { id String @id }\n");
  writeFileSync(join(dir, "prisma.config.ts"), "export default {};\n");
  setPrismaVersion("prisma", "7.9.1");
  setPrismaVersion("@prisma/client", "7.9.1");
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("ensureGeneratedClient", () => {
  it("generates when there is no client, then skips while the inputs are unchanged", () => {
    expect(staleReason(dir)).toBe("no generated client");
    expect(ensure()).toEqual({ generated: true, reason: "no generated client" });
    expect(staleReason(dir)).toBeNull();
    expect(ensure()).toEqual({ generated: false, reason: null });
    expect(generateCalls).toBe(1);
  });

  it("regenerates a client that predates the stamp", () => {
    fakeGenerate(dir);
    expect(ensure().reason).toBe("generated client has no schema stamp");
    expect(generateCalls).toBe(2);
  });

  it.each([
    [
      "an edited schema file",
      () =>
        writeFileSync(
          join(dir, "prisma", "schema", "schema.prisma"),
          "model A { id String @id\n quiescingSince DateTime? }\n",
        ),
    ],
    [
      "a new schema file",
      () =>
        writeFileSync(join(dir, "prisma", "schema", "extra.prisma"), "model B { id String @id }\n"),
    ],
    [
      "an edited prisma.config.ts",
      () => writeFileSync(join(dir, "prisma.config.ts"), "export default { x: 1 };\n"),
    ],
    ["a Prisma CLI upgrade", () => setPrismaVersion("prisma", "7.10.0")],
    ["a Prisma client upgrade", () => setPrismaVersion("@prisma/client", "7.10.0")],
  ])("regenerates after %s", (_label, change) => {
    ensure();
    change();
    expect(staleReason(dir)).toMatch(/changed since the last generate/);
    expect(ensure().generated).toBe(true);
    expect(generateCalls).toBe(2);
    expect(staleReason(dir)).toBeNull();
  });

  it("hashes file names, not only contents", () => {
    const before = schemaInputsHash(dir);
    rmSync(join(dir, "prisma", "schema", "schema.prisma"));
    writeFileSync(join(dir, "prisma", "schema", "renamed.prisma"), "model A { id String @id }\n");
    expect(schemaInputsHash(dir)).not.toBe(before);
  });

  it("never leaves a fresh-looking stamp behind a failed generate", () => {
    ensure();
    writeFileSync(join(dir, "prisma", "schema", "schema.prisma"), "model A { id Int @id }\n");
    expect(() =>
      ensure({
        generate: () => {
          throw new Error("prisma generate exited with 1");
        },
      }),
    ).toThrow("exited with 1");
    expect(staleReason(dir)).toBe("generated client has no schema stamp");
  });

  it("regenerates when forced, even if fresh", () => {
    ensure();
    expect(ensure({ force: true })).toEqual({ generated: true, reason: "forced" });
    expect(generateCalls).toBe(2);
  });

  it("writes the stamp inside the generated directory", () => {
    ensure();
    expect(staleReason(dir)).toBeNull();
    rmSync(join(dir, "prisma", "generated", SCHEMA_STAMP));
    expect(staleReason(dir)).toBe("generated client has no schema stamp");
  });
});
