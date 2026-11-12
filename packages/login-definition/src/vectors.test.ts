import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  buildMaxBundle,
  generatedFiles,
  MAX_BUNDLE_RECIPE,
  maxBundleDefinition,
  PACKAGE_ROOT,
  validVectorNames,
} from "../scripts/generated";
import { BundleError, decodeBundle, encodeBundle, serializeBundleUnchecked } from "./bundle";
import { canonicalJson, definitionDigestHex } from "./canonical-json";
import { type LoginDefinition, parseLoginDefinition, parseLoginDefinitionText } from "./definition";
import { headerValueAcceptable } from "./net";
import { fromHex, toHex, utf8 } from "./text";

/**
 * Shared conformance vectors. `crates/login-definition/tests/vectors.rs`
 * consumes the same files; both suites must agree on every case.
 */
const read = (rel: string) => readFileSync(new URL(rel, PACKAGE_ROOT));
const readJson = <T>(rel: string): T => JSON.parse(read(rel).toString("utf8")) as T;
const listJson = (dir: string) =>
  readdirSync(new URL(dir, PACKAGE_ROOT))
    .filter((n) => n.endsWith(".json"))
    .sort();

function parsedOrThrow(document: unknown): LoginDefinition {
  const result = parseLoginDefinition(document);
  if (!result.success) throw new Error(JSON.stringify(result.error));
  return result.definition;
}

describe("generated artifacts", () => {
  it("match the committed bytes exactly (schema, digests, max inputs, bundles)", async () => {
    const files = await generatedFiles();
    expect(files.size).toBeGreaterThan(20);
    for (const [path, bytes] of files) {
      expect(Buffer.from(read(path)).equals(Buffer.from(bytes)), path).toBe(true);
    }
    const committedBins = readdirSync(new URL("vectors/bundles/", PACKAGE_ROOT)).map(
      (n) => `vectors/bundles/${n}`,
    );
    expect(committedBins.filter((p) => !files.has(p))).toEqual([]);
  });
});

describe("valid definitions and digests", () => {
  const digests =
    readJson<Record<string, { digest: string; canonical: string; warnings: string[] }>>(
      "vectors/digests.json",
    );

  it("covers every valid vector", () => {
    expect(Object.keys(digests).sort()).toEqual(validVectorNames());
  });

  for (const name of validVectorNames()) {
    it(`accepts ${name} with the pinned digest`, async () => {
      const document = readJson(`vectors/valid/${name}`);
      const result = parseLoginDefinition(document);
      expect(result.success).toBe(true);
      if (!result.success) return;
      expect(result.warnings).toEqual(digests[name]?.warnings);
      expect(canonicalJson(document)).toBe(digests[name]?.canonical);
      expect(await definitionDigestHex(document)).toBe(digests[name]?.digest);
    });
  }
});

describe("invalid definitions", () => {
  type Invalid = { description: string; expect: string; document?: unknown; documentText?: string };
  const names = listJson("vectors/invalid/");
  it("has a broad set", () => expect(names.length).toBeGreaterThan(100));
  for (const name of names) {
    it(`refuses ${name}`, () => {
      const vector = readJson<Invalid>(`vectors/invalid/${name}`);
      const result =
        vector.documentText !== undefined
          ? parseLoginDefinitionText(vector.documentText)
          : parseLoginDefinition(vector.document);
      expect(result.success, vector.description).toBe(false);
      if (!result.success) expect(result.error.code).toBe(vector.expect);
    });
  }
});

describe("canonical JSON", () => {
  const { cases } = readJson<{ cases: { name: string; text: string; canonical: string | null }[] }>(
    "vectors/canonical.json",
  );
  for (const c of cases) {
    it(c.name, () => {
      const value = JSON.parse(c.text);
      if (c.canonical === null) expect(() => canonicalJson(value)).toThrow();
      else expect(canonicalJson(value)).toBe(c.canonical);
    });
  }
});

describe("header values (R2-7)", () => {
  type HeaderCase = {
    name: string;
    format: string;
    value?: string;
    valueHex?: string;
    valueRepeat?: { byte: number; count: number };
    ok: boolean;
  };
  const { cases } = readJson<{ cases: HeaderCase[] }>("vectors/headers/cases.json");
  for (const c of cases) {
    it(c.name, () => {
      const value =
        c.value !== undefined
          ? utf8(c.value)
          : c.valueHex !== undefined
            ? fromHex(c.valueHex)
            : new Uint8Array(c.valueRepeat?.count ?? 0).fill(c.valueRepeat?.byte ?? 0);
      expect(headerValueAcceptable(c.format, value)).toBe(c.ok);
    });
  }
});

describe("max-input definitions (R3-5)", () => {
  type MaxCase = {
    name: string;
    ok: boolean;
    document: unknown;
    textPadding?: number;
    firstIssue?: { path: string; message: string };
  };
  const { cases } = readJson<{ cases: MaxCase[] }>("vectors/max-inputs/definitions.json");
  for (const c of cases) {
    it(c.name, () => {
      const result =
        c.textPadding === undefined
          ? parseLoginDefinition(c.document)
          : parseLoginDefinitionText(canonicalJson(c.document) + " ".repeat(c.textPadding));
      expect(result.success, JSON.stringify(result.success ? [] : result.error.issues)).toBe(c.ok);
      if (!result.success) {
        expect(result.error.code).toBe("definition.invalid");
        if (c.firstIssue) expect(result.error.issues[0]).toEqual(c.firstIssue);
      }
    });
  }
});

describe("bundle vectors", () => {
  type Case = {
    file: string;
    definition: string;
    expect: string;
    decoded?: {
      files: { kind: string; path: string; mode: number; dataHex?: string }[];
      env: { name: string; valueHex: string }[];
    };
  };
  const { cases } = readJson<{ cases: Case[] }>("vectors/bundles/cases.json");
  for (const c of cases) {
    it(c.file, async () => {
      const document = readJson(`vectors/valid/${c.definition}`);
      const definition = parsedOrThrow(document);
      const digest = fromHex(await definitionDigestHex(document));
      const bytes = new Uint8Array(read(`vectors/bundles/${c.file}`));
      if (c.expect !== "ok") {
        expect(() => decodeBundle(bytes, definition, digest)).toThrow(
          expect.objectContaining({ reason: c.expect }),
        );
        return;
      }
      const bundle = decodeBundle(bytes, definition, digest);
      expect({
        files: bundle.files.map((f) =>
          f.kind === "file"
            ? { kind: f.kind, path: f.path, mode: f.mode, dataHex: toHex(f.data) }
            : { kind: f.kind, path: f.path, mode: f.mode },
        ),
        env: bundle.env.map((e) => ({ name: e.name, valueHex: toHex(e.value) })),
      }).toEqual(c.decoded);
      expect(toHex(encodeBundle(bundle, definition))).toBe(toHex(bytes));
    });
  }
});

describe("exact-maximum bundle (R2-9)", () => {
  const recipe = readJson<
    typeof MAX_BUNDLE_RECIPE & { definition: unknown; definitionDigest: string }
  >("vectors/max-inputs/bundle.json");
  const definition = parsedOrThrow(recipe.definition);
  const digest = fromHex(recipe.definitionDigest);

  it("pins 628 825 + maxBytes = 4 823 129 bytes", async () => {
    expect(recipe.definition).toEqual(maxBundleDefinition());
    expect(await definitionDigestHex(recipe.definition)).toBe(recipe.definitionDigest);
    expect(recipe.expectedBytes).toBe(4_823_129);
    const bytes = encodeBundle(buildMaxBundle(digest, null), definition);
    expect(bytes.length).toBe(recipe.expectedBytes);
    const decoded = decodeBundle(bytes, definition, digest);
    expect(decoded.files.length).toBe(recipe.fileCount);
    expect(decoded.env.length).toBe(recipe.envCount);
  });

  for (const variant of recipe.variants) {
    it(`refuses ${variant.name}`, () => {
      const bytes = serializeBundleUnchecked(buildMaxBundle(digest, variant.name));
      let caught: unknown;
      try {
        decodeBundle(bytes, definition, digest);
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(BundleError);
      expect((caught as BundleError).reason).toBe(variant.expect);
    });
  }
});
