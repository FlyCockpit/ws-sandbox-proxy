import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, expectTypeOf, it } from "vitest";
import { canonicalDigestHex, canonicalJson, definitionDigestHex } from "./canonical-json";
import {
  type LoginDefinitionInput,
  loadVerifiedDefinition,
  parseLoginDefinition,
  parseLoginDefinitionText,
} from "./definition";
import { buildLoginDefinitionJsonSchema } from "./json-schema";
import { LOGIN_DEFINITION_LIMITS as L } from "./limits";

const minimal = () => ({
  schemaVersion: 1,
  id: "tool",
  displayName: "Tool",
  login: { command: "tool login", method: "device-code" },
  credentials: { files: { required: [".tool/auth.json"] } },
});

describe("parseLoginDefinition", () => {
  it("fills defaults without touching the stored document", () => {
    const document = minimal();
    const result = parseLoginDefinition(document);
    expect(result.success).toBe(true);
    if (!result.success) return;
    expect(result.definition.login.doneWhenCommandExits).toBe(true);
    expect(result.definition.credentials).toMatchObject({
      sharing: "exclusive",
      rotates: "unknown",
      maxBytes: 1_048_576,
      files: { required: [".tool/auth.json"], optional: [], exclude: [] },
    });
    expect(document).toEqual(minimal());
  });

  it("keeps x-* extensions at every level", () => {
    const result = parseLoginDefinition({
      ...minimal(),
      "x-a": 1,
      login: { ...minimal().login, "x-b": { any: ["thing"] } },
    });
    expect(result.success && result.definition["x-a"]).toBe(1);
    expect(result.success && result.definition.login["x-b"]).toEqual({ any: ["thing"] });
  });

  it("flags browser-callback as unsupported but accepts it", () => {
    const result = parseLoginDefinition({
      ...minimal(),
      login: { command: "x", method: "browser-callback" },
    });
    expect(result.success && result.warnings).toEqual([
      "login.method.browser_callback_unsupported",
    ]);
  });

  it("returns the typed refusal for a newer schema version", () => {
    const result = parseLoginDefinition({ ...minimal(), schemaVersion: 2 });
    expect(!result.success && result.error.code).toBe("definition.schema_version_unsupported");
  });

  it("reports the failing path", () => {
    const result = parseLoginDefinition({
      ...minimal(),
      credentials: { files: { required: ["../escape"] } },
    });
    expect(!result.success && result.error.issues.map((i) => i.path)).toEqual([
      "credentials.files.required.0",
    ]);
  });
});

describe("own __proto__ keys", () => {
  const dir = new URL("../vectors/invalid/", import.meta.url);
  const names = readdirSync(dir).filter((n) => n.startsWith("proto-key-"));

  it("are refused by name, at the level they appear", () => {
    const document = JSON.parse(
      '{"schemaVersion":1,"id":"t","displayName":"T","login":{"command":"x","method":"paste","__proto__":{"probe":true}},"credentials":{"env":[{"name":"A","required":true}]}}',
    );
    const result = parseLoginDefinition(document);
    expect(!result.success && result.error.issues.map((i) => i.path)).toEqual(["login.__proto__"]);
  });

  it("vectors cover every object level and are valid without the key", () => {
    expect(names.length).toBe(8);
    const strip = (node: unknown): unknown => {
      if (Array.isArray(node)) return node.map(strip);
      if (typeof node !== "object" || node === null) return node;
      return Object.fromEntries(
        Object.entries(node)
          .filter(([key]) => key !== "__proto__")
          .map(([key, value]) => [key, strip(value)]),
      );
    };
    for (const name of names) {
      const vector = JSON.parse(readFileSync(new URL(name, dir), "utf8"));
      expect(parseLoginDefinition(strip(vector.document)).success, name).toBe(true);
    }
  });

  it("keep the schema input type", () => {
    expectTypeOf<LoginDefinitionInput>().not.toBeUnknown();
    expectTypeOf<LoginDefinitionInput["login"]["command"]>().toEqualTypeOf<string>();
  });
});

describe("document bounds fail fast", () => {
  const tooLarge = { path: "", message: `canonical JSON exceeds ${L.documentMaxBytes} bytes` };

  it("stops canonicalizing at the byte budget", () => {
    // 50 000 strings of 10 bytes pass the cheap container bound (2n + 1 bytes)
    // but need ~650 KB. The last element is a getter: reaching it would mean
    // the walk did not stop at the budget.
    const probe: unknown[] = Array.from({ length: 50_000 }, () => "0123456789");
    let reached = false;
    Object.defineProperty(probe, probe.length - 1, {
      enumerable: true,
      get: () => {
        reached = true;
        return 1.5;
      },
    });
    const result = parseLoginDefinition({ ...minimal(), "x-probe": probe });
    expect(!result.success && result.error.issues[0]).toEqual(tooLarge);
    expect(reached).toBe(false);
  });

  it("refuses containers and strings that cannot fit before walking them", () => {
    for (const probe of ["p".repeat(64 << 20), new Array(1 << 20).fill(0), new Array(2 ** 31)]) {
      const result = parseLoginDefinition({ ...minimal(), "x-probe": probe });
      expect(!result.success && result.error.issues[0]).toEqual(tooLarge);
    }
    expect(() => canonicalJson({ a: "p".repeat(L.documentMaxBytes) })).toThrow(tooLarge.message);
  });

  it("bounds raw text in UTF-8 bytes before JSON.parse", () => {
    const message = `definition text exceeds ${L.documentTextMaxBytes} bytes`;
    // Not JSON at all: refused for its size, so the parser never ran.
    const garbage = parseLoginDefinitionText(`{${" ".repeat(L.documentTextMaxBytes)}`);
    expect(!garbage.success && garbage.error.issues[0]?.message).toBe(message);
    const wide = parseLoginDefinitionText("€".repeat(Math.floor(L.documentTextMaxBytes / 3) + 1));
    expect(!wide.success && wide.error.issues[0]?.message).toBe(message);
  });

  it("returns the canonical bytes the digest is computed from", async () => {
    const result = parseLoginDefinitionText(JSON.stringify(minimal()));
    expect(result.success).toBe(true);
    if (!result.success) return;
    expect(result.document).toEqual(minimal());
    expect(await canonicalDigestHex(result.canonical)).toBe(await definitionDigestHex(minimal()));
  });
});

describe("loadVerifiedDefinition", () => {
  it("loads a document whose digest matches", async () => {
    const document = minimal();
    const result = await loadVerifiedDefinition(document, await definitionDigestHex(document));
    expect(result.success).toBe(true);
  });

  it("refuses a document that no longer matches its pinned digest", async () => {
    const pinned = await definitionDigestHex(minimal());
    const tampered = { ...minimal(), credentials: { files: { required: [".ssh/id_ed25519"] } } };
    const result = await loadVerifiedDefinition(tampered, pinned);
    expect(!result.success && result.error.code).toBe("credential.definition_corrupt");
  });

  it("is sensitive to x-* extensions (they are part of the document)", async () => {
    const pinned = await definitionDigestHex(minimal());
    const result = await loadVerifiedDefinition({ ...minimal(), "x-note": "changed" }, pinned);
    expect(!result.success && result.error.code).toBe("credential.definition_corrupt");
  });
});

describe("JSON Schema", () => {
  it("closes every object to known keys plus x-*", () => {
    const schema = buildLoginDefinitionJsonSchema() as {
      additionalProperties: unknown;
      patternProperties: unknown;
      properties: Record<string, { additionalProperties?: unknown }>;
    };
    expect(schema.additionalProperties).toBe(false);
    expect(schema.patternProperties).toEqual({ "^x-.": {} });
    expect(schema.properties.login?.additionalProperties).toBe(false);
    expect(schema.properties.credentials?.additionalProperties).toBe(false);
  });
});
