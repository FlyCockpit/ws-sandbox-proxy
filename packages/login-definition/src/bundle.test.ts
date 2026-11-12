import { describe, expect, it } from "vitest";
import {
  type Bundle,
  BundleError,
  decodeBundle,
  encodeBundle,
  missingRequiredPaths,
  serializeBundleUnchecked,
} from "./bundle";
import { type LoginDefinition, parseLoginDefinition } from "./definition";
import { utf8 } from "./text";

const definition = (() => {
  const result = parseLoginDefinition({
    schemaVersion: 1,
    id: "tool",
    displayName: "Tool",
    login: { command: "tool login", method: "paste" },
    credentials: {
      files: { required: [".tool/auth.json"], optional: [".tool/extra"] },
      env: [
        { name: "B_TOKEN", required: false },
        { name: "A_TOKEN", required: true },
      ],
      maxBytes: 64,
    },
  });
  if (!result.success) throw new Error("fixture invalid");
  return result.definition as LoginDefinition;
})();
const digest = new Uint8Array(32).fill(7);
const SECRET = "s3cr3t-value";

const bundle = (): Bundle => ({
  definitionDigest: digest,
  files: [
    { kind: "file", path: ".tool/extra/b", mode: 0o755, data: utf8("b") },
    { kind: "dir", path: ".tool/extra", mode: 0o750 },
    { kind: "file", path: ".tool/auth.json", mode: 0o640, data: utf8(SECRET) },
  ],
  env: [
    { name: "B_TOKEN", value: utf8("b") },
    { name: "A_TOKEN", value: utf8(SECRET) },
  ],
});

describe("bundle v1", () => {
  it("encodes canonically: sorted entries, normalized modes, exact sizes", () => {
    const bytes = encodeBundle(bundle(), definition);
    const decoded = decodeBundle(bytes, definition, digest);
    expect(decoded.files.map((f) => [f.path, f.mode.toString(8)])).toEqual([
      [".tool/auth.json", "600"],
      [".tool/extra", "700"],
      [".tool/extra/b", "700"],
    ]);
    expect(decoded.env.map((e) => e.name)).toEqual(["A_TOKEN", "B_TOKEN"]);
    const expected =
      41 +
      (9 + 15 + SECRET.length) +
      (9 + 11) +
      (9 + 13 + 1) +
      (3 + 7 + SECRET.length) +
      (3 + 7 + 1);
    expect(bytes.length).toBe(expected);
    const shuffled = { ...bundle(), files: [...bundle().files].reverse() };
    expect(encodeBundle(shuffled, definition)).toEqual(bytes);
  });

  it("uses big-endian integers and the WSCB magic", () => {
    const bytes = encodeBundle(bundle(), definition);
    expect(new TextDecoder().decode(bytes.subarray(0, 4))).toBe("WSCB");
    expect(bytes[4]).toBe(1);
    expect([bytes[37], bytes[38], bytes[39], bytes[40]]).toEqual([0, 3, 0, 2]);
  });

  it("refuses an encoding the decoder would refuse", () => {
    const over = { ...bundle(), env: [{ name: "C_TOKEN", value: utf8("x") }] };
    expect(() => encodeBundle(over, definition)).toThrow(BundleError);
  });

  it("E1-B-09 names the offending path of a refused file entry", () => {
    const parent = {
      ...bundle(),
      files: [...bundle().files, { kind: "dir" as const, path: ".tool", mode: 0o700 }],
    };
    try {
      encodeBundle(parent, definition);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(BundleError);
      expect((error as BundleError).reason).toBe("undeclared_path");
      expect((error as BundleError).path).toBe(".tool");
      expect(String(error)).toContain("(.tool)");
    }
  });

  it("never puts value bytes in an error", () => {
    const bytes = serializeBundleUnchecked({
      ...bundle(),
      files: [],
      env: [{ name: "A_TOKEN", value: utf8(`${SECRET}\0`) }],
    });
    try {
      decodeBundle(bytes, definition, digest);
      expect.unreachable();
    } catch (error) {
      expect((error as BundleError).reason).toBe("env_value_nul");
      expect(String(error)).not.toContain(SECRET);
      expect(JSON.stringify(error)).not.toContain(SECRET);
    }
  });

  it("reports missing required paths", () => {
    const partial = { ...bundle(), files: bundle().files.slice(0, 2) };
    expect(missingRequiredPaths(partial, definition)).toEqual([".tool/auth.json"]);
    expect(missingRequiredPaths(bundle(), definition)).toEqual([]);
  });
});
