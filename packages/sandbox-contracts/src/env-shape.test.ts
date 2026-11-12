import { describe, expect, it } from "vitest";
import { defaultEnvShapeSchema, envShapeSchema } from "./env-shape";

describe("staged environment shape and Unicode validation", () => {
  it("accepts POSIX names, empty values, Unicode and null-prototype maps", () => {
    const map = Object.assign(Object.create(null), { PATH: "/bin", _X1: "😀é\n", EMPTY: "" });
    expect(envShapeSchema.parse(map)).toEqual({ PATH: "/bin", _X1: "😀é\n", EMPTY: "" });
    expect(envShapeSchema.parse({})).toEqual({});
  });

  it("rejects non-string values, invalid names, NUL, lone surrogates and prototype keys", () => {
    for (const bad of [
      null,
      [],
      "env",
      { A: 1 },
      { A: false },
      { A: null },
      { A: undefined },
      { A: {} },
      { "": "x" },
      { "1A": "x" },
      { "A-B": "x" },
      { é: "x" },
      { A: "sentinel\0" },
      { A: "\ud800" },
      { A: "\udfff" },
      { "A\0": "x" },
      JSON.parse('{"__proto__":"x"}'),
      { constructor: "x" },
      { prototype: "x" },
      new Date(),
      Object.create({ inherited: "x" }),
      { [Symbol("x")]: "x" },
    ])
      expect(envShapeSchema.safeParse(bad).success).toBe(false);
  });

  it("does not invoke getters or include env values in errors", () => {
    let reads = 0;
    const result = envShapeSchema.safeParse({
      get VALUE() {
        reads++;
        return "secret-sentinel";
      },
    });
    expect(reads).toBe(0);
    expect(result.success).toBe(false);
    expect(JSON.stringify(result.error)).not.toContain("secret-sentinel");
    const invalid = envShapeSchema.safeParse({ VALUE: "secret-sentinel\0" });
    expect(JSON.stringify(invalid.error)).not.toContain("secret-sentinel");
  });

  it("reserves identity/PTY names only in stored defaults", () => {
    for (const name of ["HOME", "SHELL", "TERM"]) {
      expect(envShapeSchema.safeParse({ [name]: "value" }).success).toBe(true);
      expect(defaultEnvShapeSchema.safeParse({ [name]: "value" }).success).toBe(false);
    }
    expect(defaultEnvShapeSchema.parse({ home: "value", APP: "😀" })).toEqual({
      home: "value",
      APP: "😀",
    });
  });
});
