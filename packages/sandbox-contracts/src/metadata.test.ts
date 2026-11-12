import { expect, it } from "vitest";
import { metadataSchema } from "./metadata";

it("rejects non-string metadata without coercion", () => {
  for (const value of [1, true, null, {}, [], undefined]) {
    expect(metadataSchema.safeParse({ key: value }).success).toBe(false);
  }
  expect(metadataSchema.parse({ label: "😀", empty: "" })).toEqual({
    label: "😀",
    empty: "",
  });
});

it("enforces exact key, code-unit and canonical JSON UTF-8 byte bounds", () => {
  const keys = Object.fromEntries(Array.from({ length: 32 }, (_, i) => [`k${i}`, ""]));
  expect(metadataSchema.safeParse(keys).success).toBe(true);
  expect(metadataSchema.safeParse({ ...keys, extra: "" }).success).toBe(false);
  expect(metadataSchema.safeParse({ ["k".repeat(64)]: "😀".repeat(512) }).success).toBe(true);
  expect(metadataSchema.safeParse({ ["😀".repeat(32)]: "" }).success).toBe(true);
  for (const bad of [
    { "": "x" },
    { ["k".repeat(65)]: "x" },
    { key: "x".repeat(1025) },
    { ["😀".repeat(33)]: "" },
    { key: "😀".repeat(513) },
    { key: "\0" },
    { key: "\ud800" },
    { "\udfff": "x" },
    { constructor: "x" },
    { prototype: "x" },
    JSON.parse('{"__proto__":"x"}'),
  ])
    expect(metadataSchema.safeParse(bad).success).toBe(false);
  // Seven 1024-byte values plus an exact tail, counting escaped JSON, not characters.
  const map = Object.fromEntries(Array.from({ length: 7 }, (_, i) => [`k${i}`, "😀".repeat(256)]));
  const overhead = new TextEncoder().encode(JSON.stringify({ ...map, tail: "" })).byteLength;
  const exact = { ...map, tail: "x".repeat(8192 - overhead) };
  expect(new TextEncoder().encode(JSON.stringify(exact)).byteLength).toBe(8192);
  expect(metadataSchema.safeParse(exact).success).toBe(true);
  expect(metadataSchema.safeParse({ ...exact, tail: `${exact.tail}x` }).success).toBe(false);
  expect(metadataSchema.safeParse({ key: "\n".repeat(1024) }).success).toBe(true);
});

it("refuses inherited maps, symbols and accessors without invoking getters", () => {
  let invoked = false;
  const getter = Object.defineProperty({}, "key", {
    enumerable: true,
    get() {
      invoked = true;
      return "bad";
    },
  });
  for (const bad of [
    [],
    null,
    Object.create({ inherited: "x" }),
    { [Symbol("x")]: "x" },
    getter,
    Object.defineProperty({}, "hidden", { value: "x" }),
  ]) {
    expect(metadataSchema.safeParse(bad).success).toBe(false);
  }
  expect(invoked).toBe(false);
  expect(metadataSchema.parse(Object.assign(Object.create(null), { plain: "value" }))).toEqual({
    plain: "value",
  });
});
