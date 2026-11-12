// biome-ignore-all lint/suspicious/noTemplateCurlyInString: recipe substitution syntax is literal ${…} text
import { describe, expect, it } from "vitest";
import { RecipeError } from "./errors";
import { escapeSubstitution, substitute } from "./substitute";

const vars = new Map([
  ["A", "1"],
  ["EMPTY", ""],
]);

describe("substitute", () => {
  it.each([
    ["$A", "1"],
    ["${A}x", "1x"],
    ["$UNSET-", "-"],
    ["${EMPTY:-d}", "d"],
    ["${A:-d}", "1"],
    ["${A:+set}", "set"],
    ["${UNSET:+set}", ""],
    ["\\$A", "$A"],
    ["\\\\$A", "\\1"],
    ["a\\b", "a\\b"],
    ["$ 1 $", "$ 1 $"],
    ["$1", "$1"],
  ])("%s → %s", (text, expected) => {
    expect(substitute(text, vars)).toBe(expected);
  });
  it("refuses malformed braces", () => {
    expect(() => substitute("${A", vars)).toThrow(RecipeError);
    expect(() => substitute("${A?x}", vars)).toThrow(RecipeError);
  });
  it("round-trips escaped literals", () => {
    const literal = "C:\\$HOME ${X} \\\\";
    expect(substitute(escapeSubstitution(literal), vars)).toBe(literal);
  });
  it("refuses an expansion over maxBytes before materializing it", () => {
    const big = new Map([["B", "b".repeat(3000)]]);
    expect(substitute("$B", big, { maxBytes: 4096 })).toHaveLength(3000);
    expect(() => substitute("$B$B", big, { maxBytes: 4096 })).toThrow(
      expect.objectContaining({ code: "recipe_expansion_too_large" }),
    );
    // UTF-8 bytes, not code units: 1500 x "é" is 3000 bytes.
    const wide = new Map([["W", "é".repeat(1500)]]);
    expect(() => substitute("$W$W", wide, { maxBytes: 4096 })).toThrow(RecipeError);
  });
  it("charges a shared budget across calls", () => {
    const budget = { remaining: 10 };
    expect(substitute("${A}2345", vars, { budget })).toBe("12345");
    expect(budget.remaining).toBe(5);
    expect(() => substitute("123456", vars, { budget })).toThrow(
      expect.objectContaining({ code: "recipe_expansion_too_large" }),
    );
  });
});
