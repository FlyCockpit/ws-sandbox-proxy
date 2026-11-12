import { expect, it } from "vitest";
import { assertUniqueEnvKeys } from "./env-json";

it("rejects decoded duplicate envs keys before object construction, including batches", () => {
  for (const source of [
    '{"envs":{"A":"first","A":"second"}}',
    '{"envs":{"A":"first","\\u0041":"second"}}',
    '[{"json":{"envs":{"A":"first","A":"second"}}}]',
    '{"envs":{},"envs":{}}',
  ])
    expect(() => assertUniqueEnvKeys(source, 65536)).toThrow("sandbox.env_invalid");
});
it("skips value tokens, walks nested batches and bounds depth/bytes", () => {
  for (const input of [
    { envs: { A: 'quotes\\"\n😀', B: "A" } },
    [{ json: { envs: { A: "1" } } }, { json: { envs: { A: "2" } } }],
    { text: '{"envs":{"A":"v","A":"v"}}' },
  ])
    expect(() => assertUniqueEnvKeys(JSON.stringify(input), 65536)).not.toThrow();
  expect(() => assertUniqueEnvKeys('["😀"]', 7)).toThrow();
  expect(() => assertUniqueEnvKeys("[".repeat(130) + "0" + "]".repeat(130), 65536)).toThrow();
});
it("bounds UTF-8 bytes exactly as TextEncoder counts them, multibyte and lone surrogates included", () => {
  const sources = [
    '"aaaa"',
    '"é"',
    '"€"',
    '"😀"',
    '"\uD83D"', // lone high surrogate -> U+FFFD (3 bytes)
    '"\uDE00"', // lone low surrogate -> U+FFFD (3 bytes)
    '"\uD83Da"',
    '"😀😀é€a"',
    `"${"😀".repeat(40)}"`,
    `"${"é".repeat(41)}a"`,
  ];
  for (const source of sources) {
    const bytes = new TextEncoder().encode(source).byteLength;
    // At the bound: accepted; one byte under: refused.
    expect(() => assertUniqueEnvKeys(source, bytes)).not.toThrow();
    expect(() => assertUniqueEnvKeys(source, bytes - 1)).toThrow("sandbox.env_invalid");
    // The fast path (length * 3 <= max) still accepts.
    expect(() => assertUniqueEnvKeys(source, source.length * 3)).not.toThrow();
  }
  // A code-unit count over the bound fails before any byte count.
  expect(() => assertUniqueEnvKeys('"abc"', 4)).toThrow("sandbox.env_invalid");
});
