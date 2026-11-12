import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parseLoginDefinition } from "./definition";

/** The guide's example definitions are the committed vectors, verbatim. */
const guide = readFileSync(new URL("../../../docs/guide/cli-logins.md", import.meta.url), "utf8");
const vector = (name: string) =>
  readFileSync(new URL(`../vectors/valid/${name}`, import.meta.url), "utf8");

describe("docs/guide/cli-logins.md", () => {
  const blocks = [...guide.matchAll(/```json\n([\s\S]*?)\n```/g)].map((m) => `${m[1]}\n`);

  it("embeds the Codex and Claude example vectors byte for byte", () => {
    expect(blocks).toEqual([vector("codex-cli.json"), vector("claude-code.json")]);
  });

  it("shows only valid definitions", () => {
    for (const block of blocks) expect(parseLoginDefinition(JSON.parse(block)).success).toBe(true);
  });
});
