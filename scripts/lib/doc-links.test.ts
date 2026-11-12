import assert from "node:assert/strict";
import { test } from "node:test";

import { extractDocLinks, githubSlug, isRepoRelative, markdownAnchors } from "./doc-links.js";

test("githubSlug follows GitHub heading anchors", () => {
  assert.equal(githubSlug("Terminal PTY (C51)"), "terminal-pty-c51");
  assert.equal(githubSlug("The `APPLY_SCHEMA` contract"), "the-apply_schema-contract");
  assert.equal(githubSlug("Close intent and 4401"), "close-intent-and-4401");
  assert.equal(githubSlug("Drain and undrain"), "drain-and-undrain");
  assert.equal(githubSlug("Three planes, one owner"), "three-planes-one-owner");
  assert.equal(githubSlug("[Linked](./x.md) heading"), "linked-heading");
});

test("markdownAnchors numbers duplicate headings and ignores fenced code", () => {
  const anchors = markdownAnchors('# A\n## A\n```\n# Not a heading\n```\n<a id="custom"></a>\n');
  assert.deepEqual([...anchors].sort(), ["a", "a-1", "custom"]);
});

test("extractDocLinks keeps repo-relative targets outside code only", () => {
  const links = extractDocLinks(
    [
      "See [infra](../infra.md#health) and [license](LICENSE).",
      'Badge <a href="apps/cli/Cargo.toml">cli</a> and [site](https://example.com).',
      "Same file [jump](#below); `[code](missing.md)` is code.",
      "```",
      "[fenced](missing.md)",
      "```",
      "Site path [api](/v1/openapi.json).",
    ].join("\n"),
  );
  assert.deepEqual(
    links.map((link) => [link.target, link.anchor, link.line]),
    [
      ["../infra.md", "health", 1],
      ["LICENSE", null, 1],
      ["apps/cli/Cargo.toml", null, 2],
      ["", "below", 3],
    ],
  );
});

test("isRepoRelative excludes schemes and site paths", () => {
  assert.equal(isRepoRelative("docs/infra.md"), true);
  assert.equal(isRepoRelative("#anchor"), true);
  assert.equal(isRepoRelative("https://github.com"), false);
  assert.equal(isRepoRelative("mailto:a@b.c"), false);
  assert.equal(isRepoRelative("/v1/openapi.json"), false);
});
