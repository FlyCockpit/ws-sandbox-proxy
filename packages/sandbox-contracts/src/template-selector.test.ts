import { expect, it } from "vitest";
import { parseTemplateSelector } from "./template-selector";

it("parses selectors without resolving mutable tags or bare-name ambiguity", () => {
  expect(parseTemplateSelector("ubuntu")).toEqual({ kind: "name", name: "ubuntu" });
  expect(parseTemplateSelector("logicalID")).toEqual({ kind: "name", name: "logicalID" });
  expect(parseTemplateSelector("ubuntu-lts:stable")).toEqual({
    kind: "tag",
    slug: "ubuntu-lts",
    tag: "stable",
  });
  expect(parseTemplateSelector("template/logicalID")).toEqual({
    kind: "template",
    id: "logicalID",
  });
  expect(parseTemplateSelector("revision/revisionID")).toEqual({
    kind: "revision",
    id: "revisionID",
  });
  expect(parseTemplateSelector(`revision/${"r".repeat(64)}`)).toEqual({
    kind: "revision",
    id: "r".repeat(64),
  });
  expect(parseTemplateSelector(`${"s".repeat(63)}:${"t".repeat(128)}`).kind).toBe("tag");
});

it("bounds selectors and resource IDs and refuses malformed syntax", () => {
  for (const value of [
    "",
    null,
    1,
    " template/x",
    "a b",
    "x\0",
    "\ud800",
    "template/",
    "revision/",
    "template/x/y",
    "revision/x:tag",
    "other/x",
    "a:",
    ":tag",
    "a:b:c",
    "Bad-Slug:tag",
    "x".repeat(65),
    `revision/${"x".repeat(65)}`,
    `${"s".repeat(63)}:${"t".repeat(129)}`,
  ])
    expect(() => parseTemplateSelector(value)).toThrow();
});
