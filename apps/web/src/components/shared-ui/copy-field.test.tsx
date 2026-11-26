import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { CodeSnippet } from "@wssp/ui/components/code-snippet";
import { CopyField } from "@wssp/ui/components/copy-field";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

// Static markup: the layout contract lives in the classes and the element
// order, so that is what these pin down.
const CODE_TEXT = ["font-mono", "text-xs", "leading-5"];

function parse(html: string) {
  const slot = (name: string) => {
    const match = new RegExp(`<(\\w+)[^>]*data-slot="${name}"[^>]*>`).exec(html);
    if (!match) throw new Error(`Missing data-slot ${name}`);
    return {
      tag: match[1],
      index: match.index,
      classes: /class="([^"]*)"/.exec(match[0])?.[1]?.split(" ") ?? [],
    };
  };
  return { slot, button: html.indexOf("<button") };
}

describe("CopyField", () => {
  const html = renderToStaticMarkup(
    <CopyField value="curl -fsSL https://example.com/install.sh | sh" copyLabel="Copy" />,
  );
  const { slot, button } = parse(html);

  it("keeps the value in its own scroller beside the button, never under it", () => {
    const field = slot("copy-field");
    const value = slot("copy-field-value");
    // The outer box carries the border, so the edge fade on the scroller
    // dims the text and never the outline.
    expect(field.classes).toEqual(
      expect.arrayContaining(["flex", "min-w-0", "max-w-full", "border"]),
    );
    expect(value.tag).toBe("code");
    expect(value.classes).toEqual(
      expect.arrayContaining(["min-w-0", "flex-1", "overflow-x-auto", "whitespace-nowrap"]),
    );
    expect(value.classes).toContain("edge-fade-x");
    expect(value.classes).not.toContain("border");
    // The button comes after the value closes: a sibling, not an overlay.
    expect(html.indexOf("</code>", value.index)).toBeLessThan(button);
    expect(html).not.toMatch(/absolute/);
  });

  it("uses the shared code text size and a 44px button", () => {
    expect(slot("copy-field-value").classes).toEqual(expect.arrayContaining(CODE_TEXT));
    expect(html).toMatch(/<button[^>]*min-h-\[44px\][^>]*min-w-\[44px\]/);
    expect(html).toContain('aria-label="Copy"');
  });

  it("shows no fade until the value is measured as overflowing", () => {
    expect(html).not.toContain("data-overflow-");
  });
});

describe("CodeSnippet", () => {
  const html = renderToStaticMarkup(<CodeSnippet code={'{\n  "a": 1\n}'} copyLabel="Copy" />);
  const { slot, button } = parse(html);

  it("gives the button its own column, so the scroll region ends before it", () => {
    const root = slot("code-snippet");
    const pre = slot("code-snippet-pre");
    expect(root.classes).toEqual(
      expect.arrayContaining(["flex", "min-w-0", "max-w-full", "border"]),
    );
    expect(pre.tag).toBe("pre");
    expect(pre.classes).toEqual(
      expect.arrayContaining(["min-w-0", "flex-1", "overflow-x-auto", "edge-fade-x"]),
    );
    expect(html.indexOf("</pre>")).toBeLessThan(button);
    expect(html).not.toMatch(/absolute|pr-12/);
    expect(html).toMatch(/<button[^>]*min-h-\[44px\][^>]*min-w-\[44px\]/);
  });

  it("uses the same code text size as CopyField", () => {
    expect(slot("code-snippet-pre").classes).toEqual(expect.arrayContaining(CODE_TEXT));
    expect(html).not.toMatch(/text-sm/);
  });

  it("wraps long lines only when asked", () => {
    expect(slot("code-snippet-pre").classes).not.toContain("whitespace-pre-wrap");
    const wrapped = parse(renderToStaticMarkup(<CodeSnippet code="x" wrap />)).slot(
      "code-snippet-pre",
    );
    expect(wrapped.classes).toEqual(
      expect.arrayContaining(["whitespace-pre-wrap", "[overflow-wrap:anywhere]"]),
    );
  });
});

it("uses the measured edge fade, not the vendored scroll-driven scroll-fade-x", () => {
  // shadcn-tailwind.css's `scroll-fade-x` fades both edges in browsers without
  // scroll-driven animations even when nothing overflows.
  for (const name of ["copy-field", "code-snippet", "selector-row"]) {
    const source = readFileSync(
      resolve(import.meta.dirname, `../../../../../packages/ui/src/components/${name}.tsx`),
      "utf8",
    );
    expect(source, name).toContain("edge-fade-x");
    expect(source, name).not.toContain("scroll-fade-x");
  }
});
