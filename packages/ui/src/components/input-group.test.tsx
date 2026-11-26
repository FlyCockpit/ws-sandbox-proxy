import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { InputGroupInput, InputGroupTextarea } from "./input-group";

function classes(markup: string): string[] {
  return (/class="([^"]*)"/.exec(markup)?.[1] ?? "").split(/\s+/);
}

describe("grouped controls", () => {
  // The group draws the (invalid) focus ring; the inner Input/Textarea's own
  // invalid + focus ring (aria-invalid:focus-visible:ring-2) must be merged
  // away, or a focused invalid field shows a second ring inside the group.
  it.each([
    ["input", InputGroupInput],
    ["textarea", InputGroupTextarea],
  ] as const)("the %s draws no ring of its own while invalid and focused", (_name, Control) => {
    const list = classes(renderToStaticMarkup(<Control aria-invalid />));
    expect(list).toContain("aria-invalid:focus-visible:ring-0");
    expect(list).not.toContain("aria-invalid:focus-visible:ring-2");
    expect(list).toContain("focus-visible:ring-0");
    expect(list).not.toContain("focus-visible:ring-2");
  });
});
