import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { AuthCard } from "./auth-screen";

/**
 * On phones the auth card starts just under the header and is flat (no
 * surface, ring or inner padding), so the login page's sign-up link stays
 * above the BottomNav at 320×568; from `sm` up it is the centred card as
 * before. Static markup pins the classes; the real geometry is checked in a
 * browser.
 */
const classesOf = (html: string, pattern: RegExp) => html.match(pattern)?.[1]?.split(" ") ?? [];

describe("auth card", () => {
  const html = renderToStaticMarkup(
    <AuthCard title="Welcome" description="Sign in">
      <p>form</p>
    </AuthCard>,
  );

  it("starts under the header on phones and centres from sm: up", () => {
    const screen = classesOf(html, /^<div class="([^"]*)"/);
    expect(screen).toEqual(
      expect.arrayContaining([
        "min-h-[80svh]",
        "items-center",
        "max-sm:min-h-0",
        "max-sm:items-start",
        "max-sm:pt-3",
        "max-sm:pb-4",
      ]),
    );
  });

  it("is flat on phones without clipping the inputs' focus rings", () => {
    expect(classesOf(html, /data-slot="card"[^>]*class="([^"]*)"/)).toEqual(
      expect.arrayContaining([
        "max-sm:overflow-visible",
        "max-sm:bg-transparent",
        "max-sm:py-0",
        "max-sm:ring-0",
      ]),
    );
    expect(classesOf(html, /data-slot="card-header" class="([^"]*)"/)).toContain("max-sm:px-0");
    expect(classesOf(html, /data-slot="card-content" class="([^"]*)"/)).toContain("max-sm:px-0");
  });
});
