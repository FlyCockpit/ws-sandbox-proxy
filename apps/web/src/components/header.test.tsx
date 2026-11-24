import type { ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

/**
 * Both header rows (the app shell's `Header` and the public pages'
 * `PublicHeader`) start with the same app name link, and it is the first
 * thing in either row to give way, at every width, so a long name or a long
 * locale cannot push the controls to a second row. Rendered to static markup
 * (no layout, no media queries), so the widths are pinned through the
 * classes; the real widths are checked in a browser.
 */
// Route files are code-split in the test build too: the layout component
// arrives through the real `lazyRouteComponent`, preloaded before rendering.
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  lazyRouteComponent: (await importOriginal<typeof import("@tanstack/react-router")>())
    .lazyRouteComponent,
  Link: ({
    children,
    className,
    to,
    title,
  }: {
    children: ReactNode;
    className?: string;
    to: string;
    title?: string;
  }) => (
    <a data-to={to} className={className} title={title}>
      {children}
    </a>
  ),
  Outlet: () => null,
  useParams: () => ({ lang: "en-US" }),
  createFileRoute: () => (options: Record<string, unknown>) => ({
    options,
    useParams: () => ({ lang: "en-US" }),
  }),
}));
vi.mock("@wssp/env/web", () => ({ env: { VITE_APP_NAME: "Northwind Regional Logistics" } }));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (key: string) => key }) }));
vi.mock("./language-switcher", () => ({ LanguageSwitcher: () => <i data-control="" /> }));
vi.mock("@/components/language-switcher", () => ({
  LanguageSwitcher: () => <i data-control="" />,
}));
vi.mock("./mode-toggle", () => ({ ModeToggle: () => <i data-control="" /> }));
vi.mock("@/components/mode-toggle", () => ({ ModeToggle: () => <i data-control="" /> }));
vi.mock("./user-menu", () => ({ default: () => <i data-control="" /> }));
vi.mock("./main-nav", () => ({ MainNav: () => null }));
vi.mock("@/components/skip-to-content", () => ({ SkipToContent: () => null }));

const { default: Header } = await import("./header");
const { Route: PublicRoute } = await import("@/routes/$lang/_public/route");

const PublicLayout = (
  PublicRoute as unknown as {
    options: { component: (() => ReactNode) & { preload?: () => Promise<void> } };
  }
).options.component;
await PublicLayout.preload?.();

function renderPublic() {
  return renderToStaticMarkup(<PublicLayout />);
}

const APP_NAME_LINK = /<a data-to="\/\$lang" class="([^"]*)" title="([^"]*)">(.*?)<\/a>/;

function expectAppNameGivesWayFirst(html: string) {
  const [, classes = "", title = "", inner = ""] = html.match(APP_NAME_LINK) ?? [];
  const brand = classes.split(" ");
  // A zero basis: it only grows into what the controls leave (up to its own
  // width), never below a 44px target, and the row wraps on that basis, so
  // the controls never move to a second row first. No shrink factor, no
  // larger minimum and no breakpoint variant of these.
  expect(brand).toEqual(
    expect.arrayContaining(["basis-0", "grow", "max-w-fit", "min-w-11", "inline-flex"]),
  );
  expect(brand.filter((c) => /shrink|min-w-(?!11)|:(basis|grow|max-w|min-w)/.test(c))).toEqual([]);
  // The ellipsis needs a block box: `truncate` on the inline-flex link only
  // clips. The caps sit on the span, so a long name leaves the MainNav room.
  expect(brand).not.toContain("truncate");
  const span = inner.match(/^<span class="([^"]*)">([^<]*)<\/span>$/);
  expect(span?.[1]?.split(" ").sort()).toEqual(
    ["lg:max-w-80", "max-w-40", "sm:max-w-56", "truncate"].sort(),
  );
  expect(span?.[2]).toBe("Northwind Regional Logistics");
  expect(title).toBe("Northwind Regional Logistics");
}

describe("app header row", () => {
  it("lets the app name give way first at every width", () => {
    expectAppNameGivesWayFirst(renderToStaticMarkup(<Header />));
  });
});

describe("public header row", () => {
  it("renders the same app name link as the app header", () => {
    expectAppNameGivesWayFirst(renderPublic());
  });

  it("hides its nav row below sm:", () => {
    const nav = renderPublic()
      .match(/<nav aria-label="[^"]*" class="([^"]*)"/)?.[1]
      ?.split(" ");
    expect(nav).toEqual(expect.arrayContaining(["hidden", "sm:block", "min-w-0", "flex-1"]));
  });

  it("gives Sign In the app header's touch metrics", () => {
    const signIn = renderPublic().match(/<a data-to="\/\$lang\/login" class="([^"]*)"/)?.[1];
    const classes = signIn?.split(" ") ?? [];
    expect(classes).toEqual(expect.arrayContaining(["h-11", "px-3.5", "text-xs", "shrink-0"]));
    expect(classes).not.toContain("text-sm");
  });
});
