// @vitest-environment jsdom
import { type ComponentType, lazy, type ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { prerender } from "react-dom/static";
import { describe, expect, it, vi } from "vitest";

/**
 * The signed-in frame's height chain inside the shell's `<main>` scroller
 * (docs/design/shell-rules.md § Shell rules)
 * `min-h-full` / `h-full` is
 * 100 % of `<main>`; a box sized that way below an in-flow sibling (the
 * sticky admin section nav, the 2FA banner) is taller than `<main>` by that
 * sibling, so every page scrolls by the banner's height and the sticky
 * sidebar slides under the header at the bottom (e2e5 NEW-A1: the admin
 * pages overflowed by the 60 px admin nav). Rendered to markup, so the real
 * admin layout and frame classes are what is checked; the geometry itself
 * is measured in a browser by `pnpm check:layout`.
 */
vi.mock("@tanstack/react-router", () => ({
  createFileRoute: () => (options: Record<string, unknown>) => ({
    options,
    useParams: () => ({ lang: "en-US" }),
  }),
  lazyRouteComponent: (importer: () => Promise<Record<string, unknown>>, name = "default") =>
    lazy(async () => ({ default: (await importer())[name] as ComponentType })),
  Link: ({ children }: { children: ReactNode }) => <a href="/">{children}</a>,
  Outlet: () => <p data-page="">page</p>,
  notFound: () => undefined,
  useLocation: () => ({ pathname: "/en-US/admin/observability" }),
}));
vi.mock("@tanstack/react-query", () => ({
  useQueryClient: () => ({ invalidateQueries: async () => {} }),
}));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (key: string) => key }) }));
vi.mock("@/hooks/use-admin-navigation", () => ({ useShowsAdminNavigation: () => true }));
vi.mock("@/components/admin/two-factor-nudge", () => ({
  TwoFactorNudge: () => <div className="border-b">2fa</div>,
}));
vi.mock("@/lib/hidden-admin", () => ({ HIDDEN_ROUTE_NOT_FOUND_ID: "/$lang" }));
vi.mock("@/lib/route-session-access", () => ({ decideAdminRouteAccess: () => null }));
vi.mock("@/server/admin-route-access", () => ({ getRouteAdminAccess: async () => null }));

const { DashboardFrame } = await import("./dashboard-frame");
const { Route: AdminRoute } = await import("@/routes/$lang/_app/admin");

/** `min-h-full`, `h-full`, with or without a variant (`md:min-h-full`). */
const PERCENT_HEIGHT = /^(?:[\w-]+:)*(?:min-)?h-full$/;
const OUT_OF_FLOW = new Set(["absolute", "fixed", "sr-only"]);

/** The boxes a `display: contents` wrapper leaves in its parent's flow. */
function flowChildren(element: Element): Element[] {
  return [...element.children].flatMap((child) => {
    if (child.classList.contains("contents")) return flowChildren(child);
    if ([...child.classList].some((name) => OUT_OF_FLOW.has(name))) return [];
    return [child];
  });
}

/** The box `child` is laid out in (skipping `display: contents` wrappers). */
function flowParent(child: Element): Element | null {
  let parent = child.parentElement;
  while (parent?.classList.contains("contents")) parent = parent.parentElement;
  return parent;
}

/**
 * Every percentage-height box on the page's chain must be the only in-flow
 * box at each level up to `<main>`; otherwise its 100 % adds to a sibling.
 */
function percentHeightOverflows(main: Element): string[] {
  const page = main.querySelector("[data-page]");
  if (!page) return ["no page rendered"];
  const bad: string[] = [];
  for (let node: Element | null = page; node && node !== main; node = node.parentElement) {
    if (![...node.classList].some((name) => PERCENT_HEIGHT.test(name))) continue;
    for (let box: Element = node; box !== main; ) {
      const parent = flowParent(box);
      if (!parent) break;
      const siblings = flowChildren(parent).filter((sibling) => sibling !== box);
      if (siblings.length > 0)
        bad.push(
          `<${node.tagName.toLowerCase()} class="${node.className}"> is 100 % of <main> below ${siblings
            .map((sibling) => `<${sibling.tagName.toLowerCase()} class="${sibling.className}">`)
            .join(", ")}`,
        );
      box = parent;
    }
  }
  return bad;
}

function mainOf(markup: string): Element {
  const host = document.createElement("div");
  host.innerHTML = `<main class="relative min-h-0 overflow-y-auto">${markup}</main>`;
  const main = host.querySelector("main");
  if (!main) throw new Error("no main");
  return main;
}

async function renderRoute(Component: ComponentType): Promise<string> {
  const { prelude } = await prerender(<Component />);
  return new Response(prelude).text();
}

describe("dashboard frame height chain", () => {
  it("sizes no box to <main> below the admin section nav", async () => {
    const component = (AdminRoute as unknown as { options: { component: ComponentType } }).options
      .component;
    const markup = await renderRoute(component);
    const main = mainOf(markup);
    expect(main.querySelector("nav.sticky")).not.toBeNull();
    expect(percentHeightOverflows(main)).toEqual([]);
  });

  it("sizes no box to <main> below a banner", () => {
    const main = mainOf(
      renderToStaticMarkup(
        <DashboardFrame lang="en-US" banner={<div className="border-b">banner</div>} />,
      ),
    );
    expect(percentHeightOverflows(main)).toEqual([]);
  });

  it("flags a full-height page column under a sibling bar", () => {
    // The pre-fix frame: the pull-to-refresh wrapper was `relative min-h-full`.
    const main = mainOf(
      `<div class="flex min-h-full flex-col"><div class="flex flex-1 flex-col">` +
        `<nav class="sticky top-0">tabs</nav><div class="relative min-h-full"><p data-page></p></div>` +
        `</div></div>`,
    );
    expect(percentHeightOverflows(main)).toEqual([
      '<div class="relative min-h-full"> is 100 % of <main> below <nav class="sticky top-0">',
    ]);
  });
});
