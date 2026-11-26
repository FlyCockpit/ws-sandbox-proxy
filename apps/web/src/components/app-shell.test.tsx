import type { ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The `_app` branch is client-rendered, so its pending frame is what the
 * server sends for a signed-in URL and what a hard refresh paints first. It
 * must be the app (header, sidebar, bottom nav) with only the page body as a
 * skeleton. Rendered to static markup, as the server does.
 */
type Match = { routeId: string; staticData?: Record<string, string> };
const APP: Match = { routeId: "/$lang/_app" };
const AUTH: Match = { routeId: "/$lang/_app/_auth", staticData: { pendingFrame: "dashboard" } };
const leaf = (routeId: string, staticData: Record<string, string>): Match => ({
  routeId,
  staticData,
});
const route = vi.hoisted(() => ({
  pathname: "/en-US/dashboard/sandboxes",
  matches: [] as { routeId: string; staticData?: Record<string, string> }[],
}));
vi.mock("@tanstack/react-router", () => ({
  Link: ({
    children,
    to,
    params,
    ...rest
  }: {
    children: ReactNode;
    to: string;
    params?: { lang?: string };
    "data-nav-id"?: string;
    "data-active"?: string;
  }) => (
    <a
      href={to.replace("$lang", params?.lang ?? "$lang")}
      data-nav-id={rest["data-nav-id"]}
      data-active={rest["data-active"]}
    >
      {children}
    </a>
  ),
  useLocation: () => ({ pathname: route.pathname }),
  useParams: () => ({ lang: "en-US" }),
  // `_app`'s pending boundary, and the matches of the URL being loaded.
  useMatch: () => "/$lang/_app",
  useRouterState: () => route.matches,
}));
vi.mock("@wssp/env/web", () => ({ env: { VITE_APP_NAME: "wssp" } }));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (key: string) => key }) }));
vi.mock("@/components/language-switcher", () => ({
  LanguageSwitcher: () => <i data-control="language" />,
}));
vi.mock("@/components/mode-toggle", () => ({ ModeToggle: () => <i data-control="theme" /> }));
vi.mock("./language-switcher", () => ({ LanguageSwitcher: () => <i data-control="language" /> }));
vi.mock("./mode-toggle", () => ({ ModeToggle: () => <i data-control="theme" /> }));
// The placeholder header must not touch the session: prove it by failing loudly.
vi.mock("./user-menu", () => ({
  default: () => {
    throw new Error("the pending header rendered the live account menu");
  },
}));
vi.mock("@/hooks/use-auth-session", () => ({
  useAuthSession: () => {
    throw new Error("the pending frame read the session");
  },
}));

import { AppShellPending } from "./app-shell";

/** Point the pending frame at `pathname`, matched as `matches`. */
function at(pathname: string, ...matches: Match[]) {
  route.pathname = pathname;
  route.matches = [{ routeId: "__root__" }, { routeId: "/$lang" }, APP, ...matches];
}

beforeEach(() => {
  at(
    "/en-US/dashboard/sandboxes",
    AUTH,
    leaf("/$lang/_app/_auth/dashboard/sandboxes/", { pendingShape: "list" }),
  );
});

describe("shell pending frame", () => {
  it("paints header, sidebar and bottom nav around a skeleton body on a signed-in URL", () => {
    at(
      "/en-US/settings/hosts",
      AUTH,
      leaf("/$lang/_app/_auth/settings/hosts/", { pendingShape: "list" }),
    );
    const html = renderToStaticMarkup(<AppShellPending />);
    // Header row: the app name, the controls, and the account skeleton.
    expect(html).toContain('data-control="language"');
    expect(html).toContain('data-control="theme"');
    expect(html).toMatch(/data-slot="skeleton" class="[^"]*h-11 w-11 md:w-24/);
    // The one main scroller.
    expect(html.match(/<main\b/g)).toHaveLength(1);
    expect(html).toContain('id="main-content"');
    // Sidebar: the same sections as the live one, the current one lit.
    expect(html).toContain('data-dashboard-nav="sidebar"');
    expect(html).toContain("in-data-[sidebar=collapsed]:w-16");
    const ids = [...html.matchAll(/data-nav-id="(\w+)"/g)].map((m) => m[1]);
    expect(ids).toEqual(["sandboxes", "templates", "activity", "hosts", "terminals", "settings"]);
    expect(html).toMatch(/data-nav-id="hosts" data-active="true"/);
    // Bottom nav: the static tabs drawn for real (icons and labels), More inert;
    // no blank blocks. Hosts is under More, so Settings' section is not lit here.
    const bottom = /<nav [^>]*data-bottom-nav[^>]*>(.*?)<\/nav>/.exec(html)?.[1] ?? "";
    expect(bottom).not.toContain('data-slot="skeleton"');
    expect(bottom.match(/<a /g)).toHaveLength(4);
    expect(bottom.match(/<svg/g)).toHaveLength(5);
    for (const label of ["items.sandboxes", "items.templates", "items.activity", "items.more"])
      expect(bottom).toContain(label);
    // Only the body is a skeleton, in the page's shape.
    expect(html).toContain('data-route-skeleton="list"');
    expect(html).toContain('aria-busy="true"');
  });

  it("paints a form page's body as a form", () => {
    at(
      "/en-US/dashboard/sandboxes/new",
      AUTH,
      leaf("/$lang/_app/_auth/dashboard/sandboxes/new", { pendingShape: "form" }),
    );
    const html = renderToStaticMarkup(<AppShellPending />);
    expect(html).toContain('data-dashboard-nav="sidebar"');
    expect(html).toContain('data-route-skeleton="form"');
  });

  it("paints no sidebar around an auth page", () => {
    at("/en-US/login", leaf("/$lang/_app/login", { pendingShape: "auth" }));
    const html = renderToStaticMarkup(<AppShellPending />);
    expect(html).not.toContain('data-dashboard-nav="sidebar"');
    expect(html).toContain('id="main-content"');
    expect(html).toContain('data-route-skeleton="auth"');
    // Signed-in or not is unknown here: the bar stays a skeleton.
    const bottom = /<nav [^>]*data-bottom-nav[^>]*>(.*?)<\/nav>/.exec(html)?.[1] ?? "";
    expect(bottom.match(/data-slot="skeleton"/g)).toHaveLength(5);
  });

  it("the Settings hub's first frame is card-grid shaped, not a list", () => {
    at("/en-US/settings", AUTH, leaf("/$lang/_app/_auth/settings/", { pendingShape: "hub" }));
    const html = renderToStaticMarkup(<AppShellPending />);
    expect(html).toContain('data-route-skeleton="hub"');
    expect(html).toContain("sm:grid-cols-2");
  });

  it("paints /admin exactly like a route that declares nothing, so it never reveals /admin", () => {
    at(
      "/en-US/admin/users",
      { routeId: "/$lang/_app/admin", staticData: { pendingShape: "list" } },
      leaf("/$lang/_app/admin/users", { pendingShape: "list" }),
    );
    const admin = renderToStaticMarkup(<AppShellPending />);
    at("/en-US/admin/users");
    expect(admin).toBe(renderToStaticMarkup(<AppShellPending />));
    expect(admin).not.toContain('data-dashboard-nav="sidebar"');
  });
});
