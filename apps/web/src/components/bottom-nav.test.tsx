// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enDashboard from "@wssp/locales/src/en-US/dashboard.json";
import enNav from "@wssp/locales/src/en-US/nav.json";
import esCommon from "@wssp/locales/src/es-MX/common.json";
import esDashboard from "@wssp/locales/src/es-MX/dashboard.json";
import esNav from "@wssp/locales/src/es-MX/nav.json";
import { createInstance, type i18n as I18n } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  status: "authenticated" as "authenticated" | "anonymous" | "pending",
  pathname: "/en-US/dashboard/sandboxes",
  lang: "en-US",
  showsAdmin: false,
}));

vi.mock("@tanstack/react-router", () => ({
  Link: ({
    children,
    className,
    to,
    params,
    ...rest
  }: {
    children: ReactNode;
    className?: string;
    to: string;
    params?: { lang?: string };
    "data-nav-id"?: string;
    "data-active"?: string;
    onClick?: () => void;
  }) => (
    <a
      className={className}
      href={to.replace("$lang", params?.lang ?? "$lang")}
      data-nav-id={rest["data-nav-id"]}
      data-active={rest["data-active"]}
      onClick={rest.onClick}
    >
      {children}
    </a>
  ),
  useParams: () => ({ lang: state.lang }),
  useLocation: () => ({ pathname: state.pathname }),
}));
vi.mock("@/hooks/use-admin-navigation", () => ({
  useShowsAdminNavigation: () => state.showsAdmin,
}));
// A plain stand-in for the Base UI sheet: open renders its content inline.
vi.mock("@wssp/ui/components/sheet", () => ({
  Sheet: ({ open, children }: { open: boolean; children: ReactNode }) =>
    open ? <div data-testid="more-sheet">{children}</div> : null,
  SheetContent: ({ children }: { children: ReactNode }) => <div role="dialog">{children}</div>,
  SheetHeader: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  SheetTitle: ({ children }: { children: ReactNode }) => <h2>{children}</h2>,
}));
vi.mock("@/hooks/use-auth-session", () => ({
  useAuthSession: () => ({
    state:
      state.status === "authenticated"
        ? { status: "authenticated", session: { user: { id: "u" } } }
        : { status: state.status },
  }),
}));

import BottomNav from "./bottom-nav";

const instances = {} as Record<"en-US" | "es-MX", I18n>;
beforeAll(async () => {
  for (const [lang, nav, dashboard, common] of [
    ["en-US", enNav, enDashboard, enCommon],
    ["es-MX", esNav, esDashboard, esCommon],
  ] as const) {
    const instance = createInstance();
    await instance.init({
      lng: lang,
      fallbackLng: false,
      ns: ["nav", "dashboard", "common"],
      defaultNS: "nav",
      resources: { [lang]: { nav, dashboard, common } },
      interpolation: { escapeValue: false },
      react: { useSuspense: false },
    });
    instances[lang] = instance;
  }
});
beforeEach(() => {
  state.status = "authenticated";
  state.pathname = "/en-US/dashboard/sandboxes";
  state.lang = "en-US";
  state.showsAdmin = false;
});
afterEach(() => cleanup());

function mount(lang: "en-US" | "es-MX" = "en-US") {
  state.lang = lang;
  return render(
    <I18nextProvider i18n={instances[lang]}>
      <BottomNav />
    </I18nextProvider>,
  );
}
const links = () => [...document.querySelectorAll("a")];

const tabs = () => [...document.querySelectorAll("[data-bottom-nav] [data-nav-id]")];

describe("bottom tabs", () => {
  it.each(["en-US", "es-MX"] as const)(
    "%s: signed in, four sections and More, each a 44px target",
    (lang) => {
      mount(lang);
      expect(links().map((a) => a.getAttribute("href"))).toEqual([
        `/${lang}/dashboard/sandboxes`,
        `/${lang}/dashboard/templates`,
        `/${lang}/dashboard/operations`,
        `/${lang}/settings`,
      ]);
      const nav = lang === "en-US" ? enNav : esNav;
      expect(tabs().map((el) => el.textContent)).toEqual([
        nav.items.sandboxes,
        nav.items.templates,
        nav.items.activity,
        nav.items.settings,
        nav.items.more,
      ]);
      for (const el of tabs()) expect(el.className).toContain("min-h-[44px]");
      expect(tabs()).toHaveLength(5);
      expect(document.querySelectorAll("nav")).toHaveLength(1);
    },
  );

  it.each([
    ["/en-US/settings", "settings"],
    ["/en-US/settings/pools", "settings"],
    ["/en-US/dashboard/operations/op", "activity"],
    ["/en-US/dashboard/templates/builds", "templates"],
    // Hosts lives behind More on phones, so More is the lit tab.
    ["/en-US/settings/hosts/h1", "more"],
  ])("on %s only the %s tab is active", (pathname, id) => {
    state.pathname = pathname;
    mount();
    const active = tabs().filter((el) => (el as HTMLElement).dataset.active === "true");
    expect(active.map((el) => (el as HTMLElement).dataset.navId)).toEqual([id]);
  });

  it.each([
    [false, ["/en-US/settings/hosts", "/en-US/dashboard/terminals"]],
    [true, ["/en-US/settings/hosts", "/en-US/dashboard/terminals", "/en-US/admin"]],
  ])("More (admin: %s) opens a sheet with the remaining sections", async (showsAdmin, hrefs) => {
    state.showsAdmin = showsAdmin;
    mount();
    const more = screen.getByRole("button", { name: enNav.items.more });
    expect(more.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(more);
    const sheet = await screen.findByTestId("more-sheet");
    expect(more.getAttribute("aria-expanded")).toBe("true");
    const sheetLinks = [...sheet.querySelectorAll("a")];
    expect(sheetLinks.map((a) => a.getAttribute("href"))).toEqual(hrefs);
    for (const a of sheetLinks) expect(a.className).toContain("h-11");
    fireEvent.click(sheetLinks[0] as HTMLElement);
    expect(screen.queryByTestId("more-sheet")).toBeNull();
  });

  it("shows five placeholders while the session resolves", () => {
    state.status = "pending";
    const view = mount();
    expect(links()).toHaveLength(0);
    expect(view.container.querySelectorAll('[data-slot="skeleton"]')).toHaveLength(5);
  });

  it("signed out, keeps the anonymous Home tab", () => {
    state.status = "anonymous";
    mount();
    expect(links().map((a) => a.getAttribute("href"))).toEqual(["/en-US"]);
    expect(links()[0]?.textContent).toBe(enNav.items.home);
  });
});
