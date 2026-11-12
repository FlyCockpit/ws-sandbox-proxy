// @vitest-environment jsdom

import { cleanup, render } from "@testing-library/react";
import enDashboard from "@wssp/locales/src/en-US/dashboard.json";
import enNav from "@wssp/locales/src/en-US/nav.json";
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
  }) => (
    <a
      className={className}
      href={to.replace("$lang", params?.lang ?? "$lang")}
      data-nav-id={rest["data-nav-id"]}
      data-active={rest["data-active"]}
    >
      {children}
    </a>
  ),
  useParams: () => ({ lang: state.lang }),
  useLocation: () => ({ pathname: state.pathname }),
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
  for (const [lang, nav, dashboard] of [
    ["en-US", enNav, enDashboard],
    ["es-MX", esNav, esDashboard],
  ] as const) {
    const instance = createInstance();
    await instance.init({
      lng: lang,
      fallbackLng: false,
      ns: ["nav", "dashboard"],
      defaultNS: "nav",
      resources: { [lang]: { nav, dashboard } },
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

describe("bottom tabs", () => {
  it.each(["en-US", "es-MX"] as const)(
    "%s: signed in, the four primary sections with 44px targets",
    (lang) => {
      mount(lang);
      expect(links().map((a) => a.getAttribute("href"))).toEqual([
        `/${lang}/dashboard/sandboxes`,
        `/${lang}/dashboard/templates`,
        `/${lang}/dashboard/operations`,
        `/${lang}/settings`,
      ]);
      const dashboard = lang === "en-US" ? enDashboard : esDashboard;
      expect(links().map((a) => a.textContent)).toEqual([
        dashboard.nav.sandboxes,
        dashboard.nav.templates,
        dashboard.nav.activity,
        dashboard.nav.settings,
      ]);
      for (const a of links()) expect(a.className).toContain("min-h-[44px]");
      expect(document.querySelectorAll("nav")).toHaveLength(1);
    },
  );

  it.each([
    ["/en-US/settings/hosts/h1", "settings"],
    ["/en-US/settings", "settings"],
    ["/en-US/dashboard/operations/op", "activity"],
    ["/en-US/dashboard/templates/builds", "templates"],
  ])("on %s only the %s tab is active", (pathname, id) => {
    state.pathname = pathname;
    mount();
    const active = links().filter((a) => a.dataset.active === "true");
    expect(active.map((a) => a.dataset.navId)).toEqual([id]);
  });

  it("shows four placeholders while the session resolves", () => {
    state.status = "pending";
    const view = mount();
    expect(links()).toHaveLength(0);
    expect(view.container.querySelectorAll('[data-slot="skeleton"]')).toHaveLength(4);
  });

  it("signed out, keeps the anonymous Home tab", () => {
    state.status = "anonymous";
    mount();
    expect(links().map((a) => a.getAttribute("href"))).toEqual(["/en-US"]);
    expect(links()[0]?.textContent).toBe(enNav.items.home);
  });
});
