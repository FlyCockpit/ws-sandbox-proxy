// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import enDashboard from "@wssp/locales/src/en-US/dashboard.json";
import enNav from "@wssp/locales/src/en-US/nav.json";
import { createInstance, type i18n as I18n } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The user menu offers the admin area only to users the server gate would
 * admit: admin role, verified email, and forced-2FA satisfied. Everyone else
 * gets a menu with no trace of it. The top bar and bottom tabs never link it:
 * the admin area lives in the user menu only.
 */

const state = vi.hoisted(() => ({
  session: null as null | { user: Record<string, unknown> },
  settings: {} as Record<string, string>,
  settingsCalls: 0,
}));

vi.mock("@tanstack/react-router", () => ({
  Link: ({
    children,
    to,
    params,
  }: {
    children: ReactNode;
    to: string;
    params?: { lang?: string };
  }) => <a href={to.replace("$lang", params?.lang ?? "$lang")}>{children}</a>,
  useParams: () => ({ lang: "en-US" }),
  useLocation: () => ({ pathname: "/en-US/dashboard/sandboxes" }),
  useNavigate: () => vi.fn(),
}));

vi.mock("@/hooks/use-auth-session", () => ({
  useAuthSession: () => ({
    state: state.session
      ? { status: "authenticated", session: state.session }
      : { status: "anonymous" },
  }),
}));

vi.mock("@/utils/orpc", () => ({
  orpc: {
    settings: {
      getAll: {
        queryOptions: () => ({
          queryKey: ["settings", "getAll"],
          queryFn: async () => {
            state.settingsCalls += 1;
            return state.settings;
          },
        }),
      },
    },
  },
}));

import BottomNav from "@/components/bottom-nav";
import { MainNav } from "@/components/main-nav";
import UserMenuContent from "@/components/user-menu-content";

let i18n: I18n;
beforeAll(async () => {
  i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    fallbackLng: false,
    ns: ["nav", "dashboard"],
    defaultNS: "nav",
    resources: { "en-US": { nav: enNav, dashboard: enDashboard } },
    interpolation: { escapeValue: false },
    react: { useSuspense: false },
  });
});

let client: QueryClient;
function mount() {
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <MainNav />
        <BottomNav />
        {state.session ? <UserMenuContent /> : null}
      </I18nextProvider>
    </QueryClientProvider>,
  );
}

const menuItems = (label: string) =>
  [...document.querySelectorAll('[role="menuitem"]')].filter((item) =>
    item.textContent?.includes(label),
  );
/** Admin menu items; the shell links never point at the admin area. */
const adminLinks = () => {
  expect(document.querySelector('a[href^="/en-US/admin"]')).toBeNull();
  return menuItems(enNav.items.admin);
};
/** Rendered for a signed-in user: the menu's Settings item. */
const dashboardLinks = () => menuItems(enNav.items.settings);

/** Resolve once the settings query has settled and React has rendered its result. */
async function settingsSettled() {
  await waitFor(() => expect(client.getQueryState(["settings", "getAll"])?.status).toBe("success"));
  await act(async () => {});
}

const DAY = 24 * 60 * 60 * 1000;
function sessionUser(overrides: Record<string, unknown> = {}) {
  return {
    user: {
      id: "u",
      role: "admin",
      emailVerified: true,
      twoFactorEnabled: true,
      createdAt: new Date(Date.now() - 30 * DAY),
      ...overrides,
    },
  };
}

beforeEach(() => {
  state.session = null;
  state.settings = {};
  state.settingsCalls = 0;
});
afterEach(() => cleanup());

describe("admin navigation matrix", () => {
  it("shows the admin area to an enrolled, verified admin in both navs", async () => {
    state.session = sessionUser();
    mount();
    await waitFor(() => expect(adminLinks()).toHaveLength(1));
    expect(screen.getAllByText(enNav.items.admin)).toHaveLength(1);
  });

  it("omits it for anonymous visitors and ordinary users without asking for settings", async () => {
    mount();
    expect(adminLinks()).toHaveLength(0);
    cleanup();
    state.session = sessionUser({ role: "user" });
    mount();
    await waitFor(() => expect(dashboardLinks().length).toBeGreaterThan(0));
    expect(adminLinks()).toHaveLength(0);
    expect(state.settingsCalls).toBe(0);
  });

  it("omits it for an unverified admin", async () => {
    state.session = sessionUser({ emailVerified: false });
    mount();
    await waitFor(() => expect(dashboardLinks().length).toBeGreaterThan(0));
    await act(async () => {});
    expect(adminLinks()).toHaveLength(0);
    // Not a candidate at all: the settings query never runs.
    expect(state.settingsCalls).toBe(0);
  });

  it("omits it for an admin locked out by forced 2FA, and restores it when enforcement is off", async () => {
    state.session = sessionUser({ twoFactorEnabled: false });
    mount();
    await settingsSettled();
    expect(state.settingsCalls).toBe(1);
    expect(dashboardLinks().length).toBeGreaterThan(0);
    expect(adminLinks()).toHaveLength(0);
    cleanup();

    state.settings = { force2faInternalUsers: "false" };
    mount();
    await waitFor(() => expect(adminLinks()).toHaveLength(1));
  });

  it("shows it to a new admin inside the enrollment grace window", async () => {
    state.session = sessionUser({
      twoFactorEnabled: false,
      createdAt: new Date(Date.now() - 60_000),
    });
    mount();
    await waitFor(() => expect(adminLinks()).toHaveLength(1));
  });
});
