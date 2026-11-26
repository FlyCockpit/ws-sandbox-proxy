vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import enCommon from "@wssp/locales/src/en-US/common.json";
import enDashboard from "@wssp/locales/src/en-US/dashboard.json";
import enHostCredentials from "@wssp/locales/src/en-US/hostCredentials.json";
import enHosts from "@wssp/locales/src/en-US/hosts.json";
import enOperations from "@wssp/locales/src/en-US/operations.json";
import enSandboxes from "@wssp/locales/src/en-US/sandboxes.json";
import enSdkKeys from "@wssp/locales/src/en-US/sdkKeys.json";
import enTemplates from "@wssp/locales/src/en-US/templates.json";
import esCommon from "@wssp/locales/src/es-MX/common.json";
import esDashboard from "@wssp/locales/src/es-MX/dashboard.json";
import esHostCredentials from "@wssp/locales/src/es-MX/hostCredentials.json";
import esHosts from "@wssp/locales/src/es-MX/hosts.json";
import esOperations from "@wssp/locales/src/es-MX/operations.json";
import esSandboxes from "@wssp/locales/src/es-MX/sandboxes.json";
import esSdkKeys from "@wssp/locales/src/es-MX/sdkKeys.json";
import esTemplates from "@wssp/locales/src/es-MX/templates.json";
import { createInstance, type i18n as I18n } from "i18next";
import type { ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { I18nextProvider } from "react-i18next";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * DOM (static markup) tests for the dashboard frame and its section pages,
 * rendered with the real en-US and es-MX bundles. Router links render as real
 * anchors; data hooks return scripted query states.
 */

// Node has no usable localStorage for zustand's persist middleware, and static
// rendering reads a store's initial (server) snapshot. The frame only reads
// `sidebarCollapsed` and `toggleSidebar`, so serve them from a plain object.
const uiState = vi.hoisted(() => ({
  sidebarCollapsed: false,
  toggleSidebar: () => {
    uiState.sidebarCollapsed = !uiState.sidebarCollapsed;
  },
}));
vi.mock("@/stores/ui-preferences", () => ({
  useUiPreferences: <T,>(select: (state: typeof uiState) => T): T => select(uiState),
}));

vi.mock("@tanstack/react-router", () => ({
  Link: ({
    children,
    className,
    to,
    params,
    title,
    ...rest
  }: {
    children: ReactNode;
    className?: string;
    to: string;
    params?: { lang?: string };
    title?: string;
    "data-nav-id"?: string;
    "data-active"?: string;
  }) => (
    <a
      className={className}
      href={to.replace("$lang", params?.lang ?? "$lang")}
      title={title}
      data-nav-id={rest["data-nav-id"]}
      data-active={rest["data-active"]}
    >
      {children}
    </a>
  ),
  Outlet: () => <div data-testid="dashboard-outlet" />,
  useLocation: () => ({ pathname: routeState.pathname }),
}));

type QueryState = {
  data: unknown;
  isPending: boolean;
  isError: boolean;
  hasNextPage?: boolean;
};

const routeState = vi.hoisted(() => ({
  lang: "en-US",
  pathname: "/en-US/dashboard/sandboxes",
  query: { data: undefined, isPending: true, isError: false } as QueryState,
  procedures: [] as string[],
}));

vi.mock("@tanstack/react-query", () => {
  const state = () => ({
    ...routeState.query,
    refetch: () => undefined,
    fetchNextPage: () => undefined,
    isFetchingNextPage: false,
    hasNextPage: routeState.query.hasNextPage ?? false,
  });
  return {
    useQuery: state,
    useInfiniteQuery: state,
    useQueryClient: () => ({ invalidateQueries: async () => undefined }),
  };
});

vi.mock("@/utils/orpc", () => {
  const procedure = (name: string) => ({
    queryOptions: (options: unknown) => {
      routeState.procedures.push(name);
      return options;
    },
    infiniteOptions: (options: unknown) => {
      routeState.procedures.push(name);
      return options;
    },
  });
  return {
    orpc: {
      sandboxHosts: {
        listHosts: procedure("sandboxHosts.listHosts"),
      },
      sandboxTemplates: { listTemplates: procedure("sandboxTemplates.listTemplates") },
      sandboxes: { list: procedure("sandboxes.list") },
    },
  };
});

import { DashboardFrame } from "@/components/dashboard-frame";
import { primaryNavItems } from "@/lib/nav-items";

const bundles = {
  "en-US": {
    common: enCommon,
    dashboard: enDashboard,
    hosts: enHosts,
    hostCredentials: enHostCredentials,
    templates: enTemplates,
    sandboxes: enSandboxes,
    operations: enOperations,
    sdkKeys: enSdkKeys,
  },
  "es-MX": {
    common: esCommon,
    dashboard: esDashboard,
    hosts: esHosts,
    hostCredentials: esHostCredentials,
    templates: esTemplates,
    sandboxes: esSandboxes,
    operations: esOperations,
    sdkKeys: esSdkKeys,
  },
} as const;
type Lang = keyof typeof bundles;
const LANGS = Object.keys(bundles) as Lang[];

const missingKeys: string[] = [];
const instances = {} as Record<Lang, I18n>;

beforeAll(async () => {
  for (const lang of LANGS) {
    const instance = createInstance();
    await instance.init({
      lng: lang,
      // No fallback: a key missing from either locale must surface, not be
      // silently answered in English.
      fallbackLng: false,
      ns: Object.keys(bundles[lang]),
      defaultNS: "common",
      resources: { [lang]: bundles[lang] },
      interpolation: { escapeValue: false },
      react: { useSuspense: false },
      saveMissing: true,
      missingKeyHandler: (_lngs, ns, key) => missingKeys.push(`${lang}:${ns}:${key}`),
    });
    instances[lang] = instance;
  }
});

beforeEach(() => {
  missingKeys.length = 0;
  routeState.procedures = [];
  routeState.query = { data: undefined, isPending: true, isError: false };
  uiState.sidebarCollapsed = false;
  routeState.pathname = "/en-US/dashboard/sandboxes";
});

function render(lang: Lang, node: ReactNode): string {
  routeState.lang = lang;
  return renderToStaticMarkup(<I18nextProvider i18n={instances[lang]}>{node}</I18nextProvider>);
}

/** Text as renderToStaticMarkup escapes it. */
function escaped(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
}

function anchors(html: string): string[] {
  return [...html.matchAll(/<a\b[^>]*>/g)].map((match) => match[0]);
}

describe("dashboard frame", () => {
  it.each(LANGS)("%s: the sidebar links the five primary sections, in order, once", (lang) => {
    const html = render(lang, <DashboardFrame lang={lang} />);
    const hrefs = anchors(html).map((tag) => /href="([^"]+)"/.exec(tag)?.[1]);
    expect(hrefs).toEqual([
      `/${lang}/dashboard/sandboxes`,
      `/${lang}/dashboard/templates`,
      `/${lang}/dashboard/operations`,
      `/${lang}/dashboard/terminals`,
      `/${lang}/settings`,
    ]);
    for (const item of primaryNavItems) {
      const label = instances[lang].t(item.labelKey);
      expect(label).not.toBe(item.labelKey.split(":")[1]);
      expect(html).toContain(escaped(label));
    }
    expect(missingKeys).toEqual([]);
  });

  it.each([
    ["/en-US/dashboard/sandboxes/abc", "sandboxes"],
    ["/en-US/dashboard/operations", "activity"],
    ["/en-US/settings/hosts/h1", "settings"],
    ["/en-US/settings/logins/sessions/s1", "settings"],
  ])("marks exactly one section active on %s", (pathname, id) => {
    routeState.pathname = pathname;
    const html = render("en-US", <DashboardFrame lang="en-US" />);
    const active = anchors(html).filter((tag) => tag.includes('data-active="true"'));
    expect(active).toHaveLength(1);
    expect(active[0]).toContain(`data-nav-id="${id}"`);
  });

  it("uses focusable links and buttons with 44px touch targets and no tabindex traps", () => {
    const html = render("en-US", <DashboardFrame lang="en-US" />);
    // Nothing is removed from, or reordered in, the keyboard tab sequence.
    expect(html).not.toMatch(/tabindex="(-|[1-9])/i);
    for (const tag of anchors(html)) {
      expect(tag).toMatch(/href="\/en-US\/(dashboard|settings)/);
      // `touch` (h-11) or `icon-touch` (size-11) button sizing: 44px.
      expect(tag).toMatch(/\b(h-11|size-11)\b/);
    }
    const toggle = /<button\b[^>]*>/.exec(html)?.[0] ?? "";
    expect(toggle).toContain('type="button"');
    expect(toggle).toContain('aria-label="Collapse sidebar"');
    expect(toggle).toContain('aria-pressed="false"');
    expect(toggle).toMatch(/\bsize-11\b/);
    // One labelled navigation landmark: the sidebar.
    expect(html.match(/<nav\b/g)).toHaveLength(1);
  });

  it("has no phone section strip: below md the sidebar is hidden and the bottom tabs take over", () => {
    const html = render("en-US", <DashboardFrame lang="en-US" />);
    expect(html).not.toContain('data-dashboard-nav="strip"');
    const aside = /<aside\b[^>]*>/.exec(html)?.[0] ?? "";
    // Below md the sidebar is display:none (so it is out of the tab order).
    expect(aside).toMatch(/class="hidden [^"]*md:flex/);
    expect(aside).toMatch(/\bw-60\b/);
    const content = /<div[^>]*data-dashboard-content[^>]*>/.exec(html)?.[0] ?? "";
    expect(content).toMatch(/\bmin-w-0\b/);
    expect(content).toMatch(/\bmax-w-full\b/);
    // Nothing forces a width wider than a 320px viewport.
    expect(html).not.toMatch(/\bmin-w-\[|\bw-\[\d{3,}px\]|\bw-screen\b/);
  });

  it("collapses the sidebar to icon links that keep an accessible name", () => {
    uiState.sidebarCollapsed = true;
    const html = render("en-US", <DashboardFrame lang="en-US" />);
    const aside = /<aside\b[^>]*>/.exec(html)?.[0] ?? "";
    expect(aside).toContain('data-collapsed="true"');
    expect(aside).toMatch(/\bw-16\b/);
    expect(html).toContain('aria-label="Expand sidebar"');
    expect(html).toContain('aria-pressed="true"');
    expect(html).toContain('<span class="sr-only">Sandboxes</span>');
    expect(html).toContain('title="Sandboxes"');
  });
});
