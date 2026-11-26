import { type ComponentType, lazy, type ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { prerender } from "react-dom/static";
import { describe, expect, it, vi } from "vitest";

/**
 * The shell rules, see docs/design/shell-rules.md § Shell rules
 * They are rendered here, so a comment or a stray string cannot stand in for
 * the real markup. The geometry itself (full-bleed rules reach the viewport
 * edge) is measured in a browser by `pnpm check:layout`. Route components are
 * code-split (`lazyRouteComponent`), so route renders wait for the split chunk
 * (`prerender`).
 */
vi.mock("@tanstack/react-router", () => ({
  createFileRoute: () => (options: Record<string, unknown>) => ({ options }),
  lazyRouteComponent: (importer: () => Promise<Record<string, unknown>>, name = "default") =>
    lazy(async () => ({ default: (await importer())[name] as ComponentType })),
  Link: ({ children }: { children: ReactNode }) => <a>{children}</a>,
  Outlet: () => <p>outlet</p>,
  redirect: () => undefined,
  useParams: () => "en-US",
}));
vi.mock("@tanstack/react-query-devtools", () => ({ ReactQueryDevtools: () => null }));
vi.mock("@tanstack/react-router-devtools", () => ({ TanStackRouterDevtools: () => null }));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (key: string) => key }) }));
vi.mock("@wssp/env/web", () => ({ env: { VITE_APP_NAME: "WS Sandbox Proxy" } }));
vi.mock("@/components/bottom-nav", () => ({ default: () => null }));
vi.mock("@/components/header", () => ({ default: () => null }));
vi.mock("@/components/offline-banner", () => ({ OfflineBanner: () => null }));
vi.mock("@/components/language-switcher", () => ({ LanguageSwitcher: () => null }));
vi.mock("@/components/mode-toggle", () => ({ ModeToggle: () => null }));
vi.mock("@/hooks/use-document-lang", () => ({ useDocumentLang: () => {} }));
vi.mock("@/hooks/use-user-locale-sync", () => ({ useUserLocaleSync: () => {} }));
vi.mock("@/hooks/use-mobile-keyboard", () => ({ useMobileKeyboard: () => false }));
vi.mock("@/i18n", () => ({ loadLocaleInto: async () => {} }));
vi.mock("@/lib/hidden-admin", () => ({ hideAdminRoute: async () => {} }));
vi.mock("@/server/admin-route-access", () => ({ getRouteAdminAccess: async () => null }));

const { PublicNotFoundPage, PublicShell } = await import("@/components/public-shell");
const { Route: AppRoute } = await import("@/routes/$lang/_app/route");
const { Route: PublicRoute } = await import("@/routes/$lang/_public/route");
const { Route: LangRoute } = await import("@/routes/$lang");

async function render(route: unknown): Promise<string> {
  const { component: Component } = (route as { options: { component: ComponentType } }).options;
  const { prelude } = await prerender(<Component />);
  return new Response(prelude).text();
}

function mainTag(html: string): string {
  const tags = html.match(/<main\b[^>]*>/g) ?? [];
  expect(tags, "exactly one <main> per shell").toHaveLength(1);
  return tags[0] ?? "";
}

// The scroller holds one column, at least as tall as the scroller, whose page
// grows into it. wssp has no public footer; one would follow the page there.
const COLUMN =
  /<main\b[^>]*><div class="flex min-h-full min-w-0 flex-col"><div class="flex min-w-0 flex-1 flex-col">([\s\S]*)<\/div><\/div><\/main>/;

describe("public shell", () => {
  it("puts the page in a growing min-h-full column inside the one scroller, under the header", () => {
    const html = renderToStaticMarkup(
      <PublicShell>
        <p>page</p>
      </PublicShell>,
    );
    const match = html.match(COLUMN);
    expect(match, html).not.toBeNull();
    expect(match?.[1]).toBe("<p>page</p>");
    expect(html).toMatch(/<header\b[\s\S]*<hr\/><\/header><main\b/);
    expect(html).not.toContain("<footer");
  });

  it("the _public layout renders its routes through the shell", async () => {
    expect((await render(PublicRoute)).match(COLUMN)?.[1]).toBe("<p>outlet</p>");
  });

  it("the 404 for an unknown URL renders inside the public shell, with one <main>", async () => {
    // `$lang`'s notFoundComponent is code-split too: render it, then compare.
    const { notFoundComponent: NotFound } = (
      LangRoute as { options: { notFoundComponent?: ComponentType } }
    ).options;
    expect(NotFound, "$lang sets a notFoundComponent").toBeDefined();
    const html = renderToStaticMarkup(<PublicNotFoundPage />);
    if (NotFound) {
      const { prelude } = await prerender(<NotFound />);
      expect(await new Response(prelude).text()).toBe(html);
    }
    expect(html).toContain("<header");
    mainTag(html);
    const body = html.match(COLUMN)?.[1];
    expect(body).toContain("pageNotFound.title");
    // The body fills the column, so the message centres below the header.
    expect(body).toMatch(/^<div class="flex flex-1 flex-col items-center justify-center/);
  });
});

describe("full-bleed rules inside the scroller", () => {
  it.each([
    ["public", PublicRoute],
    ["app", AppRoute],
  ])("the %s shell's scroller reserves no scrollbar gutter", async (_name, route) => {
    const tag = mainTag(await render(route));
    expect(tag).toContain('data-scroll-restoration-id="app-main"');
    expect(tag).toContain("overflow-y-auto");
    expect(tag).not.toContain("scrollbar-gutter");
  });

  it("the app shell has no footer (BottomNav on phones)", async () => {
    expect(await render(AppRoute)).not.toContain("<footer");
  });
});
