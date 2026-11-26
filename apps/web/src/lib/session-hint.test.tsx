import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enNav from "@wssp/locales/src/en-US/nav.json";
import { createInstance } from "i18next";
import type { ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { I18nextProvider } from "react-i18next";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The public pages' session-cookie hint as one shared query: seeded by the
 * `_public` layout during SSR, read by the landing redirect and the public
 * header. Uses the real React Query, so "seeded" means what SSR does: the
 * data is in the request's QueryClient before the header renders. Also the
 * landing page's actions per sign-up mode.
 */
const hint = vi.hoisted(() => ({ getSessionCookieHint: vi.fn(async () => false) }));
vi.mock("@/server/auth-session", () => hint);
// Route files are code-split in the test build too: the page component
// arrives through the real `lazyRouteComponent`, preloaded before rendering.
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  lazyRouteComponent: (await importOriginal<typeof import("@tanstack/react-router")>())
    .lazyRouteComponent,
  createFileRoute: () => (options: Record<string, unknown>) => ({
    options,
    useParams: () => ({ lang: "en-US" }),
  }),
  redirect: (options: Record<string, unknown>) => ({ redirect: options }),
  Link: ({
    to,
    children,
    className,
    "data-landing-action": action,
  }: {
    to: string;
    children: ReactNode;
    className?: string;
    "data-landing-action"?: string;
  }) => (
    <a data-to={to} data-landing-action={action} className={className}>
      {children}
    </a>
  ),
  Outlet: () => null,
  useParams: () => ({ lang: "en-US" }),
}));
vi.mock("@/utils/orpc", () => ({
  orpc: {
    appConfig: {
      queryOptions: () => ({ queryKey: ["appConfig"], queryFn: () => new Promise(() => {}) }),
    },
  },
}));
vi.mock("@wssp/env/web", () => ({ env: { VITE_APP_NAME: "WS Sandbox Proxy" } }));
vi.mock("@/components/language-switcher", () => ({ LanguageSwitcher: () => null }));
vi.mock("@/components/mode-toggle", () => ({ ModeToggle: () => null }));

const { ensureSessionHint, sessionHintQueryOptions, setSessionHint, SESSION_HINT_QUERY_KEY } =
  await import("./session-hint");
const { PublicShell } = await import("@/components/public-shell");
const { Route: PublicRoute } = await import("@/routes/$lang/_public/route");
const { Route: LandingRoute } = await import("@/routes/$lang/_public/index");

type Options = {
  beforeLoad: (ctx: {
    params?: { lang: string };
    context: { queryClient: QueryClient };
  }) => Promise<void>;
  component: (() => ReactNode) & { preload?: () => Promise<void> };
};
const publicOptions = (PublicRoute as unknown as { options: Options }).options;
const landingOptions = (LandingRoute as unknown as { options: Options }).options;
await landingOptions.component.preload?.();
const LandingPage = landingOptions.component;

const i18n = createInstance();
beforeAll(async () => {
  await i18n.init({
    lng: "en-US",
    defaultNS: "common",
    resources: { "en-US": { nav: enNav, common: enCommon } },
    interpolation: { escapeValue: false },
    react: { useSuspense: false },
  });
});
beforeEach(() => {
  hint.getSessionCookieHint.mockReset();
  hint.getSessionCookieHint.mockResolvedValue(false);
});

const newClient = () => new QueryClient({ defaultOptions: { queries: { retry: false } } });

function renderWith(queryClient: QueryClient, children: ReactNode) {
  return renderToStaticMarkup(
    <QueryClientProvider client={queryClient}>
      <I18nextProvider i18n={i18n}>{children}</I18nextProvider>
    </QueryClientProvider>,
  );
}

function renderHeader(queryClient: QueryClient) {
  return renderWith(
    queryClient,
    <PublicShell>
      <p>page</p>
    </PublicShell>,
  );
}

/** The header action (its last link) target and its visible (not reserved) label. */
function headerAction(html: string) {
  const match = [
    ...html.matchAll(
      /<a data-to="(\/\$lang\/(?:login|dashboard\/sandboxes))"[^>]*>([\s\S]*?)<\/a>/g,
    ),
  ].at(-1);
  const visible = (match?.[2] ?? "")
    .replace(/<span aria-hidden="true"[^>]*>[^<]*<\/span>/g, "")
    .replace(/<[^>]*>/g, "");
  return { to: match?.[1], visible };
}

/** The app name link's target (the first link in the header). */
function appNameTarget(html: string) {
  return html.match(/<header>[\s\S]*?<a data-to="([^"]*)"/)?.[1];
}

describe("session hint query", () => {
  it("asks the server once, then reads the cache (layout seed + landing redirect)", async () => {
    hint.getSessionCookieHint.mockResolvedValue(true);
    const queryClient = newClient();
    expect(await ensureSessionHint(queryClient)).toBe(true);
    expect(await ensureSessionHint(queryClient)).toBe(true);
    expect(hint.getSessionCookieHint).toHaveBeenCalledTimes(1);
    expect(sessionHintQueryOptions().queryKey).toEqual(SESSION_HINT_QUERY_KEY);
  });

  it("never decides on a stale answer: it waits for a fresh one", async () => {
    const queryClient = newClient();
    // Signed out a while ago (older than the staleTime) ...
    queryClient.setQueryData(SESSION_HINT_QUERY_KEY, false, { updatedAt: Date.now() - 120_000 });
    // ... and signed in since, in another tab.
    hint.getSessionCookieHint.mockResolvedValue(true);
    expect(await ensureSessionHint(queryClient)).toBe(true);
    expect(hint.getSessionCookieHint).toHaveBeenCalledTimes(1);
  });

  it("does not pause while the browser reports offline (it fails fast to signed out)", async () => {
    const { onlineManager } = await import("@tanstack/react-query");
    onlineManager.setOnline(false);
    try {
      expect(sessionHintQueryOptions().networkMode).toBe("always");
      hint.getSessionCookieHint.mockRejectedValue(new TypeError("Failed to fetch"));
      await expect(ensureSessionHint(newClient())).resolves.toBe(false);
    } finally {
      onlineManager.setOnline(true);
    }
  });

  it("reads a failed hint as signed out instead of throwing", async () => {
    hint.getSessionCookieHint.mockRejectedValue(new Error("offline"));
    await expect(ensureSessionHint(newClient())).resolves.toBe(false);
  });

  it("follows what the app's session gate learned", async () => {
    const queryClient = newClient();
    setSessionHint(queryClient, true);
    expect(await ensureSessionHint(queryClient)).toBe(true);
    expect(hint.getSessionCookieHint).not.toHaveBeenCalled();
  });

  it("is seeded by the _public layout's beforeLoad", async () => {
    hint.getSessionCookieHint.mockResolvedValue(true);
    const queryClient = newClient();
    await publicOptions.beforeLoad({ context: { queryClient } });
    expect(queryClient.getQueryData(SESSION_HINT_QUERY_KEY)).toBe(true);
  });
});

describe("landing redirect", () => {
  it("sends a signed-in visitor to Sandboxes, replacing the entry, from the seeded hint", async () => {
    const queryClient = newClient();
    setSessionHint(queryClient, true);
    await expect(
      landingOptions.beforeLoad({ params: { lang: "es-MX" }, context: { queryClient } }),
    ).rejects.toEqual({
      redirect: { to: "/$lang/dashboard/sandboxes", params: { lang: "es-MX" }, replace: true },
    });
    // A cache read: the layout already asked.
    expect(hint.getSessionCookieHint).not.toHaveBeenCalled();
  });

  it("shows the landing page to everyone else, also when the hint fails", async () => {
    for (const answer of [false, new Error("offline")]) {
      if (answer instanceof Error) hint.getSessionCookieHint.mockRejectedValue(answer);
      else hint.getSessionCookieHint.mockResolvedValue(answer);
      await expect(
        landingOptions.beforeLoad({
          params: { lang: "en-US" },
          context: { queryClient: newClient() },
        }),
      ).resolves.toBeUndefined();
    }
  });
});

describe("landing actions per sign-up mode", () => {
  function actions(config?: { signupEnabled: boolean; adminBootstrapSignupEnabled: boolean }) {
    const queryClient = newClient();
    if (config) queryClient.setQueryData(["appConfig"], config);
    const html = renderWith(queryClient, <LandingPage />);
    const links = [
      ...html.matchAll(
        /<a data-to="([^"]*)" data-landing-action="([^"]*)" class="([^"]*)">([^<]*)<\/a>/g,
      ),
    ];
    return {
      html,
      links: links.map((m) => ({
        to: m[1],
        action: m[2],
        filled: (m[3] ?? "").split(" ").includes("bg-primary"),
        label: m[4],
      })),
    };
  }

  it("before appConfig answers (and in the cached SSR HTML): a neutral Sign in only", () => {
    const { links, html } = actions();
    expect(links).toEqual([
      { to: "/$lang/login", action: "sign-in", filled: true, label: enCommon.home.signIn },
    ]);
    expect(html).not.toContain(enCommon.home.inviteOnly);
  });

  it("open: Create account (primary), then Sign in", () => {
    const { links } = actions({ signupEnabled: true, adminBootstrapSignupEnabled: false });
    expect(links.map((l) => [l.action, l.filled])).toEqual([
      ["create-account", true],
      ["sign-in", false],
    ]);
    expect(links[0]?.to).toBe("/$lang/signup");
  });

  it("bootstrap (no admin yet): Set up this server (primary), then Sign in; no invite line", () => {
    const { links, html } = actions({ signupEnabled: false, adminBootstrapSignupEnabled: true });
    expect(links.map((l) => [l.action, l.filled, l.label])).toEqual([
      ["set-up", true, enCommon.home.setUp],
      ["sign-in", false, enCommon.home.signIn],
    ]);
    expect(links[0]?.to).toBe("/$lang/signup");
    expect(html).not.toContain(enCommon.home.inviteOnly);
  });

  it("closed (an admin exists): Sign in (primary) and the invite-only line, no set-up", () => {
    const { links, html } = actions({ signupEnabled: false, adminBootstrapSignupEnabled: false });
    expect(links.map((l) => [l.action, l.filled])).toEqual([["sign-in", true]]);
    expect(html).toContain(enCommon.home.inviteOnly);
    expect(html).not.toContain(enCommon.home.setUp);
  });

  it("closed, but this tab holds a pool invitation: Create account (primary), no invite line", async () => {
    const { capturePoolInviteFragment, clearPoolInviteToken } = await import("@/lib/pool-invite");
    capturePoolInviteFragment({
      location: { pathname: "/en-US/settings/pools/invite", hash: `#wssp_inv_${"a".repeat(43)}` },
      history: { state: null, replaceState: () => {} },
    } as unknown as Pick<Window, "location" | "history">);
    try {
      const { links, html } = actions({ signupEnabled: false, adminBootstrapSignupEnabled: false });
      expect(links.map((l) => [l.action, l.filled])).toEqual([
        ["create-account", true],
        ["sign-in", false],
      ]);
      expect(html).not.toContain(enCommon.home.inviteOnly);
    } finally {
      clearPoolInviteToken();
    }
  });
});

describe("public header, rendered on the server", () => {
  it("with a seeded 'signed in' hint: Open app to the signed-in home, and the name goes there", () => {
    const queryClient = newClient();
    setSessionHint(queryClient, true);
    const html = renderHeader(queryClient);
    expect(headerAction(html)).toEqual({
      to: "/$lang/dashboard/sandboxes",
      visible: enNav.userMenu.openApp,
    });
    expect(appNameTarget(html)).toBe("/$lang/dashboard/sandboxes");
  });

  it("with a seeded 'signed out' hint: Sign In", () => {
    const queryClient = newClient();
    setSessionHint(queryClient, false);
    const html = renderHeader(queryClient);
    expect(headerAction(html)).toEqual({ to: "/$lang/login", visible: enNav.userMenu.signIn });
    expect(appNameTarget(html)).toBe("/$lang");
  });

  // The 404 has no `_public` route to seed it: the server renders the
  // anonymous header (identical for everyone) and the client asks afterwards.
  it("without a seed (the 404): Sign In, and no server call during the render", () => {
    expect(headerAction(renderHeader(newClient()))).toEqual({
      to: "/$lang/login",
      visible: enNav.userMenu.signIn,
    });
    expect(hint.getSessionCookieHint).not.toHaveBeenCalled();
  });

  it("keeps one box for both labels: the other one is reserved, invisible and unannounced", () => {
    for (const signedIn of [true, false]) {
      const queryClient = newClient();
      setSessionHint(queryClient, signedIn);
      const html = renderHeader(queryClient);
      const reserved = signedIn ? enNav.userMenu.signIn : enNav.userMenu.openApp;
      expect(html).toContain(
        `<span aria-hidden="true" class="invisible col-start-1 row-start-1">${reserved}</span>`,
      );
    }
  });
});
