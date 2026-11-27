// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const route = vi.hoisted(() => ({
  pathname: "/en-US/login",
  signupEnabled: false,
  bootstrap: false,
  /** The public header's session-cookie hint. */
  signedIn: false,
  /** The app header's session. */
  authenticated: false,
}));

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
  useLocation: () => ({ pathname: route.pathname }),
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
// The real signed-out UserMenu: its Sign Up / Sign In buttons are the
// controls that must fit one row at phone widths when sign-up is open.
vi.mock("@/hooks/use-auth-session", () => ({
  useAuthSession: () => ({
    meta: { isDegraded: false, isRefetching: false },
    actions: { retry: vi.fn() },
    state: route.authenticated
      ? { status: "authenticated", session: { user: { id: "u1", name: "Owner" } } }
      : { status: "anonymous" },
  }),
}));
vi.mock("@/hooks/use-orphan-owner-sync", () => ({ useOrphanOwnerSync: () => undefined }));
vi.mock("@tanstack/react-query", () => ({
  queryOptions: (options: unknown) => options,
  useQuery: (options: { queryKey?: readonly unknown[] }) =>
    options?.queryKey?.[0] === "session-cookie-hint"
      ? { data: route.signedIn }
      : {
          data: {
            signupEnabled: route.signupEnabled,
            adminBootstrapSignupEnabled: route.bootstrap,
          },
          isPending: false,
        },
}));
vi.mock("@/server/auth-session", () => ({ getSessionCookieHint: async () => false }));
vi.mock("@/utils/orpc", () => ({ orpc: { appConfig: { queryOptions: () => ({}) } } }));
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

const APP_NAME_LINK =
  /<a data-to="(\/\$lang(?:\/dashboard\/sandboxes)?)" class="([^"]*)" title="([^"]*)">(.*?)<\/a>/;

function expectAppNameGivesWayFirst(html: string) {
  const [, , classes = "", title = "", inner = ""] = html.match(APP_NAME_LINK) ?? [];
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
  // The logo first: its box declared (no shift when it loads), never
  // shrinking, named by the app name; the visible name is hidden from
  // assistive tech, so the link's name is the app name once.
  const img = inner.match(/^<img ([^>]*)\/>/)?.[1] ?? "";
  expect(img).toContain('src="/pwa-32x32.png"');
  expect(img).toContain('srcSet="/pwa-32x32.png 32w, /pwa-64x64.png 64w, /pwa-128x128.png 128w"');
  expect(img).toContain('sizes="48px"');
  expect(img).toContain('width="32" height="32"');
  expect(img).toContain('alt="Northwind Regional Logistics"');
  expect(img).toMatch(/class="[^"]*\bsize-8\b[^"]*\bshrink-0\b/);
  const span = inner.match(/<span aria-hidden="true" class="([^"]*)">([^<]*)<\/span>$/);
  expect(span?.[1]?.split(" ").sort()).toEqual(
    ["lg:max-w-80", "max-w-40", "sm:max-w-56", "truncate"].sort(),
  );
  expect(span?.[2]).toBe("Northwind Regional Logistics");
  expect(title).toBe("Northwind Regional Logistics");
}

/** Where the app name link goes. */
const appNameTarget = (html: string) => html.match(APP_NAME_LINK)?.[1];

beforeEach(() => {
  route.pathname = "/en-US/login";
  route.signupEnabled = false;
  route.bootstrap = false;
  route.signedIn = false;
  route.authenticated = false;
});

describe("app header row", () => {
  it("lets the app name give way first at every width", () => {
    expectAppNameGivesWayFirst(renderToStaticMarkup(<Header />));
  });

  it("sends the app name to the signed-in home when signed in, the landing page otherwise", () => {
    expect(appNameTarget(renderToStaticMarkup(<Header />))).toBe("/$lang");
    route.authenticated = true;
    expect(appNameTarget(renderToStaticMarkup(<Header />))).toBe("/$lang/dashboard/sandboxes");
    // The server-rendered first frame has no session yet.
    expect(appNameTarget(renderToStaticMarkup(<Header placeholder />))).toBe("/$lang");
  });

  it("as the server-rendered placeholder keeps the row, with the account control as a skeleton", () => {
    const html = renderToStaticMarkup(<Header placeholder />);
    expectAppNameGivesWayFirst(html);
    // Same controls; the account slot is the skeleton UserMenu shows while the
    // session resolves (a 44px square below md:), never Sign In / Sign Up.
    expect(html.match(/data-control=""/g)).toHaveLength(2);
    expect(html).toMatch(/data-slot="skeleton" class="[^"]*\bh-11 w-11 md:w-24\b/);
    expect(html).not.toContain("/$lang/login");
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

  it("gives Sign In the app header's touch metrics: a 44px icon below sm:, the text from sm:", () => {
    const signIn = renderPublic().match(/<a data-to="\/\$lang\/login" class="([^"]*)"/)?.[1];
    const classes = signIn?.split(" ") ?? [];
    expect(classes).toEqual(
      expect.arrayContaining(["h-11", "w-11", "px-0", "sm:w-auto", "sm:px-3.5", "text-xs"]),
    );
    expect(classes).not.toContain("text-sm");
    expect(classes).not.toContain("hidden");
  });

  it("offers Open app instead of Sign In to a visitor with a session cookie", () => {
    route.signedIn = true;
    const html = renderPublic();
    expect(html).not.toContain('data-to="/$lang/login"');
    expect(appNameTarget(html)).toBe("/$lang/dashboard/sandboxes");
    expect(html).toContain("userMenu.openApp");
  });
});

/** `{ signup, login }`: each auth button's classes, `undefined` when absent. */
function authButtons(pathname: string, config: { signupEnabled?: boolean; bootstrap?: boolean }) {
  route.pathname = pathname;
  route.signupEnabled = config.signupEnabled ?? false;
  route.bootstrap = config.bootstrap ?? false;
  const html = renderToStaticMarkup(<Header />);
  const classes = (to: string) =>
    html
      .match(new RegExp(`<a data-to="${to.replaceAll("$", "\\$")}" class="([^"]*)"`))?.[1]
      ?.split(" ");
  return { signup: classes("/$lang/signup"), login: classes("/$lang/login") };
}

/** Shown at every width: a 44px icon below `sm:`, the text from `sm:`. */
function expectIconBelowSm(classes: string[] | undefined) {
  expect(classes).toEqual(
    expect.arrayContaining(["inline-flex", "h-11", "w-11", "px-0", "sm:w-auto", "sm:px-3.5"]),
  );
  expect(classes).not.toContain("hidden");
}

describe("signed-out header buttons", () => {
  it("with sign-up closed shows only Sign In, at every width", () => {
    for (const pathname of ["/en-US/login", "/en-US/signup", "/en-US/forgot-password"]) {
      const { signup, login } = authButtons(pathname, {});
      expect(signup).toBeUndefined();
      expectIconBelowSm(login);
    }
  });

  it("with sign-up open, or the admin bootstrap, shows both on every page and at every width", () => {
    for (const config of [{ signupEnabled: true }, { bootstrap: true }]) {
      for (const pathname of ["/en-US/login", "/en-US/signup", "/en-US/forgot-password"]) {
        const { signup, login } = authButtons(pathname, config);
        expectIconBelowSm(signup);
        expectIconBelowSm(login);
      }
    }
  });

  it("renders the buttons as links, not buttons nested in links", () => {
    route.signupEnabled = true;
    expect(renderToStaticMarkup(<Header />)).not.toMatch(/<a [^>]*><button/);
  });
});

describe("auth header landmark", () => {
  it.each(["/en-US/login", "/en-US/forgot-password"])(
    "wraps the controls in a banner on %s",
    (path) => {
      route.pathname = path;
      render(<Header />);
      expect(screen.getByRole("banner").querySelector("[data-control]")).not.toBeNull();
      cleanup();
    },
  );
});
