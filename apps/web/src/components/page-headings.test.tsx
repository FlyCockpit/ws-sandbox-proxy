import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import type { ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

/**
 * One real h1 per page, never `role="heading"`: the 404 in the public shell
 * (signed out and signed in; the shell's own header chrome is rendered for
 * real and brings no heading), the settings hub and account pages, and no
 * settings page that draws its own h1 beside `PageHeader`. Auth pages: the
 * AuthCard title is the h1 (auth-screen.test.tsx); the forced-2FA takeover:
 * forced-two-factor-gate.test.tsx.
 */
const fx = vi.hoisted(() => ({ signedIn: false }));

vi.mock("@tanstack/react-router", () => ({
  Link: ({ children, className }: { children: ReactNode; className?: string }) => (
    <a className={className}>{children}</a>
  ),
  useParams: () => ({ lang: "en-US" }),
  useNavigate: () => vi.fn(),
  useLocation: () => ({ pathname: "/en-US/nope" }),
  useRouterState: () => undefined,
  useMatch: () => undefined,
}));
// The public header's session-cookie hint (lib/session-hint.ts).
vi.mock("@tanstack/react-query", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tanstack/react-query")>()),
  useQuery: () => ({ data: fx.signedIn }),
}));
vi.mock("@/server/auth-session", () => ({ getSessionCookieHint: async () => fx.signedIn }));
vi.mock("react-i18next", () => ({
  useTranslation: () => ({ t: (key: string) => key, i18n: { language: "en-US" } }),
}));
vi.mock("@wssp/env/web", () => ({ env: { VITE_APP_NAME: "WS Sandbox Proxy" } }));
vi.mock("@/i18n", () => ({ default: {}, loadLocaleInto: async () => {} }));

const { PublicNotFoundPage } = await import("@/components/public-shell");
const { SettingsHub } = await import("@/components/settings/settings-hub");
const { AccountSettingsLayout } = await import("@/components/settings/account-settings-layout");

function h1s(html: string): string[] {
  expect(html).not.toContain('role="heading"');
  return [...html.matchAll(/<h1\b[^>]*>([\s\S]*?)<\/h1>/g)].map(([, inner = ""]) => inner);
}

describe.each([false, true])("404 (signed in: %s)", (signedIn) => {
  it("has exactly one h1 inside the public shell, the page's title", () => {
    fx.signedIn = signedIn;
    expect(h1s(renderToStaticMarkup(<PublicNotFoundPage />))).toEqual(["pageNotFound.title"]);
  });
});

describe("settings", () => {
  it("the hub has exactly one h1", () => {
    expect(h1s(renderToStaticMarkup(<SettingsHub lang="en-US" />))).toEqual(["hub.title"]);
  });

  it("an account page has exactly one h1, before its content", () => {
    const html = renderToStaticMarkup(
      <AccountSettingsLayout lang="en-US">
        <p>page</p>
      </AccountSettingsLayout>,
    );
    expect(h1s(html)).toEqual(["account.title"]);
    expect(html.indexOf("<h1")).toBeLessThan(html.indexOf("<p>page</p>"));
  });

  it("no settings route or component draws its own heading beside PageHeader", () => {
    // Route files cannot be rendered cheaply; the source check also catches
    // new pages. PageHeader (components/page-shell.tsx) owns the h1.
    const roots = [
      join(import.meta.dirname, "../routes/$lang/_app/_auth/settings"),
      join(import.meta.dirname, "../routes/$lang/_app/_auth/settings.tsx"),
      join(import.meta.dirname, "settings"),
    ];
    const files: string[] = [];
    const walk = (path: string) => {
      if (statSync(path).isDirectory())
        for (const name of readdirSync(path)) walk(join(path, name));
      else if (path.endsWith(".tsx") && !path.endsWith(".test.tsx")) files.push(path);
    };
    for (const root of roots) walk(root);
    expect(files.length).toBeGreaterThan(10);
    for (const file of files) {
      const source = readFileSync(file, "utf8");
      expect(source, file).not.toMatch(/<h1\b/);
      expect(source, file).not.toContain('role="heading"');
    }
  });
});
