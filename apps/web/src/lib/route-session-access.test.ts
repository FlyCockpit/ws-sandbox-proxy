import { describe, expect, it } from "vitest";

import { SUPPORTED_LOCALES } from "@/i18n/config";
import { safeRedirectTo } from "@/utils/safe-redirect";

import { primaryNavItems, settingsHubGroups, toLangRoute } from "./nav-items";
import {
  decideAdminRouteAccess,
  decideAnonymousOnlyRouteAccess,
  decideDeviceRouteAccess,
  decideProtectedRouteAccess,
  decideRootLanding,
  failedRouteSessionResolution,
  loginRedirect,
  type RouteSession,
  resolvedRouteSession,
  showsAdminNavigation,
} from "./route-session-access";

const baseSession: RouteSession = {
  user: {
    id: "user-1",
    name: "Test User",
    email: "test@example.com",
    emailVerified: true,
    role: "user",
    twoFactorEnabled: false,
    createdAt: Date.UTC(2026, 0, 1),
  },
};

function sessionWith(overrides: Partial<RouteSession["user"]>): RouteSession {
  return { user: { ...baseSession.user, ...overrides } };
}

describe("route session access decisions", () => {
  it("allows protected routes for authenticated sessions, carrying the force-2FA settings", () => {
    const forcedTwoFactorSettings = { force2faPublicUsers: "true" };
    expect(
      decideProtectedRouteAccess({
        status: "resolved",
        session: baseSession,
        forcedTwoFactorSettings,
        passwordChangeRequired: true,
      }),
    ).toEqual({
      kind: "allow",
      session: baseSession,
      forcedTwoFactorSettings,
      passwordChangeRequired: true,
    });
  });

  // Pins the asymmetry documented on `decideProtectedRouteAccess`: the ordinary
  // app admits unverified sessions, the privileged surface below does not. This
  // mirrors `protectedProcedure`, which has no verification check either.
  // Making this fail means changing a product decision (and needing a
  // verify-email interstitial to avoid a redirect loop), so change the guard
  // and this test together, deliberately.
  it("admits unverified sessions to the ordinary app, unlike the privileged guard", () => {
    const unverified = sessionWith({ emailVerified: false });

    expect(
      decideProtectedRouteAccess({
        status: "resolved",
        session: unverified,
        forcedTwoFactorSettings: {},
        passwordChangeRequired: false,
      }),
    ).toEqual({
      kind: "allow",
      session: unverified,
      forcedTwoFactorSettings: {},
      passwordChangeRequired: false,
    });
    expect(showsAdminNavigation({ ...unverified.user, role: "admin" }, {})).toBe(false);
  });

  it("redirects confirmed anonymous protected users to login", () => {
    expect(decideProtectedRouteAccess({ status: "resolved", session: null })).toEqual({
      kind: "redirect-to-login",
    });
  });

  it("keeps route-session resolution failures distinct from anonymous users", () => {
    expect(decideProtectedRouteAccess({ status: "error" })).toEqual({ kind: "error" });
    expect(decideAdminRouteAccess({ status: "error" })).toEqual({ kind: "error" });
    expect(decideAnonymousOnlyRouteAccess(failedRouteSessionResolution())).toEqual({
      kind: "error",
    });
  });

  it("keeps logged-out-only routes available only to confirmed anonymous users", () => {
    expect(decideAnonymousOnlyRouteAccess(resolvedRouteSession(null))).toEqual({ kind: "allow" });
    expect(decideAnonymousOnlyRouteAccess(resolvedRouteSession(baseSession))).toEqual({
      kind: "redirect-authenticated",
      session: baseSession,
    });
  });

  it("admits only sessions the server admin gate authorized", () => {
    const admin = sessionWith({ role: "admin", emailVerified: true, twoFactorEnabled: true });
    expect(
      decideAdminRouteAccess({ status: "resolved", session: admin, authorized: true }),
    ).toEqual({ kind: "allow", session: admin });
  });

  it("404-hides anonymous visitors and every session the server gate refused", () => {
    expect(
      decideAdminRouteAccess({ status: "resolved", session: null, authorized: false }),
    ).toEqual({ kind: "not-found" });
    // A stale cookie claiming admin cannot override the server's verdict.
    const cookieAdmin = sessionWith({ role: "admin", emailVerified: true, twoFactorEnabled: true });
    expect(
      decideAdminRouteAccess({ status: "resolved", session: cookieAdmin, authorized: false }),
    ).toEqual({ kind: "not-found" });
    // A session-less "authorized" verdict is impossible, but still hidden.
    expect(decideAdminRouteAccess({ status: "resolved", session: null, authorized: true })).toEqual(
      { kind: "not-found" },
    );
  });

  it("offers admin navigation only to verified admins the forced-2FA policy admits", () => {
    const now = Date.UTC(2026, 5, 1);
    const enrolled = { role: "admin", emailVerified: true, twoFactorEnabled: true, createdAt: 0 };
    expect(showsAdminNavigation(enrolled, {}, now)).toBe(true);
    expect(showsAdminNavigation({ ...enrolled, role: "user" }, {}, now)).toBe(false);
    expect(showsAdminNavigation({ ...enrolled, emailVerified: false }, {}, now)).toBe(false);
    expect(showsAdminNavigation(null, {}, now)).toBe(false);
    // Settings not loaded yet: omit rather than flash a link that may 404.
    expect(showsAdminNavigation(enrolled, undefined, now)).toBe(false);

    const blocked = { ...enrolled, twoFactorEnabled: false, createdAt: Date.UTC(2020, 0, 1) };
    expect(showsAdminNavigation(blocked, {}, now)).toBe(false);
    expect(showsAdminNavigation(blocked, { force2faInternalUsers: "false" }, now)).toBe(true);
    const grace = { ...blocked, createdAt: now - 60_000 };
    expect(showsAdminNavigation(grace, {}, now)).toBe(true);
  });

  it("redirects device enrollment to login when unauthenticated", () => {
    expect(decideDeviceRouteAccess(resolvedRouteSession(null), {})).toEqual({
      kind: "redirect-to-login",
    });
  });

  it("redirects device enrollment to security when email is unverified", () => {
    expect(
      decideDeviceRouteAccess(resolvedRouteSession(sessionWith({ emailVerified: false })), {}),
    ).toEqual({ kind: "redirect-to-security" });
  });

  it("sends a signed-in visitor's root to the dashboard and keeps anonymous visitors on the landing page", () => {
    expect(decideRootLanding(resolvedRouteSession(baseSession))).toEqual({ kind: "dashboard" });
    // Unverified sessions reach the ordinary app too (see decideProtectedRouteAccess).
    expect(decideRootLanding(resolvedRouteSession(sessionWith({ emailVerified: false })))).toEqual({
      kind: "dashboard",
    });
    expect(decideRootLanding(resolvedRouteSession(null))).toEqual({ kind: "landing" });
    // A failed lookup never turns the public page into an error or a redirect.
    expect(decideRootLanding(failedRouteSessionResolution())).toEqual({ kind: "landing" });
  });
});

describe("login redirect round trip — auth redirects preserve the intended route", () => {
  const deepLinks = SUPPORTED_LOCALES.flatMap((lang) =>
    [...primaryNavItems, ...settingsHubGroups.flatMap((group) => group.items)].map((item) => {
      const path = toLangRoute(item.path).replace("$lang", lang);
      return [lang, `${path}?filter=ready#top`] as const;
    }),
  );

  it.each(deepLinks)("%s: %s survives login", (lang, href) => {
    const options = loginRedirect(lang, href);
    expect(options).toEqual({
      to: "/$lang/login",
      params: { lang },
      search: { redirectTo: href },
    });
    // What the login page navigates to after sign-in.
    expect(safeRedirectTo(options.search.redirectTo, lang)).toBe(href);
  });

  it("falls back to the locale dashboard for foreign, other-locale and auth-page targets", () => {
    expect(safeRedirectTo("https://evil.example/en-US/dashboard", "en-US")).toBe(
      "/en-US/dashboard",
    );
    expect(safeRedirectTo("//evil.example/en-US/dashboard", "en-US")).toBe("/en-US/dashboard");
    expect(safeRedirectTo("/es-MX/settings/hosts", "en-US")).toBe("/en-US/dashboard");
    expect(safeRedirectTo("/en-US/login?redirectTo=/en-US/dashboard", "en-US")).toBe(
      "/en-US/dashboard",
    );
    expect(safeRedirectTo(undefined, "es-MX")).toBe("/es-MX/dashboard");
  });
});
